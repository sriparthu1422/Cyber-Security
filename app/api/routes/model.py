"""
app/api/routes/model.py — Model training and metrics endpoints.

GET /api/v1/model/metrics  — Get latest model evaluation metrics
POST /api/v1/model/train   — Trigger model training (uses sample dataset)
"""
import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.event_schemas import ModelMetricsResponse
from app.models.model_run import ModelRun

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["model"])


@router.get(
    "/model/metrics",
    response_model=ModelMetricsResponse,
    summary="Get Model Evaluation Metrics",
)
def get_model_metrics(db: Session = Depends(get_db)):
    """
    Get evaluation metrics from the most recent successful model training run.

    Metrics are only available when:
    1. A model has been trained (run `python scripts/train_model.py`)
    2. The training dataset included ground-truth labels (label column)

    If no model has been trained, returns 404 with an explanation.

    **Note on metrics:**
    - Precision, recall, and F1 are computed on the held-out test set
    - These metrics reflect performance on the SYNTHETIC training dataset only
    - Performance on real-world financial data may differ significantly
    - IsolationForest scores have NO calibrated probability interpretation
    """
    run = (
        db.query(ModelRun)
        .filter(ModelRun.status == "completed")
        .order_by(ModelRun.trained_at.desc())
        .first()
    )

    if run is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "No completed model training run found. "
                "Train a model by running: python scripts/train_model.py"
            ),
        )

    return ModelMetricsResponse.model_validate(run)


@router.post(
    "/model/train",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger Model Training",
)
def trigger_training(db: Session = Depends(get_db)):
    """
    Trigger model training using the sample dataset.

    This is a synchronous endpoint — it blocks until training completes.
    For production use, this should be a background task.

    Prerequisites: Sample data must be generated first.
    Run: `python scripts/generate_sample_data.py`

    Returns:
        Training results including metrics and model run ID.
    """
    import uuid
    from datetime import datetime, timezone
    from pathlib import Path

    from app.config import DATA_SAMPLE_PATH, settings
    from app.services.preprocessing import prepare_features, validate_dataframe
    from app.services.training import train_models
    import pandas as pd

    sample_file = DATA_SAMPLE_PATH / "network_events.csv"
    if not sample_file.exists():
        raise HTTPException(
            status_code=404,
            detail=(
                f"Sample dataset not found at {sample_file}. "
                "Generate it first: python scripts/generate_sample_data.py"
            ),
        )

    # Create ModelRun record
    run_id = str(uuid.uuid4())
    model_run = ModelRun(
        run_id=run_id,
        model_type="isolation_forest",
        status="running",
        trained_at=datetime.now(timezone.utc),
        random_seed=settings.random_seed,
        contamination=settings.isolation_forest_contamination,
        n_estimators=settings.random_forest_n_estimators,
    )
    db.add(model_run)
    db.commit()

    try:
        df = pd.read_csv(sample_file)
        df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]

        is_valid, warnings = validate_dataframe(df)
        if not is_valid:
            raise ValueError(f"Sample data validation failed: {warnings}")

        X, y, pipeline = prepare_features(df, fit=True)
        metrics, _ = train_models(X, y, pipeline)

        # Update model run record
        model_run.status = "completed"
        model_run.completed_at = datetime.now(timezone.utc)
        model_run.training_rows = metrics.get("training_rows")
        model_run.test_rows = metrics.get("test_rows")
        model_run.has_labels = metrics.get("has_labels", False)
        model_run.model_type = metrics.get("model_type", "isolation_forest")
        model_run.precision = metrics.get("precision")
        model_run.recall = metrics.get("recall")
        model_run.f1_score = metrics.get("f1_score")
        model_run.accuracy = metrics.get("accuracy")
        model_run.if_anomaly_count = metrics.get("if_anomaly_count")
        model_run.if_normal_count = metrics.get("if_normal_count")
        model_run.artifact_path = metrics.get("artifact_path")
        model_run.notes = (
            f"Trained on {metrics.get('training_rows', 'N/A')} samples. "
            + (f"F1={metrics.get('f1_score', 0):.3f}" if metrics.get("f1_score") else "No labels available.")
            + (f" Warnings: {'; '.join(warnings)}" if warnings else "")
        )
        db.commit()

        return {
            "status": "completed",
            "run_id": run_id,
            "model_type": model_run.model_type,
            "training_rows": model_run.training_rows,
            "metrics": {
                k: v for k, v in metrics.items()
                if k not in ("confusion_matrix",) and v is not None
            },
            "warnings": warnings,
            "message": "Model trained successfully. Reload the application to use the new model.",
        }

    except Exception as e:
        model_run.status = "failed"
        model_run.error_message = str(e)
        db.commit()
        logger.error(f"Training failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Model training failed: {e}"
        )
