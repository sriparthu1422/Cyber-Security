"""
app/api/routes/analyze.py — Analysis endpoints.

POST /api/v1/analyze      — Analyze a JSON list of events
POST /api/v1/analyze/csv  — Upload and analyze a CSV file
"""
import logging
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.event_schemas import AnalyzeRequest, AnalyzeResponse, DetectionEventResponse
from app.services.training import load_models

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["analysis"])


def _get_models():
    """Load models once per request (cached by FastAPI's dependency system if needed)."""
    return load_models()


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze Events",
)
def analyze_events(request: AnalyzeRequest, db: Session = Depends(get_db)):
    """
    Analyze one or more events using the trained ML model.

    Accepts a JSON list of network/authentication events.
    Returns predictions, anomaly scores, severity levels, and explanations.

    If no model has been trained yet, returns rule-based predictions with a warning.
    To train a model, run: `python scripts/train_model.py`

    **Anomaly score note**: IsolationForest scores are relative measures,
    not calibrated probabilities. A score of -0.2 means "more anomalous
    than a score of -0.1", but does NOT mean "20% chance of attack".
    """
    import pandas as pd
    from app.services.detection import run_detection
    from app.models.detection_event import DetectionEvent

    events_data = [e.model_dump() for e in request.events]
    df = pd.DataFrame(events_data)

    models = _get_models()

    try:
        event_results = run_detection(df, models=models, pipeline=None)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error(f"Detection failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Detection pipeline error: {e}"
        )

    # Persist results
    db_events = []
    for event_data in event_results:
        db_event = DetectionEvent(**event_data)
        db.add(db_event)
        db.flush()
        db_events.append(db_event)
    db.commit()

    anomalies = [e for e in event_results if e["is_anomaly"]]
    high = [e for e in event_results if e["severity"] == "High"]
    suspicious = [e for e in event_results if e["severity"] == "Suspicious"]

    model_used = event_results[0].get("prediction_source", "unknown") if event_results else "unknown"
    warning = None
    if model_used == "rule_based_fallback":
        warning = (
            "No trained ML model found. Results use simple rules only. "
            "Train a model with: python scripts/train_model.py"
        )

    return AnalyzeResponse(
        total_analyzed=len(event_results),
        anomalies_detected=len(anomalies),
        normal_events=len(event_results) - len(anomalies),
        high_severity=len(high),
        suspicious_events=len(suspicious),
        events=[DetectionEventResponse.model_validate(e) for e in db_events],
        model_used=model_used,
        warning=warning,
    )


@router.post(
    "/analyze/csv",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze CSV File",
)
async def analyze_csv(
    file: UploadFile = File(..., description="CSV file with event data"),
    db: Session = Depends(get_db),
):
    """
    Upload and analyze a CSV file.

    The CSV should contain columns matching the event schema:
    - failed_logins, bytes_in, bytes_out, connection_duration (numeric)
    - protocol (categorical: TCP/UDP/etc.)
    - unusual_hour (boolean: true/false)
    - port_number (integer)
    - source_ip, dest_ip (optional metadata)
    - label (optional: 0=normal, 1=anomaly for evaluation)

    Missing columns are imputed with sensible defaults.
    Invalid rows are skipped with a warning.

    Maximum file size: 10 MB. Accepted format: .csv only.
    """
    from app.services.ingestion import ingest_csv

    # Validate file type before reading
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=415,
            detail="Only .csv files are accepted. Please upload a valid CSV file."
        )

    # Read file bytes (with size check)
    max_bytes = 10 * 1024 * 1024  # 10 MB
    file_bytes = await file.read(max_bytes + 1)

    if len(file_bytes) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum allowed size is 10 MB."
        )

    if len(file_bytes) == 0:
        raise HTTPException(status_code=422, detail="Uploaded file is empty.")

    models = _get_models()

    try:
        result = ingest_csv(file_bytes, file.filename, db, models)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error(f"CSV ingestion failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"CSV processing failed: {e}"
        )

    # Fetch persisted events for this import
    from app.models.detection_event import DetectionEvent
    events = (
        db.query(DetectionEvent)
        .filter(DetectionEvent.dataset_import_id != None)
        .order_by(DetectionEvent.timestamp.desc())
        .limit(result["row_count"] or 0)
        .all()
    )

    high = [e for e in events if e.severity == "High"]
    suspicious = [e for e in events if e.severity == "Suspicious"]

    warning = None
    if result.get("warnings"):
        warning = "; ".join(result["warnings"])

    return AnalyzeResponse(
        total_analyzed=result["row_count"],
        anomalies_detected=result["anomaly_count"],
        normal_events=result["row_count"] - result["anomaly_count"],
        high_severity=len(high),
        suspicious_events=len(suspicious),
        events=[DetectionEventResponse.model_validate(e) for e in events[:50]],  # Cap at 50 in response
        model_used="isolation_forest",
        warning=warning,
    )
