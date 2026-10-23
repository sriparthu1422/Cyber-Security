"""
scripts/train_model.py — Model training CLI script.

Trains the IsolationForest (and optionally RandomForest) on the sample dataset.
Saves model artifacts to the artifacts/ directory.
Records training metadata in the database.

Usage:
    python scripts/train_model.py [--data data/sample/network_events.csv]
                                   [--contamination 0.1]
                                   [--n-estimators 100]
                                   [--test-size 0.2]

Prerequisites:
    1. Generate sample data:  python scripts/generate_sample_data.py
    2. Initialize database:   python scripts/initialize_db.py
"""
import argparse
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd

from app.config import settings, DATA_SAMPLE_PATH
from app.database import init_db, get_db_session
from app.models.model_run import ModelRun
from app.services.preprocessing import validate_dataframe, prepare_features
from app.services.training import train_models


def main():
    parser = argparse.ArgumentParser(description="Train threat detection ML models.")
    parser.add_argument(
        "--data",
        default=str(DATA_SAMPLE_PATH / "network_events.csv"),
        help="Path to training CSV file",
    )
    parser.add_argument(
        "--contamination", type=float, default=settings.isolation_forest_contamination,
        help=f"IsolationForest contamination parameter (default: {settings.isolation_forest_contamination})",
    )
    parser.add_argument(
        "--n-estimators", type=int, default=settings.random_forest_n_estimators,
        help=f"Number of trees (default: {settings.random_forest_n_estimators})",
    )
    parser.add_argument(
        "--test-size", type=float, default=settings.test_split_size,
        help=f"Fraction for test split (default: {settings.test_split_size})",
    )
    args = parser.parse_args()

    data_path = Path(args.data)
    if not data_path.exists():
        print(f"ERROR: Data file not found: {data_path}")
        print("Generate sample data first: python scripts/generate_sample_data.py")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"CYBERSECURITY THREAT DETECTION — MODEL TRAINING")
    print(f"{'='*60}")
    print(f"Data file   : {data_path}")
    print(f"Contamination: {args.contamination}")
    print(f"N estimators : {args.n_estimators}")
    print(f"Test size    : {args.test_size}")
    print(f"Random seed  : {settings.random_seed}")
    print()

    # Load data
    print("Loading data...")
    df = pd.read_csv(data_path)
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
    print(f"Loaded {len(df)} rows with columns: {', '.join(df.columns)}")

    # Validate
    is_valid, warnings = validate_dataframe(df)
    if not is_valid:
        print(f"ERROR: Data validation failed: {warnings}")
        sys.exit(1)
    if warnings:
        for w in warnings:
            print(f"WARNING: {w}")

    has_labels = "label" in df.columns
    if has_labels:
        label_dist = df["label"].value_counts()
        print(f"Labels found: {dict(label_dist)} (0=normal, 1=anomaly)")
        print("Will train both IsolationForest and RandomForest.")
    else:
        print("No labels found. Will train IsolationForest (unsupervised) only.")

    # Preprocess
    print("\nPreprocessing features...")
    X, y, pipeline = prepare_features(df, fit=True)
    print(f"Feature matrix: {X.shape[0]} rows × {X.shape[1]} columns")

    # Initialize DB and create ModelRun record
    init_db()
    run_id = str(uuid.uuid4())

    with get_db_session() as db:
        model_run = ModelRun(
            run_id=run_id,
            model_type="isolation_forest" if not has_labels else "both",
            status="running",
            trained_at=datetime.now(timezone.utc),
            random_seed=settings.random_seed,
            contamination=args.contamination,
            n_estimators=args.n_estimators,
            has_labels=has_labels,
        )
        db.add(model_run)
        db.flush()

        try:
            # Override settings for this run
            settings.isolation_forest_contamination = args.contamination
            settings.random_forest_n_estimators = args.n_estimators

            print("\nTraining models...")
            metrics, _ = train_models(X, y, pipeline, test_size=args.test_size)

            # Update model run record
            model_run.status = "completed"
            model_run.completed_at = datetime.now(timezone.utc)
            model_run.training_rows = metrics.get("training_rows")
            model_run.test_rows = metrics.get("test_rows")
            model_run.precision = metrics.get("precision")
            model_run.recall = metrics.get("recall")
            model_run.f1_score = metrics.get("f1_score")
            model_run.accuracy = metrics.get("accuracy")
            model_run.if_anomaly_count = metrics.get("if_anomaly_count")
            model_run.if_normal_count = metrics.get("if_normal_count")
            model_run.artifact_path = metrics.get("artifact_path")
            model_run.notes = (
                f"Trained on {data_path.name}. "
                f"{metrics.get('training_rows', 'N/A')} training rows. "
                + (
                    f"F1={metrics.get('f1_score', 0):.4f}, "
                    f"Precision={metrics.get('precision', 0):.4f}, "
                    f"Recall={metrics.get('recall', 0):.4f}"
                    if metrics.get("f1_score") is not None
                    else "No labels available for supervised evaluation."
                )
            )
            db.commit()

            # Print results
            print(f"\n{'='*60}")
            print(f"TRAINING COMPLETE — Run ID: {run_id}")
            print(f"{'='*60}")
            print(f"Training rows : {metrics.get('training_rows')}")
            print(f"Test rows     : {metrics.get('test_rows')}")
            print(f"IF Anomalies  : {metrics.get('if_anomaly_count')} / {X.shape[0]} total events")
            print(f"IF Normal     : {metrics.get('if_normal_count')}")

            if metrics.get("f1_score") is not None:
                print(f"\nSupervised Metrics (RandomForest on test set):")
                print(f"  Precision : {metrics.get('precision', 0):.4f}")
                print(f"  Recall    : {metrics.get('recall', 0):.4f}")
                print(f"  F1 Score  : {metrics.get('f1_score', 0):.4f}")
                print(f"  Accuracy  : {metrics.get('accuracy', 0):.4f}")
                print(f"\nNOTE: These metrics are on SYNTHETIC data only.")
                print(f"Real-world performance may differ significantly.")
            else:
                print(f"\nNo supervised metrics (no labels in dataset).")
                print(f"IsolationForest anomaly scores are relative, not probabilities.")

            print(f"\nArtifacts saved to: artifacts/")
            print(f"Start API with: uvicorn app.main:app --reload --port 8000")
            print(f"{'='*60}\n")

        except Exception as e:
            model_run.status = "failed"
            model_run.error_message = str(e)
            db.commit()
            print(f"\nERROR: Training failed: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
