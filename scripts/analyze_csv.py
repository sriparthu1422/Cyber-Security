"""
scripts/analyze_csv.py — Batch CSV analysis CLI.

Analyze a CSV file through the trained detection pipeline.
Outputs results to the console and optionally saves to a CSV.

Usage:
    python scripts/analyze_csv.py --input data/sample/network_events.csv
    python scripts/analyze_csv.py --input my_data.csv --output results.csv

Prerequisites:
    python scripts/generate_sample_data.py
    python scripts/initialize_db.py
    python scripts/train_model.py
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd

from app.database import init_db, get_db_session
from app.services.ingestion import load_csv, validate_csv_file
from app.services.preprocessing import validate_dataframe
from app.services.detection import run_detection
from app.services.training import load_models


def main():
    parser = argparse.ArgumentParser(description="Analyze a CSV file for cybersecurity threats.")
    parser.add_argument("--input", required=True, help="Input CSV file path")
    parser.add_argument("--output", help="Output CSV file path (optional)")
    parser.add_argument("--no-persist", action="store_true", help="Skip database persistence")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"ERROR: Input file not found: {input_path}")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"CYBERSECURITY THREAT DETECTION — BATCH ANALYSIS")
    print(f"{'='*60}")
    print(f"Input: {input_path}")

    # Read file
    file_bytes = input_path.read_bytes()

    # Validate file
    is_valid, err = validate_csv_file(input_path.name, file_bytes)
    if not is_valid:
        print(f"ERROR: {err}")
        sys.exit(1)

    # Load CSV
    df, total_rows, error_rows = load_csv(file_bytes, input_path.name)
    print(f"Loaded: {len(df)} rows ({error_rows} rows skipped)")

    # Validate features
    is_valid_df, warnings = validate_dataframe(df)
    if not is_valid_df:
        print(f"ERROR: {warnings[0]}")
        sys.exit(1)
    for w in warnings:
        print(f"WARNING: {w}")

    # Load models
    init_db()
    models = load_models()
    if models["isolation_forest"] is None:
        print("WARNING: No trained model found. Using rule-based fallback.")
        print("Train a model with: python scripts/train_model.py")

    # Run detection
    print("\nRunning threat detection...")
    events = run_detection(df, models=models, pipeline=None)

    # Persist to DB (unless --no-persist)
    if not args.no_persist:
        from app.models.detection_event import DetectionEvent
        with get_db_session() as db:
            for event_data in events:
                db.add(DetectionEvent(**event_data))
        print(f"Persisted {len(events)} events to database.")

    # Summary
    anomalies = [e for e in events if e["is_anomaly"]]
    high = [e for e in events if e["severity"] == "High"]
    suspicious = [e for e in events if e["severity"] == "Suspicious"]

    print(f"\n{'='*60}")
    print(f"ANALYSIS RESULTS")
    print(f"{'='*60}")
    print(f"Total events  : {len(events)}")
    print(f"Normal        : {len(events) - len(anomalies)}")
    print(f"Suspicious    : {len(suspicious)}")
    print(f"High severity : {len(high)}")
    print(f"Anomaly rate  : {len(anomalies)/len(events):.1%}")
    print()

    # Show top anomalies
    if anomalies:
        print("Top 5 anomalies by severity:")
        sorted_anomalies = sorted(
            anomalies,
            key=lambda e: (e["severity"] == "High", -(e["anomaly_score"] or 0)),
            reverse=True,
        )
        for i, e in enumerate(sorted_anomalies[:5], 1):
            score_str = f"{e['anomaly_score']:.4f}" if e["anomaly_score"] is not None else "N/A"
            print(f"  {i}. [{e['severity']:12s}] score={score_str} | {e['alert_reason'][:80]}...")

    # Save output CSV
    if args.output:
        results_df = pd.DataFrame(events)
        output_path = Path(args.output)
        results_df.to_csv(output_path, index=False)
        print(f"\nResults saved to: {output_path}")

    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
