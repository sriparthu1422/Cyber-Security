"""
app/services/ingestion.py — CSV ingestion and validation service.

Handles:
- CSV file loading with size and type checks
- Column validation against expected schema
- Invalid row handling (graceful, not crash)
- Dataset metadata creation and persistence
- Dispatch to detection pipeline
"""
import io
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

import pandas as pd

from app.config import settings
from app.services.preprocessing import validate_dataframe, ALL_FEATURE_COLUMNS

logger = logging.getLogger(__name__)

# Maximum allowed CSV size (10 MB default)
MAX_BYTES = settings.max_upload_mb * 1024 * 1024

# Allowed MIME types / file extensions
ALLOWED_EXTENSIONS = {".csv"}


def validate_csv_file(filename: str, file_bytes: bytes) -> Tuple[bool, str]:
    """
    Validate a CSV upload before processing.

    Checks:
    1. File extension is .csv
    2. File size is within limits
    3. File can be parsed as CSV

    Args:
        filename: Original filename
        file_bytes: Raw bytes of the file

    Returns:
        (is_valid, error_message)
    """
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        return False, f"Invalid file type '{suffix}'. Only .csv files are accepted."

    if len(file_bytes) > MAX_BYTES:
        return False, (
            f"File too large: {len(file_bytes) / 1024:.1f} KB. "
            f"Maximum allowed: {settings.max_upload_mb} MB."
        )

    if len(file_bytes) == 0:
        return False, "File is empty."

    # Try parsing
    try:
        pd.read_csv(io.BytesIO(file_bytes), nrows=5)
    except Exception as e:
        return False, f"File cannot be parsed as CSV: {e}"

    return True, ""


def load_csv(file_bytes: bytes, filename: str = "upload.csv") -> Tuple[pd.DataFrame, int, int]:
    """
    Load and clean a CSV file.

    - Strips whitespace from column names
    - Converts column names to lowercase
    - Counts and logs invalid rows (those that fail to parse)

    Args:
        file_bytes: Raw CSV bytes
        filename: Original filename (for logging)

    Returns:
        (df, total_rows, error_rows)
        df: Cleaned DataFrame
        total_rows: Original row count
        error_rows: Rows that couldn't be parsed
    """
    df = pd.read_csv(
        io.BytesIO(file_bytes),
        on_bad_lines="warn",  # Warn but skip malformed rows
        dtype=str,            # Read all as strings first, coerce later
    )

    # Normalize column names
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]

    total_rows = len(df)
    initial_count = len(df)

    # Drop completely empty rows
    df = df.dropna(how="all")
    error_rows = initial_count - len(df)

    if error_rows > 0:
        logger.warning(f"{filename}: Dropped {error_rows} fully-empty rows.")

    logger.info(f"Loaded {filename}: {total_rows} total rows, {len(df)} usable rows.")
    return df, total_rows, error_rows


def ingest_csv(
    file_bytes: bytes,
    filename: str,
    db,
    models: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Full CSV ingestion pipeline: validate → load → detect → persist.

    This is the main entry point for CSV uploads (API and scripts).

    Args:
        file_bytes: Raw CSV bytes
        filename: Original filename
        db: SQLAlchemy session
        models: Loaded model dict from training.load_models()

    Returns:
        Dict with import_id, row_count, anomaly_count, status, notes, etc.

    Raises:
        ValueError: If file fails validation
    """
    from app.models.dataset_import import DatasetImport
    from app.models.detection_event import DetectionEvent
    from app.services.detection import run_detection

    import_id = str(uuid.uuid4())

    # ── 1. Validate file ──────────────────────────────────────
    is_valid, error_msg = validate_csv_file(filename, file_bytes)
    if not is_valid:
        raise ValueError(error_msg)

    # ── 2. Create import record (status=processing) ───────────
    dataset_import = DatasetImport(
        import_id=import_id,
        filename=filename,
        source_type="csv_upload",
        status="processing",
        imported_at=datetime.now(timezone.utc),
    )
    db.add(dataset_import)
    db.flush()  # Get ID without full commit

    try:
        # ── 3. Load CSV ───────────────────────────────────────
        df, total_rows, error_rows = load_csv(file_bytes, filename)

        # ── 4. Validate DataFrame columns ─────────────────────
        is_valid_df, warnings = validate_dataframe(df)
        if not is_valid_df:
            raise ValueError(f"CSV validation failed: {warnings[0]}")

        has_labels = "label" in df.columns

        # ── 5. Run detection ──────────────────────────────────
        events_data = run_detection(
            df,
            models=models,
            pipeline=None,  # Detection uses models['pipeline']
            dataset_import_id=dataset_import.id,
        )

        # ── 6. Persist detection events ───────────────────────
        anomaly_count = 0
        for event_data in events_data:
            event = DetectionEvent(**event_data)
            db.add(event)
            if event_data["is_anomaly"]:
                anomaly_count += 1

        # ── 7. Update import record ───────────────────────────
        dataset_import.row_count = len(df)
        dataset_import.anomaly_count = anomaly_count
        dataset_import.error_count = error_rows
        dataset_import.has_labels = has_labels
        dataset_import.status = "completed"
        dataset_import.completed_at = datetime.now(timezone.utc)
        dataset_import.notes = (
            f"Processed {len(df)} rows. "
            f"{anomaly_count} anomalies detected. "
            + (f"Warnings: {'; '.join(warnings)}" if warnings else "")
        )

        db.commit()

        logger.info(
            f"Ingestion complete: import_id={import_id}, "
            f"rows={len(df)}, anomalies={anomaly_count}"
        )

        return {
            "import_id": import_id,
            "filename": filename,
            "row_count": len(df),
            "anomaly_count": anomaly_count,
            "error_count": error_rows,
            "has_labels": has_labels,
            "status": "completed",
            "warnings": warnings,
        }

    except Exception as e:
        dataset_import.status = "failed"
        dataset_import.error_message = str(e)
        db.commit()
        logger.error(f"Ingestion failed for {filename}: {e}")
        raise
