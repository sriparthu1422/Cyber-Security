"""
app/models/dataset_import.py — DatasetImport SQLAlchemy model.

Tracks each CSV file or sample dataset that was loaded into the system.
Provides an audit trail of what data was analyzed and when.
"""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean
from app.database import Base


class DatasetImport(Base):
    """
    Represents a dataset ingestion event (CSV upload or sample data load).

    Fields:
        id              — Auto-incrementing primary key
        import_id       — UUID string for external references
        filename        — Original filename (or 'sample_data' for built-in dataset)
        source_type     — 'csv_upload', 'sample_data', 'batch_script'
        row_count       — Number of rows processed
        anomaly_count   — Number of rows flagged as anomalies
        error_count     — Number of rows that failed validation
        has_labels      — Whether the dataset had ground-truth labels
        status          — 'processing', 'completed', 'failed'
        error_message   — Error details if status is 'failed'
        notes           — Optional user notes or preprocessing summary
        imported_at     — When the import was created
        completed_at    — When processing finished
    """
    __tablename__ = "dataset_imports"

    id = Column(Integer, primary_key=True, index=True)
    import_id = Column(String(36), unique=True, nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    source_type = Column(String(50), nullable=False, default="csv_upload")
    row_count = Column(Integer, nullable=True)
    anomaly_count = Column(Integer, nullable=True)
    error_count = Column(Integer, nullable=True, default=0)
    has_labels = Column(Boolean, nullable=True)
    status = Column(String(20), nullable=False, default="processing")
    error_message = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    imported_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)

    def __repr__(self):
        return (
            f"<DatasetImport id={self.id} filename={self.filename!r} "
            f"rows={self.row_count} anomalies={self.anomaly_count} status={self.status!r}>"
        )
