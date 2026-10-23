"""
app/models/detection_event.py — DetectionEvent SQLAlchemy model.

Stores the result of each individual analyzed event/record.
This is the primary output table of the threat detection pipeline.
"""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey
from app.database import Base


class DetectionEvent(Base):
    """
    Represents a single analyzed network/auth event with its threat prediction.

    Fields:
        id              — Auto-incrementing primary key (event ID in URLs)
        event_id        — UUID string for external references
        timestamp       — When the event was analyzed (UTC)
        source_ip       — Source IP address from the data
        dest_ip         — Destination IP address
        protocol        — Network protocol (TCP/UDP/etc.)
        failed_logins   — Number of failed login attempts
        bytes_in        — Bytes transferred inbound
        bytes_out       — Bytes transferred outbound
        connection_duration — Duration of connection in seconds
        unusual_hour    — Whether connection occurred outside business hours
        port_number     — Destination port
        is_anomaly      — True if model flagged as anomaly
        anomaly_score   — Raw IsolationForest score (negative = more anomalous)
                          NOTE: This is NOT a calibrated probability
        severity        — Human-readable severity: Normal / Suspicious / High
        prediction_source — 'isolation_forest' or 'random_forest'
        alert_reason    — Plain-English explanation of why this was flagged
        dataset_import_id — FK to the dataset batch this came from
        model_run_id    — FK to the model run that produced this prediction
    """
    __tablename__ = "detection_events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(36), unique=True, nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    # Input features (stored for auditability)
    source_ip = Column(String(45), nullable=True)
    dest_ip = Column(String(45), nullable=True)
    protocol = Column(String(10), nullable=True)
    failed_logins = Column(Integer, nullable=True)
    bytes_in = Column(Float, nullable=True)
    bytes_out = Column(Float, nullable=True)
    connection_duration = Column(Float, nullable=True)
    unusual_hour = Column(Boolean, nullable=True)
    port_number = Column(Integer, nullable=True)
    raw_features_json = Column(Text, nullable=True)  # Full feature set as JSON

    # Prediction results
    is_anomaly = Column(Boolean, nullable=False, default=False)
    anomaly_score = Column(Float, nullable=True)  # IsolationForest raw score
    rf_probability = Column(Float, nullable=True)  # RandomForest probability (0-1) if available
    severity = Column(String(20), nullable=False, default="Normal")  # Normal/Suspicious/High
    prediction_source = Column(String(50), nullable=True)  # Which model produced this
    alert_reason = Column(Text, nullable=True)  # Human-readable explanation

    # Relationships
    dataset_import_id = Column(Integer, ForeignKey("dataset_imports.id"), nullable=True)
    model_run_id = Column(Integer, ForeignKey("model_runs.id"), nullable=True)

    def __repr__(self):
        return (
            f"<DetectionEvent id={self.id} severity={self.severity} "
            f"is_anomaly={self.is_anomaly} score={self.anomaly_score:.3f if self.anomaly_score else 'N/A'}>"
        )
