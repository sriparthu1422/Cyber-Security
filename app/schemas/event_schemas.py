"""
app/schemas/event_schemas.py — Pydantic schemas for API request/response validation.

These schemas define what data the API accepts and returns.
They are separate from SQLAlchemy models (which define the database structure).
"""
from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, Field, field_validator
import json


# ─────────────────────────────────────────────
#  Request Schemas (what the API accepts)
# ─────────────────────────────────────────────

class EventFeatures(BaseModel):
    """
    Features for a single network/authentication event to be analyzed.
    All fields are optional to support partial data, but at least some
    numeric features must be present for meaningful analysis.
    """
    source_ip: Optional[str] = Field(None, description="Source IP address")
    dest_ip: Optional[str] = Field(None, description="Destination IP address")
    protocol: Optional[str] = Field(None, description="Network protocol")
    failed_logins: Optional[int] = Field(None, ge=0, le=1000, description="Failed login attempts in session")
    bytes_in: Optional[float] = Field(None, ge=0, description="Bytes received")
    bytes_out: Optional[float] = Field(None, ge=0, description="Bytes sent")
    connection_duration: Optional[float] = Field(None, ge=0, description="Connection duration in seconds")
    unusual_hour: Optional[bool] = Field(None, description="True if outside business hours (8am-6pm)")
    port_number: Optional[int] = Field(None, ge=0, le=65535, description="Destination port")

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v):
        if v is not None:
            allowed = {"TCP", "UDP", "ICMP", "HTTP", "HTTPS", "FTP", "SSH", "DNS", "OTHER"}
            if v.upper() not in allowed:
                raise ValueError(f"Protocol must be one of: {', '.join(sorted(allowed))}")
            return v.upper()
        return v


class AnalyzeRequest(BaseModel):
    """Request body for POST /api/v1/analyze — analyze one or more events."""
    events: List[EventFeatures] = Field(
        ...,
        min_length=1,
        max_length=1000,
        description="List of events to analyze (1-1000 events per request)"
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "events": [
                    {
                        "source_ip": "10.0.0.5",
                        "dest_ip": "192.168.1.100",
                        "protocol": "TCP",
                        "failed_logins": 15,
                        "bytes_in": 2048.0,
                        "bytes_out": 512.0,
                        "connection_duration": 30.5,
                        "unusual_hour": True,
                        "port_number": 22
                    }
                ]
            }
        }
    }


# ─────────────────────────────────────────────
#  Response Schemas (what the API returns)
# ─────────────────────────────────────────────

class DetectionEventResponse(BaseModel):
    """Response schema for a single detection event."""
    id: int
    event_id: str
    timestamp: datetime
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    protocol: Optional[str] = None
    failed_logins: Optional[int] = None
    bytes_in: Optional[float] = None
    bytes_out: Optional[float] = None
    connection_duration: Optional[float] = None
    unusual_hour: Optional[bool] = None
    port_number: Optional[int] = None
    is_anomaly: bool
    anomaly_score: Optional[float] = None
    rf_probability: Optional[float] = None
    severity: str
    prediction_source: Optional[str] = None
    alert_reason: Optional[str] = None
    dataset_import_id: Optional[int] = None
    model_run_id: Optional[int] = None

    model_config = {"from_attributes": True}


class AnalyzeResponse(BaseModel):
    """Response from POST /api/v1/analyze."""
    total_analyzed: int
    anomalies_detected: int
    normal_events: int
    high_severity: int
    suspicious_events: int
    events: List[DetectionEventResponse]
    model_used: str
    warning: Optional[str] = None  # e.g., "No trained model found, used rule-based fallback"


class EventListResponse(BaseModel):
    """Paginated list of detection events."""
    total: int
    page: int
    per_page: int
    pages: int
    events: List[DetectionEventResponse]


class DatasetImportResponse(BaseModel):
    """Response schema for a dataset import record."""
    id: int
    import_id: str
    filename: str
    source_type: str
    row_count: Optional[int] = None
    anomaly_count: Optional[int] = None
    error_count: Optional[int] = None
    has_labels: Optional[bool] = None
    status: str
    error_message: Optional[str] = None
    notes: Optional[str] = None
    imported_at: datetime
    completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ModelMetricsResponse(BaseModel):
    """Response schema for model evaluation metrics."""
    run_id: str
    model_type: str
    trained_at: datetime
    training_rows: Optional[int] = None
    test_rows: Optional[int] = None
    has_labels: bool
    contamination: Optional[float] = None
    n_estimators: Optional[int] = None
    # Supervised metrics (None if no labels available)
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    accuracy: Optional[float] = None
    # Unsupervised counts
    if_anomaly_count: Optional[int] = None
    if_normal_count: Optional[int] = None
    artifact_path: Optional[str] = None
    status: str
    notes: Optional[str] = None

    model_config = {"from_attributes": True}


class SummaryResponse(BaseModel):
    """Response from GET /api/v1/summary — dashboard KPI data."""
    total_events: int
    total_anomalies: int
    total_normal: int
    high_severity_count: int
    suspicious_count: int
    total_datasets_imported: int
    total_model_runs: int
    latest_model_run_at: Optional[datetime] = None
    model_trained: bool
    anomaly_rate_pct: float  # Percentage of events flagged as anomalies

    model_config = {"from_attributes": True}


class HealthResponse(BaseModel):
    """Response from GET /health."""
    status: str
    version: str
    model_loaded: bool
    database_ok: bool
    total_events: int
