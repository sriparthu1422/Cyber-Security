"""
app/api/routes/events.py — Detection event retrieval endpoints.

GET /api/v1/events         — List events with pagination and filtering
GET /api/v1/events/{id}    — Get one event by ID
GET /api/v1/summary        — Dashboard KPI summary
"""
import logging
import math
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models.detection_event import DetectionEvent
from app.models.dataset_import import DatasetImport
from app.models.model_run import ModelRun
from app.schemas.event_schemas import (
    DetectionEventResponse,
    EventListResponse,
    SummaryResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["events"])


@router.get("/summary", response_model=SummaryResponse, summary="Detection Summary")
def get_summary(db: Session = Depends(get_db)):
    """
    Returns KPI statistics derived from actual database records.

    All values come from real computations — no hardcoded data.
    """
    total_events = db.query(func.count(DetectionEvent.id)).scalar() or 0
    total_anomalies = (
        db.query(func.count(DetectionEvent.id))
        .filter(DetectionEvent.is_anomaly == True)
        .scalar() or 0
    )
    total_normal = total_events - total_anomalies
    high_count = (
        db.query(func.count(DetectionEvent.id))
        .filter(DetectionEvent.severity == "High")
        .scalar() or 0
    )
    suspicious_count = (
        db.query(func.count(DetectionEvent.id))
        .filter(DetectionEvent.severity == "Suspicious")
        .scalar() or 0
    )
    total_imports = db.query(func.count(DatasetImport.id)).scalar() or 0
    total_model_runs = db.query(func.count(ModelRun.id)).scalar() or 0

    # Latest model run timestamp
    latest_run = (
        db.query(ModelRun)
        .filter(ModelRun.status == "completed")
        .order_by(ModelRun.trained_at.desc())
        .first()
    )

    from app.services.training import models_are_trained
    model_trained = models_are_trained()

    anomaly_rate = (total_anomalies / total_events * 100) if total_events > 0 else 0.0

    return SummaryResponse(
        total_events=total_events,
        total_anomalies=total_anomalies,
        total_normal=total_normal,
        high_severity_count=high_count,
        suspicious_count=suspicious_count,
        total_datasets_imported=total_imports,
        total_model_runs=total_model_runs,
        latest_model_run_at=latest_run.trained_at if latest_run else None,
        model_trained=model_trained,
        anomaly_rate_pct=round(anomaly_rate, 2),
    )


@router.get("/events", response_model=EventListResponse, summary="List Detection Events")
def list_events(
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    per_page: int = Query(20, ge=1, le=100, description="Events per page (max 100)"),
    severity: Optional[str] = Query(None, description="Filter by severity: Normal/Suspicious/High"),
    is_anomaly: Optional[bool] = Query(None, description="Filter by anomaly flag"),
    dataset_import_id: Optional[int] = Query(None, description="Filter by dataset import"),
    db: Session = Depends(get_db),
):
    """
    List detection events with pagination and optional filtering.

    All filters are additive (AND logic).
    Results are ordered by most recent first.
    """
    query = db.query(DetectionEvent)

    if severity is not None:
        allowed_severities = {"Normal", "Suspicious", "High"}
        if severity not in allowed_severities:
            raise HTTPException(
                status_code=422,
                detail=f"severity must be one of: {', '.join(sorted(allowed_severities))}"
            )
        query = query.filter(DetectionEvent.severity == severity)

    if is_anomaly is not None:
        query = query.filter(DetectionEvent.is_anomaly == is_anomaly)

    if dataset_import_id is not None:
        query = query.filter(DetectionEvent.dataset_import_id == dataset_import_id)

    total = query.count()
    pages = math.ceil(total / per_page) if total > 0 else 1
    offset = (page - 1) * per_page

    events = (
        query
        .order_by(DetectionEvent.timestamp.desc())
        .offset(offset)
        .limit(per_page)
        .all()
    )

    return EventListResponse(
        total=total,
        page=page,
        per_page=per_page,
        pages=pages,
        events=[DetectionEventResponse.model_validate(e) for e in events],
    )


@router.get(
    "/events/{event_id}",
    response_model=DetectionEventResponse,
    summary="Get Detection Event Detail",
)
def get_event(event_id: int, db: Session = Depends(get_db)):
    """
    Retrieve a single detection event by its integer ID.

    The event detail includes:
    - All input features
    - Model prediction and anomaly score
    - Severity assignment
    - Human-readable explanation of why it was flagged
    """
    event = db.query(DetectionEvent).filter(DetectionEvent.id == event_id).first()
    if event is None:
        raise HTTPException(status_code=404, detail=f"Event with id={event_id} not found.")

    return DetectionEventResponse.model_validate(event)
