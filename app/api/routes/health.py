"""
app/api/routes/health.py — Health check and API info endpoints.

GET /health — Returns application health status.
GET /       — Returns API information.
"""
import logging
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.database import get_db
from app.schemas.event_schemas import HealthResponse
from app.config import settings
from app.services.training import models_are_trained

logger = logging.getLogger(__name__)
router = APIRouter(tags=["health"])


@router.get("/", summary="API Information")
def api_info():
    """Returns basic information about the API."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "description": (
            "AI-Based Cybersecurity Threat Detection API. "
            "Provides ML-powered anomaly detection for financial institution security monitoring."
        ),
        "docs": "/docs",
        "redoc": "/redoc",
        "api_prefix": settings.api_prefix,
        "environment": settings.environment,
        "endpoints": {
            "health": "GET /health",
            "summary": f"GET {settings.api_prefix}/summary",
            "analyze": f"POST {settings.api_prefix}/analyze",
            "analyze_csv": f"POST {settings.api_prefix}/analyze/csv",
            "events": f"GET {settings.api_prefix}/events",
            "event_detail": f"GET {settings.api_prefix}/events/{{event_id}}",
            "model_metrics": f"GET {settings.api_prefix}/model/metrics",
        },
    }


@router.get("/health", response_model=HealthResponse, summary="Health Check")
def health_check(db: Session = Depends(get_db)):
    """
    Check application health status.

    Tests:
    - Database connectivity (executes a simple query)
    - Model availability (checks for trained model artifact on disk)
    - Total event count (from database)

    Returns 200 even if model is not trained — use model_loaded flag
    to determine if predictions will be ML-based or rule-based.
    """
    # Test database
    db_ok = False
    total_events = 0
    try:
        result = db.execute(text("SELECT COUNT(*) FROM detection_events"))
        total_events = result.scalar() or 0
        db_ok = True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")

    model_loaded = models_are_trained()

    return HealthResponse(
        status="healthy" if db_ok else "degraded",
        version=settings.app_version,
        model_loaded=model_loaded,
        database_ok=db_ok,
        total_events=total_events,
    )
