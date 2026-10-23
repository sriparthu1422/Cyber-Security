"""
app/main.py — FastAPI application entry point.

This is the main FastAPI application. It:
1. Creates the FastAPI app with metadata
2. Configures CORS middleware
3. Initializes the database on startup
4. Loads trained models into memory
5. Registers all API routers
6. Provides the / and /health endpoints

Run with:
    uvicorn app.main:app --reload --port 8000

API documentation available at:
    http://localhost:8000/docs  (Swagger UI)
    http://localhost:8000/redoc (ReDoc)
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import init_db

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ─── Application State ────────────────────────────────────────
# Models are loaded once at startup and shared across all requests.
# This avoids reloading model artifacts (potentially large) on every request.
_loaded_models: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.
    
    Startup: Initialize database tables, load ML models.
    Shutdown: Clean up resources.
    """
    # ── Startup ──
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")

    # Initialize database (creates tables if they don't exist)
    init_db()
    logger.info("Database initialized.")

    # Load ML models (if trained)
    from app.services.training import load_models, models_are_trained
    if models_are_trained():
        global _loaded_models
        _loaded_models = load_models()
        loaded_names = [k for k, v in _loaded_models.items() if v is not None]
        logger.info(f"ML models loaded: {loaded_names}")
    else:
        logger.warning(
            "No trained models found. API will use rule-based fallback. "
            "Train models with: python scripts/train_model.py"
        )

    yield  # Application runs here

    # ── Shutdown ──
    logger.info("Application shutting down.")
    _loaded_models.clear()


# ─── FastAPI App ──────────────────────────────────────────────
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="""
## AI-Based Cybersecurity Threat Detection API

This API provides ML-powered anomaly detection for financial institution security monitoring.

### Key Features
- **IsolationForest** unsupervised anomaly detection
- **RandomForest** supervised classification (when labels are available)
- Persistent event storage in SQLite
- CSV upload and batch analysis
- Model evaluation metrics

### Data Disclaimer
The sample dataset is **synthetic** and was generated for demonstration purposes only.
It does NOT represent real financial institution data or validated attack patterns.

### Score Interpretation
IsolationForest anomaly scores are **relative measures**, not calibrated probabilities.
A score of -0.2 means "more anomalous than -0.1", but does NOT mean "20% attack probability".
""",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ─── CORS Middleware ──────────────────────────────────────────
# Allow Streamlit dashboard and local development to access the API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins + ["http://localhost:8501", "http://127.0.0.1:8501"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Register Routers ─────────────────────────────────────────
from app.api.routes.health import router as health_router
from app.api.routes.events import router as events_router
from app.api.routes.analyze import router as analyze_router
from app.api.routes.model import router as model_router

app.include_router(health_router)
app.include_router(events_router)
app.include_router(analyze_router)
app.include_router(model_router)

logger.info("All routers registered.")
