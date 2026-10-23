"""
tests/conftest.py — Shared pytest fixtures.

Provides:
- Isolated test database (temporary SQLite in memory/file)
- Test FastAPI client (TestClient wired to test DB)
- Sample DataFrames for preprocessing tests
- Pre-trained test models (trained on tiny synthetic data)

All fixtures use temporary resources that are cleaned up after each test.
They do NOT modify the production database or model artifacts.

KEY FIX — StaticPool:
    SQLite `sqlite:///:memory:` creates a NEW empty database per connection.
    Tables created in connection A are invisible to connection B.
    Using `StaticPool` forces all engine connections to share the SAME
    underlying connection object, so tables created once are visible everywhere.

IMPORTANT: This conftest patches `app.database.engine` and `app.database.SessionLocal`
globally so that ALL code paths (FastAPI deps, context managers, scripts) use the
test DB instead of the production DB.
"""
import os
import sys
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool      # ← KEY FIX

# ── Add project root to path ──────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent))

# Set test environment BEFORE importing app modules so pydantic-settings
# reads these values when building the Settings object.
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["ARTIFACTS_DIR"] = tempfile.mkdtemp()
os.environ["ENVIRONMENT"] = "testing"


# ─────────────────────────────────────────────────────────────────────────────
# Session-scoped: sample DataFrames
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def test_artifacts_dir(tmp_path_factory) -> Path:
    """Temporary directory for model artifacts during tests."""
    return tmp_path_factory.mktemp("artifacts")


@pytest.fixture(scope="session")
def sample_df() -> pd.DataFrame:
    """
    Small reproducible DataFrame for preprocessing tests.
    Contains both normal and anomalous patterns.
    """
    np.random.seed(42)
    n, n_anomaly = 100, 12

    normal_rows = [
        {
            "source_ip": "192.0.2.1",
            "dest_ip": "198.51.100.1",
            "protocol": np.random.choice(["TCP", "UDP", "HTTPS"]),
            "failed_logins": int(np.random.poisson(0.3)),
            "bytes_in": float(np.exp(np.random.normal(8, 1))),
            "bytes_out": float(np.exp(np.random.normal(7, 1))),
            "connection_duration": float(np.random.exponential(30)),
            "unusual_hour": False,
            "port_number": int(np.random.choice([80, 443, 22, 53])),
            "label": 0,
        }
        for _ in range(n - n_anomaly)
    ]

    anomaly_rows = [
        {
            "source_ip": "203.0.113.1",
            "dest_ip": "192.0.2.99",
            "protocol": "TCP",
            "failed_logins": int(np.random.randint(20, 80)),
            "bytes_in": float(np.exp(np.random.normal(5, 0.5))),
            "bytes_out": float(np.exp(np.random.normal(13, 1))),
            "connection_duration": float(np.random.exponential(300)),
            "unusual_hour": True,
            "port_number": int(np.random.choice([4444, 6667, 9999])),
            "label": 1,
        }
        for _ in range(n_anomaly)
    ]

    df = pd.DataFrame(normal_rows + anomaly_rows)
    return df.sample(frac=1, random_state=42).reset_index(drop=True)


@pytest.fixture(scope="session")
def sample_df_no_labels(sample_df) -> pd.DataFrame:
    """Sample DataFrame without label column (for unsupervised tests)."""
    return sample_df.drop(columns=["label"])


@pytest.fixture(scope="session")
def trained_models(sample_df, test_artifacts_dir):
    """
    Train IsolationForest + RandomForest on sample data.
    Saves artifacts to test_artifacts_dir.
    Returns the models dict for inference tests.
    """
    import app.services.training as training_module

    original_path = training_module.ARTIFACTS_PATH
    training_module.ARTIFACTS_PATH = test_artifacts_dir

    from app.services.preprocessing import prepare_features
    from app.services.training import train_models

    X, y, pipeline = prepare_features(sample_df, fit=True)
    train_models(X, y, pipeline)

    models = {
        "isolation_forest": training_module.load_artifact(training_module.ISOLATION_FOREST_FILE),
        "random_forest": training_module.load_artifact(training_module.RANDOM_FOREST_FILE),
        "pipeline": training_module.load_artifact(training_module.PIPELINE_FILE),
    }

    yield models

    training_module.ARTIFACTS_PATH = original_path


# ─────────────────────────────────────────────────────────────────────────────
# Per-test: isolated database
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def test_db_engine():
    """
    Isolated in-memory SQLite engine with all tables pre-created.

    Uses StaticPool so ALL sessions share the same underlying SQLite
    connection. Without this, each new session gets its own empty
    in-memory DB (different connection = different database in SQLite).

    Imports ALL model modules BEFORE create_all() so SQLAlchemy metadata
    knows about every table.
    """
    # These imports must happen BEFORE create_all()
    import app.database as db_module
    from app.models import detection_event, dataset_import, model_run  # noqa: F401

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,   # ← KEY: all connections share one SQLite DB
    )
    db_module.Base.metadata.create_all(bind=engine)
    yield engine
    db_module.Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def test_db(test_db_engine):
    """Provide a test database session bound to the test engine."""
    import app.database as db_module
    from app.models import detection_event, dataset_import, model_run  # noqa: F401

    Session = sessionmaker(bind=test_db_engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def test_client(test_db_engine, test_artifacts_dir):
    """
    FastAPI TestClient wired to an isolated in-memory test database.

    Strategy: patch the global `app.database.engine` and `app.database.SessionLocal`
    so that ALL code paths (FastAPI dependency injection, context managers like
    `get_db_session()`, and scripts) use the test DB instead of the real DB.

    The production cybersec_ai.db is never touched during tests.
    """
    import app.database as db_module
    import app.services.training as training_module
    from app.models import detection_event, dataset_import, model_run  # noqa: F401
    from app.main import app
    from app.database import get_db

    # ── Patch the global engine and SessionLocal ──────────────
    original_engine = db_module.engine
    original_session_local = db_module.SessionLocal

    db_module.engine = test_db_engine
    db_module.SessionLocal = sessionmaker(
        autocommit=False, autoflush=False, bind=test_db_engine
    )

    # ── Override FastAPI dependency (belt and suspenders) ─────
    def override_get_db():
        session = db_module.SessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db

    # ── Point artifacts to test dir ───────────────────────────
    original_artifacts = training_module.ARTIFACTS_PATH
    training_module.ARTIFACTS_PATH = test_artifacts_dir

    with TestClient(app, raise_server_exceptions=True) as client:
        yield client

    # ── Restore everything ────────────────────────────────────
    app.dependency_overrides.clear()
    db_module.engine = original_engine
    db_module.SessionLocal = original_session_local
    training_module.ARTIFACTS_PATH = original_artifacts


# ─────────────────────────────────────────────────────────────────────────────
# Event fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def normal_event() -> dict:
    """A typical normal network event."""
    return {
        "source_ip": "192.0.2.10",
        "dest_ip": "198.51.100.5",
        "protocol": "HTTPS",
        "failed_logins": 0,
        "bytes_in": 4096.0,
        "bytes_out": 1024.0,
        "connection_duration": 10.0,
        "unusual_hour": False,
        "port_number": 443,
    }


@pytest.fixture
def anomalous_event() -> dict:
    """A clearly anomalous event (brute force + after-hours + suspicious port)."""
    return {
        "source_ip": "203.0.113.99",
        "dest_ip": "192.0.2.1",
        "protocol": "TCP",
        "failed_logins": 50,
        "bytes_in": 512.0,
        "bytes_out": 5_000_000.0,
        "connection_duration": 600.0,
        "unusual_hour": True,
        "port_number": 4444,
    }
