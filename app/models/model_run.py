"""
app/models/model_run.py — ModelRun SQLAlchemy model.

Tracks each model training session, storing configuration and evaluation metrics.
Enables reproducibility and comparison between training runs.
"""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean
from app.database import Base


class ModelRun(Base):
    """
    Represents a single model training run.

    Fields:
        id              — Auto-incrementing primary key
        run_id          — UUID string for external references
        model_type      — 'isolation_forest', 'random_forest', 'both'
        training_rows   — Number of rows used for training
        test_rows       — Number of rows held out for testing
        has_labels      — Whether supervised training was performed
        random_seed     — Seed used for reproducibility
        contamination   — IsolationForest contamination parameter
        n_estimators    — Number of trees (both models)
        
        # Evaluation metrics (only populated when ground-truth labels exist)
        precision       — Precision score on test set
        recall          — Recall score on test set
        f1_score        — F1 score on test set
        accuracy        — Overall accuracy
        
        # IsolationForest anomaly counts (always populated)
        if_anomaly_count — Anomalies detected by IsolationForest
        if_normal_count  — Normal events detected by IsolationForest
        
        artifact_path   — Path to the saved .joblib file
        status          — 'running', 'completed', 'failed'
        error_message   — Error details if training failed
        trained_at      — When training started
        completed_at    — When training finished
        notes           — Human-readable summary of results
    """
    __tablename__ = "model_runs"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String(36), unique=True, nullable=False, index=True)
    model_type = Column(String(30), nullable=False, default="isolation_forest")
    training_rows = Column(Integer, nullable=True)
    test_rows = Column(Integer, nullable=True)
    has_labels = Column(Boolean, nullable=False, default=False)
    random_seed = Column(Integer, nullable=True)
    contamination = Column(Float, nullable=True)
    n_estimators = Column(Integer, nullable=True)

    # Supervised metrics (null when no labels)
    precision = Column(Float, nullable=True)
    recall = Column(Float, nullable=True)
    f1_score = Column(Float, nullable=True)
    accuracy = Column(Float, nullable=True)

    # IsolationForest counts
    if_anomaly_count = Column(Integer, nullable=True)
    if_normal_count = Column(Integer, nullable=True)

    # Artifacts
    artifact_path = Column(String(500), nullable=True)

    # Status
    status = Column(String(20), nullable=False, default="running")
    error_message = Column(Text, nullable=True)
    trained_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)

    def __repr__(self):
        return (
            f"<ModelRun id={self.id} type={self.model_type!r} "
            f"f1={self.f1_score} status={self.status!r}>"
        )
