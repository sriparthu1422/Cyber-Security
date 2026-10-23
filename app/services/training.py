"""
app/services/training.py — Model training service.

Trains:
1. IsolationForest (unsupervised anomaly detection) — always trained
2. RandomForest classifier (supervised) — trained only when labels are present

Both models are saved to disk as .joblib artifacts for later inference.
A fixed random seed ensures reproducibility.

IMPORTANT DISCLAIMER:
- IsolationForest anomaly scores are NOT calibrated probabilities.
  A score of -0.1 does not mean "10% chance of attack".
  The score is a relative measure — more negative = more anomalous.
- Model performance on this synthetic dataset does not reflect real-world accuracy.
"""
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    precision_score, recall_score, f1_score, accuracy_score,
    confusion_matrix
)

from app.config import settings, ARTIFACTS_PATH

logger = logging.getLogger(__name__)

# Artifact filenames
ISOLATION_FOREST_FILE = "isolation_forest.joblib"
RANDOM_FOREST_FILE = "random_forest.joblib"
PIPELINE_FILE = "preprocessing_pipeline.joblib"


def get_artifact_path(filename: str) -> Path:
    """Return full path to a model artifact file."""
    return ARTIFACTS_PATH / filename


def save_artifact(obj: Any, filename: str) -> Path:
    """Save a Python object to disk using joblib."""
    path = get_artifact_path(filename)
    joblib.dump(obj, path)
    logger.info(f"Artifact saved: {path}")
    return path


def load_artifact(filename: str) -> Optional[Any]:
    """
    Load a model artifact from disk.
    Returns None if the file does not exist.
    """
    path = get_artifact_path(filename)
    if not path.exists():
        logger.warning(f"Artifact not found: {path}")
        return None
    try:
        obj = joblib.load(path)
        logger.info(f"Artifact loaded: {path}")
        return obj
    except Exception as e:
        logger.error(f"Failed to load artifact {path}: {e}")
        return None


def train_isolation_forest(
    X_train: np.ndarray,
    contamination: float = 0.1,
    n_estimators: int = 100,
    random_state: int = 42,
) -> IsolationForest:
    """
    Train an IsolationForest model on the training data.

    IsolationForest works by randomly partitioning data.
    Anomalies are isolated in fewer steps, giving them lower scores.

    Args:
        X_train: Feature matrix (already preprocessed)
        contamination: Expected fraction of anomalies (0.01-0.5).
                       Controls the decision threshold.
        n_estimators: Number of trees in the forest
        random_state: Seed for reproducibility

    Returns:
        Fitted IsolationForest model

    Note:
        The contamination parameter affects where the decision boundary is set,
        not the actual distribution of anomalies in the data.
    """
    logger.info(
        f"Training IsolationForest: {len(X_train)} samples, "
        f"contamination={contamination}, n_estimators={n_estimators}"
    )

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,  # Use all CPU cores
    )
    model.fit(X_train)

    logger.info("IsolationForest training complete.")
    return model


def train_random_forest(
    X_train: np.ndarray,
    y_train: np.ndarray,
    n_estimators: int = 100,
    random_state: int = 42,
) -> RandomForestClassifier:
    """
    Train a RandomForest classifier for supervised threat detection.

    Only used when ground-truth labels are present in the dataset.

    Args:
        X_train: Feature matrix (already preprocessed)
        y_train: Binary labels (0=normal, 1=anomaly/threat)
        n_estimators: Number of trees
        random_state: Seed for reproducibility

    Returns:
        Fitted RandomForestClassifier
    """
    logger.info(
        f"Training RandomForest: {len(X_train)} samples, "
        f"class distribution: {dict(zip(*np.unique(y_train, return_counts=True)))}"
    )

    model = RandomForestClassifier(
        n_estimators=n_estimators,
        random_state=random_state,
        n_jobs=-1,
        class_weight="balanced",  # Handle class imbalance
    )
    model.fit(X_train, y_train)

    logger.info("RandomForest training complete.")
    return model


def evaluate_supervised_model(
    model: RandomForestClassifier,
    X_test: np.ndarray,
    y_test: np.ndarray,
) -> Dict[str, Any]:
    """
    Evaluate a trained supervised model on the test set.

    Args:
        model: Fitted RandomForestClassifier
        X_test: Test feature matrix
        y_test: True labels

    Returns:
        Dictionary with precision, recall, f1, accuracy, confusion_matrix
    """
    y_pred = model.predict(X_test)

    metrics = {
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y_test, y_pred, zero_division=0)),
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
    }

    logger.info(
        f"Evaluation metrics: "
        f"precision={metrics['precision']:.3f}, "
        f"recall={metrics['recall']:.3f}, "
        f"f1={metrics['f1_score']:.3f}, "
        f"accuracy={metrics['accuracy']:.3f}"
    )
    return metrics


def train_models(
    X: np.ndarray,
    y: Optional[np.ndarray],
    pipeline: Any,
    test_size: float = 0.2,
) -> Tuple[Dict[str, Any], str]:
    """
    Main training function that trains both models and saves artifacts.

    Args:
        X: Full preprocessed feature matrix
        y: Labels (None for unsupervised only)
        pipeline: Fitted preprocessing pipeline
        test_size: Fraction for test split

    Returns:
        (metrics_dict, run_id)
        metrics_dict: All evaluation metrics and training details
        run_id: UUID identifying this training run
    """
    from app.services.preprocessing import split_data

    run_id = str(uuid.uuid4())
    random_seed = settings.random_seed
    n_estimators = settings.random_forest_n_estimators
    contamination = settings.isolation_forest_contamination

    # Split data
    X_train, X_test, y_train, y_test = split_data(
        X, y, test_size=test_size, random_state=random_seed
    )

    metrics = {
        "run_id": run_id,
        "training_rows": len(X_train),
        "test_rows": len(X_test),
        "has_labels": y is not None,
        "random_seed": random_seed,
        "contamination": contamination,
        "n_estimators": n_estimators,
        "model_type": "both" if y is not None else "isolation_forest",
    }

    # Always train IsolationForest (unsupervised)
    if_model = train_isolation_forest(
        X_train,
        contamination=contamination,
        n_estimators=n_estimators,
        random_state=random_seed,
    )

    # Get IsolationForest predictions on the full dataset
    if_preds = if_model.predict(X)
    metrics["if_anomaly_count"] = int(np.sum(if_preds == -1))
    metrics["if_normal_count"] = int(np.sum(if_preds == 1))

    # Save IsolationForest
    if_path = save_artifact(if_model, ISOLATION_FOREST_FILE)
    metrics["artifact_path"] = str(if_path)

    # Train RandomForest if labels available
    if y is not None and y_train is not None:
        rf_model = train_random_forest(
            X_train, y_train,
            n_estimators=n_estimators,
            random_state=random_seed,
        )
        rf_metrics = evaluate_supervised_model(rf_model, X_test, y_test)
        metrics.update(rf_metrics)
        save_artifact(rf_model, RANDOM_FOREST_FILE)
        metrics["model_type"] = "both"
    else:
        logger.info("No labels found — skipping RandomForest training.")

    # Always save the preprocessing pipeline
    save_artifact(pipeline, PIPELINE_FILE)

    logger.info(f"Training run {run_id} completed successfully.")
    return metrics, run_id


def load_models() -> Dict[str, Optional[Any]]:
    """
    Load all trained model artifacts from disk.

    Returns:
        Dictionary with keys 'isolation_forest', 'random_forest', 'pipeline'
        Values are None if the artifact file does not exist.
    """
    return {
        "isolation_forest": load_artifact(ISOLATION_FOREST_FILE),
        "random_forest": load_artifact(RANDOM_FOREST_FILE),
        "pipeline": load_artifact(PIPELINE_FILE),
    }


def models_are_trained() -> bool:
    """Check if at least the IsolationForest model exists on disk."""
    return get_artifact_path(ISOLATION_FOREST_FILE).exists()
