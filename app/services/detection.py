"""
app/services/detection.py — Threat detection service.

Takes preprocessed features and runs them through trained models to produce
DetectionEvent records with severity labels and explanations.

This layer clearly distinguishes:
- Model-generated predictions (IsolationForest / RandomForest)
- Rule-based severity assignment (applied on top of model scores)

IMPORTANT: Anomaly scores from IsolationForest are relative measures,
not calibrated probabilities. See assign_severity() for threshold documentation.
"""
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from app.config import settings

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
#  Severity thresholds (RULE-BASED on top of model predictions)
# ─────────────────────────────────────────────────────────────
#
# IsolationForest returns scores in roughly [-0.5, 0.5]:
#   Score > 0   → normal region (well inside the training distribution)
#   Score ≈ 0   → borderline
#   Score < 0   → anomalous (the more negative, the more anomalous)
#   Score < -0.1 → clearly anomalous by IsolationForest's own boundary
#
# We add an additional rule layer:
#   IF model says anomaly AND score < -0.15 → severity = "High"
#   IF model says anomaly AND score >= -0.15 → severity = "Suspicious"
#   IF model says normal → severity = "Normal"
#
# For RandomForest (when available):
#   probability >= 0.7 → High
#   probability >= 0.5 → Suspicious
#   probability < 0.5  → Normal (override IF if confident)

HIGH_SEVERITY_IF_THRESHOLD = -0.15   # IsolationForest score
SUSPICIOUS_IF_THRESHOLD = 0.0        # IsolationForest score (any anomaly prediction)
RF_HIGH_THRESHOLD = 0.70             # RandomForest class 1 probability
RF_SUSPICIOUS_THRESHOLD = 0.50       # RandomForest class 1 probability


def assign_severity(
    is_anomaly: bool,
    anomaly_score: Optional[float],
    rf_probability: Optional[float] = None,
) -> str:
    """
    Assign a human-readable severity level using rule-based logic.

    This function applies documented thresholds on top of model predictions.
    The rules are NOT part of the model — they are separate business logic.

    Args:
        is_anomaly: Whether IsolationForest flagged this event as anomalous
        anomaly_score: Raw IsolationForest score (lower = more anomalous)
        rf_probability: RandomForest class-1 probability (0-1), if available

    Returns:
        "Normal" | "Suspicious" | "High"
    """
    # If RandomForest is available, it takes precedence (it's supervised)
    if rf_probability is not None:
        if rf_probability >= RF_HIGH_THRESHOLD:
            return "High"
        elif rf_probability >= RF_SUSPICIOUS_THRESHOLD:
            return "Suspicious"
        else:
            return "Normal"

    # Fall back to IsolationForest rules
    if not is_anomaly:
        return "Normal"

    if anomaly_score is not None and anomaly_score < HIGH_SEVERITY_IF_THRESHOLD:
        return "High"

    return "Suspicious"


def build_alert_reason(
    is_anomaly: bool,
    anomaly_score: Optional[float],
    rf_probability: Optional[float],
    features: Dict[str, Any],
    severity: str,
) -> str:
    """
    Build a human-readable explanation for why an event was flagged.

    This explanation is rule-based and reflects the detection logic,
    not an intrinsic model explanation.

    Args:
        is_anomaly: Model anomaly flag
        anomaly_score: IsolationForest raw score
        rf_probability: RandomForest probability
        features: Original input features for context
        severity: Assigned severity

    Returns:
        Plain-English explanation string
    """
    reasons = []

    if not is_anomaly and (rf_probability is None or rf_probability < RF_SUSPICIOUS_THRESHOLD):
        return "No anomalous patterns detected. Event is consistent with normal baseline activity."

    # IsolationForest reason
    if is_anomaly and anomaly_score is not None:
        reasons.append(
            f"IsolationForest flagged this event as anomalous "
            f"(score={anomaly_score:.4f}; scores below 0 indicate anomaly)"
        )

    # RandomForest reason
    if rf_probability is not None and rf_probability >= RF_SUSPICIOUS_THRESHOLD:
        reasons.append(
            f"RandomForest classifier predicted {rf_probability:.1%} probability of being a threat"
        )

    # Feature-specific contextual reasons
    failed = features.get("failed_logins")
    if isinstance(failed, (int, float)) and not np.isnan(float(failed)) and failed > 5:
        reasons.append(f"High failed login count: {int(failed)} attempts")

    unusual = features.get("unusual_hour")
    if unusual in (True, 1, "true", "1"):
        reasons.append("Activity occurred outside normal business hours")

    bytes_out = features.get("bytes_out")
    if isinstance(bytes_out, (int, float)) and not np.isnan(float(bytes_out)) and bytes_out > 100_000:
        reasons.append(f"High outbound data transfer: {bytes_out:,.0f} bytes")

    port = features.get("port_number")
    suspicious_ports = {22, 23, 445, 3389, 4444, 8080, 8443}
    if isinstance(port, (int, float)) and not np.isnan(float(port)) and int(port) in suspicious_ports:
        reasons.append(f"Activity on sensitive port: {int(port)}")

    if not reasons:
        reasons.append(
            f"Combination of feature values deviates from the learned normal baseline"
        )

    return " | ".join(reasons)


def run_detection(
    df: pd.DataFrame,
    models: Dict[str, Any],
    pipeline: Any,
    dataset_import_id: Optional[int] = None,
    model_run_id: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Run threat detection on a DataFrame of events.

    Pipeline:
    1. Preprocess features using the fitted pipeline
    2. Run IsolationForest (always)
    3. Run RandomForest (if available)
    4. Assign severity using documented rules
    5. Build explanations
    6. Return list of event dicts ready for DB insertion

    Args:
        df: DataFrame of raw events
        models: Dict with 'isolation_forest', 'random_forest', 'pipeline' keys
        pipeline: (Deprecated, use models['pipeline'] instead)
        dataset_import_id: FK to DatasetImport record
        model_run_id: FK to ModelRun record

    Returns:
        List of dicts matching the DetectionEvent schema
    """
    from app.services.preprocessing import prepare_features, ALL_FEATURE_COLUMNS

    isolation_forest = models.get("isolation_forest")
    random_forest = models.get("random_forest")
    preprocessing_pipeline = models.get("pipeline")

    # Flag for whether we're using a trained model or rule-based fallback
    model_used = "isolation_forest"
    warning = None

    if isolation_forest is None or preprocessing_pipeline is None:
        logger.warning("No trained model found. Using rule-based fallback.")
        warning = "No trained model found — results are rule-based only and less accurate. Train a model first."
        return _rule_based_detection(df, dataset_import_id, model_run_id, warning)

    # Preprocess (inference mode — use existing fitted pipeline)
    try:
        X, _, _ = prepare_features(df, pipeline=preprocessing_pipeline, fit=False)
    except Exception as e:
        logger.error(f"Preprocessing failed: {e}")
        raise ValueError(f"Feature preprocessing failed: {e}") from e

    # IsolationForest predictions
    # predict() returns: 1 (normal), -1 (anomaly)
    if_preds = isolation_forest.predict(X)
    # decision_function() returns raw anomaly score
    if_scores = isolation_forest.decision_function(X)

    # RandomForest predictions (optional)
    rf_probs = None
    if random_forest is not None:
        try:
            rf_probs = random_forest.predict_proba(X)[:, 1]  # Class 1 probability
            model_used = "both"
        except Exception as e:
            logger.warning(f"RandomForest inference failed: {e}. Using IsolationForest only.")
            rf_probs = None

    # Build detection results
    events = []
    for i, row in df.iterrows():
        idx = list(df.index).index(i)
        is_anomaly = bool(if_preds[idx] == -1)
        anomaly_score = float(if_scores[idx])
        rf_prob = float(rf_probs[idx]) if rf_probs is not None else None

        severity = assign_severity(is_anomaly, anomaly_score, rf_prob)
        features_dict = row.to_dict()
        reason = build_alert_reason(
            is_anomaly, anomaly_score, rf_prob, features_dict, severity
        )

        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc),
            "source_ip": features_dict.get("source_ip"),
            "dest_ip": features_dict.get("dest_ip"),
            "protocol": features_dict.get("protocol"),
            "failed_logins": _safe_int(features_dict.get("failed_logins")),
            "bytes_in": _safe_float(features_dict.get("bytes_in")),
            "bytes_out": _safe_float(features_dict.get("bytes_out")),
            "connection_duration": _safe_float(features_dict.get("connection_duration")),
            "unusual_hour": _safe_bool(features_dict.get("unusual_hour")),
            "port_number": _safe_int(features_dict.get("port_number")),
            "raw_features_json": json.dumps({
                k: (v.item() if hasattr(v, 'item') else v)
                for k, v in features_dict.items()
                if k in ALL_FEATURE_COLUMNS
            }, default=str),
            "is_anomaly": is_anomaly,
            "anomaly_score": anomaly_score,
            "rf_probability": rf_prob,
            "severity": severity,
            "prediction_source": model_used,
            "alert_reason": reason,
            "dataset_import_id": dataset_import_id,
            "model_run_id": model_run_id,
        }
        events.append(event)

    logger.info(
        f"Detection complete: {len(events)} events, "
        f"{sum(1 for e in events if e['is_anomaly'])} anomalies"
    )
    return events


def _rule_based_detection(
    df: pd.DataFrame,
    dataset_import_id: Optional[int],
    model_run_id: Optional[int],
    warning: str,
) -> List[Dict[str, Any]]:
    """
    Fallback rule-based detection when no trained model exists.
    
    Uses simple heuristics:
    - failed_logins > 5 → suspicious
    - failed_logins > 10 → high
    - unusual_hour=True AND failed_logins > 3 → suspicious
    - bytes_out > 100000 → suspicious
    
    NOTE: These are crude rules, NOT ML predictions. Train a model for better results.
    """
    events = []
    for i, row in df.iterrows():
        features = row.to_dict()
        failed = _safe_int(features.get("failed_logins")) or 0
        unusual = _safe_bool(features.get("unusual_hour")) or False
        bytes_out = _safe_float(features.get("bytes_out")) or 0.0

        is_anomaly = failed > 5 or (unusual and failed > 3) or bytes_out > 100_000

        if failed > 10:
            severity = "High"
        elif is_anomaly:
            severity = "Suspicious"
        else:
            severity = "Normal"

        reason = build_alert_reason(is_anomaly, None, None, features, severity)
        reason = f"[Rule-based, no ML model] {reason}"

        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc),
            "source_ip": features.get("source_ip"),
            "dest_ip": features.get("dest_ip"),
            "protocol": features.get("protocol"),
            "failed_logins": _safe_int(features.get("failed_logins")),
            "bytes_in": _safe_float(features.get("bytes_in")),
            "bytes_out": _safe_float(features.get("bytes_out")),
            "connection_duration": _safe_float(features.get("connection_duration")),
            "unusual_hour": _safe_bool(features.get("unusual_hour")),
            "port_number": _safe_int(features.get("port_number")),
            "raw_features_json": json.dumps({}, default=str),
            "is_anomaly": is_anomaly,
            "anomaly_score": None,
            "rf_probability": None,
            "severity": severity,
            "prediction_source": "rule_based_fallback",
            "alert_reason": reason,
            "dataset_import_id": dataset_import_id,
            "model_run_id": model_run_id,
        }
        events.append(event)

    return events


# ─── Helpers ──────────────────────────────────────────────────

def _safe_int(val) -> Optional[int]:
    try:
        if val is None or (isinstance(val, float) and np.isnan(val)):
            return None
        return int(val)
    except (ValueError, TypeError):
        return None


def _safe_float(val) -> Optional[float]:
    try:
        if val is None or (isinstance(val, float) and np.isnan(val)):
            return None
        return float(val)
    except (ValueError, TypeError):
        return None


def _safe_bool(val) -> Optional[bool]:
    if val is None:
        return None
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    if isinstance(val, str):
        return val.lower() in ("true", "1", "yes")
    return None
