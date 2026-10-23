"""
tests/test_detection.py — Tests for the threat detection service.

Tests:
- Normal events produce Normal severity
- Anomalous events produce Suspicious/High severity  
- Severity assignment rules (documented thresholds)
- Alert reason generation
- Rule-based fallback (no model)
- Detection with real model (integration)
"""
import numpy as np
import pandas as pd
import pytest


class TestSeverityAssignment:
    def test_normal_event_gets_normal_severity(self):
        from app.services.detection import assign_severity
        result = assign_severity(is_anomaly=False, anomaly_score=0.15)
        assert result == "Normal"

    def test_borderline_anomaly_gets_suspicious(self):
        from app.services.detection import assign_severity
        # Score between 0 and -0.15 → Suspicious
        result = assign_severity(is_anomaly=True, anomaly_score=-0.05)
        assert result == "Suspicious"

    def test_strong_anomaly_gets_high(self):
        from app.services.detection import assign_severity
        # Score below -0.15 → High
        result = assign_severity(is_anomaly=True, anomaly_score=-0.20)
        assert result == "High"

    def test_rf_probability_overrides_if(self):
        """RandomForest probability should take precedence over IsolationForest."""
        from app.services.detection import assign_severity
        # IF says normal but RF says high probability
        result = assign_severity(is_anomaly=False, anomaly_score=0.10, rf_probability=0.85)
        assert result == "High"

    def test_rf_suspicious_threshold(self):
        from app.services.detection import assign_severity
        result = assign_severity(is_anomaly=True, anomaly_score=-0.20, rf_probability=0.60)
        assert result == "Suspicious"

    def test_rf_normal_threshold(self):
        from app.services.detection import assign_severity
        result = assign_severity(is_anomaly=True, anomaly_score=-0.20, rf_probability=0.30)
        assert result == "Normal"


class TestAlertReason:
    def test_normal_event_has_no_alert_reason(self):
        from app.services.detection import build_alert_reason
        reason = build_alert_reason(
            is_anomaly=False, anomaly_score=0.1, rf_probability=None,
            features={"failed_logins": 0}, severity="Normal"
        )
        assert "no anomalous" in reason.lower() or "normal" in reason.lower()

    def test_high_failed_logins_mentioned(self):
        from app.services.detection import build_alert_reason
        reason = build_alert_reason(
            is_anomaly=True, anomaly_score=-0.2, rf_probability=None,
            features={"failed_logins": 25}, severity="High"
        )
        assert "25" in reason or "failed" in reason.lower()

    def test_unusual_hour_mentioned(self):
        from app.services.detection import build_alert_reason
        reason = build_alert_reason(
            is_anomaly=True, anomaly_score=-0.1, rf_probability=None,
            features={"unusual_hour": True, "failed_logins": 0}, severity="Suspicious"
        )
        assert "business hours" in reason.lower() or "unusual" in reason.lower()

    def test_suspicious_port_mentioned(self):
        from app.services.detection import build_alert_reason
        reason = build_alert_reason(
            is_anomaly=True, anomaly_score=-0.15, rf_probability=None,
            features={"port_number": 4444}, severity="High"
        )
        assert "4444" in reason or "sensitive port" in reason.lower()


class TestRuleBasedDetection:
    """Tests for detection when no ML model is available."""

    def test_high_failed_logins_flagged(self, normal_event):
        from app.services.detection import run_detection
        df = pd.DataFrame([{**normal_event, "failed_logins": 20}])
        # No models
        events = run_detection(df, models={}, pipeline=None)
        assert len(events) == 1
        assert events[0]["is_anomaly"] is True
        assert "rule_based_fallback" in events[0]["prediction_source"]

    def test_low_failed_logins_normal(self, normal_event):
        from app.services.detection import run_detection
        df = pd.DataFrame([normal_event])
        events = run_detection(df, models={}, pipeline=None)
        assert events[0]["is_anomaly"] is False
        assert events[0]["severity"] == "Normal"


class TestDetectionWithModel:
    """Integration tests: detection with trained IsolationForest."""

    def test_batch_detection_returns_all_events(self, sample_df, trained_models):
        from app.services.detection import run_detection

        df = sample_df.drop(columns=["label"])
        events = run_detection(df, models=trained_models, pipeline=None)
        assert len(events) == len(sample_df)

    def test_event_has_required_fields(self, normal_event, trained_models):
        from app.services.detection import run_detection

        df = pd.DataFrame([normal_event])
        events = run_detection(df, models=trained_models, pipeline=None)
        event = events[0]

        required_fields = [
            "event_id", "timestamp", "is_anomaly", "anomaly_score",
            "severity", "alert_reason", "prediction_source"
        ]
        for field in required_fields:
            assert field in event, f"Missing field: {field}"

    def test_anomaly_score_is_float(self, anomalous_event, trained_models):
        from app.services.detection import run_detection

        df = pd.DataFrame([anomalous_event])
        events = run_detection(df, models=trained_models, pipeline=None)
        score = events[0]["anomaly_score"]
        assert isinstance(score, float)

    def test_event_id_is_uuid(self, normal_event, trained_models):
        from app.services.detection import run_detection
        import uuid

        df = pd.DataFrame([normal_event])
        events = run_detection(df, models=trained_models, pipeline=None)
        event_id = events[0]["event_id"]
        # Should be parseable as UUID
        parsed = uuid.UUID(event_id)
        assert str(parsed) == event_id

    def test_anomalous_sample_produces_some_anomalies(self, sample_df, trained_models):
        """
        Integration test: when we run detection on our labeled sample data,
        at least some events should be flagged as anomalies.
        
        We don't assert exact numbers since IsolationForest is probabilistic
        and the test data is synthetic.
        """
        from app.services.detection import run_detection

        df = sample_df.drop(columns=["label"])
        events = run_detection(df, models=trained_models, pipeline=None)
        anomaly_count = sum(1 for e in events if e["is_anomaly"])
        assert anomaly_count > 0, "Expected at least some anomalies in sample data"
        assert anomaly_count < len(events), "Expected at least some normal events too"
