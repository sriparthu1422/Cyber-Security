"""
tests/test_api.py — Tests for FastAPI endpoints.

Tests:
- Health check endpoint
- API info endpoint
- Summary endpoint (with and without data)
- Analyze endpoint (valid and invalid input)
- CSV upload endpoint
- Event listing and filtering
- Event detail retrieval
- 404 for missing event
- Invalid request validation errors
- Model metrics endpoint
- Database persistence
"""
import io
import json

import pandas as pd
import pytest
from fastapi.testclient import TestClient


class TestHealthEndpoints:
    def test_health_returns_200(self, test_client):
        response = test_client.get("/health")
        assert response.status_code == 200

    def test_health_has_required_fields(self, test_client):
        response = test_client.get("/health")
        data = response.json()
        assert "status" in data
        assert "version" in data
        assert "database_ok" in data
        assert "model_loaded" in data
        assert "total_events" in data

    def test_health_database_ok_when_db_available(self, test_client):
        response = test_client.get("/health")
        assert response.json()["database_ok"] is True

    def test_api_info_returns_endpoints(self, test_client):
        response = test_client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "endpoints" in data
        assert "health" in data["endpoints"]


class TestSummaryEndpoint:
    def test_summary_returns_200(self, test_client):
        response = test_client.get("/api/v1/summary")
        assert response.status_code == 200

    def test_summary_has_correct_fields(self, test_client):
        response = test_client.get("/api/v1/summary")
        data = response.json()
        expected = [
            "total_events", "total_anomalies", "total_normal",
            "high_severity_count", "suspicious_count",
            "total_datasets_imported", "total_model_runs",
            "model_trained", "anomaly_rate_pct"
        ]
        for field in expected:
            assert field in data, f"Missing field: {field}"

    def test_summary_empty_database(self, test_client):
        response = test_client.get("/api/v1/summary")
        data = response.json()
        assert data["total_events"] == 0
        assert data["total_anomalies"] == 0
        assert data["anomaly_rate_pct"] == 0.0


class TestAnalyzeEndpoint:
    def test_analyze_single_event_returns_200(self, test_client, normal_event):
        response = test_client.post(
            "/api/v1/analyze",
            json={"events": [normal_event]}
        )
        assert response.status_code == 200

    def test_analyze_returns_correct_count(self, test_client, normal_event, anomalous_event):
        events = [normal_event, anomalous_event, normal_event]
        response = test_client.post("/api/v1/analyze", json={"events": events})
        data = response.json()
        assert data["total_analyzed"] == 3

    def test_analyze_persists_to_database(self, test_client, normal_event):
        """Events should be saved to DB after analysis."""
        # Check before
        before = test_client.get("/api/v1/summary").json()

        test_client.post("/api/v1/analyze", json={"events": [normal_event]})

        # Check after
        after = test_client.get("/api/v1/summary").json()
        assert after["total_events"] > before["total_events"]

    def test_analyze_empty_events_returns_422(self, test_client):
        response = test_client.post("/api/v1/analyze", json={"events": []})
        assert response.status_code == 422

    def test_analyze_invalid_protocol_returns_422(self, test_client):
        event = {
            "source_ip": "192.0.2.1",
            "protocol": "INVALID_PROTOCOL_XYZ",
            "failed_logins": 0,
        }
        response = test_client.post("/api/v1/analyze", json={"events": [event]})
        assert response.status_code == 422

    def test_analyze_too_many_events_returns_422(self, test_client, normal_event):
        events = [normal_event] * 1001  # Over the 1000 limit
        response = test_client.post("/api/v1/analyze", json={"events": events})
        assert response.status_code == 422

    def test_analyze_response_has_events(self, test_client, normal_event):
        response = test_client.post("/api/v1/analyze", json={"events": [normal_event]})
        data = response.json()
        assert "events" in data
        assert len(data["events"]) == 1
        event = data["events"][0]
        assert "is_anomaly" in event
        assert "severity" in event
        assert "alert_reason" in event

    def test_analyze_negative_failed_logins_returns_422(self, test_client):
        event = {"failed_logins": -5}  # Invalid: must be >= 0
        response = test_client.post("/api/v1/analyze", json={"events": [event]})
        assert response.status_code == 422

    def test_analyze_invalid_port_returns_422(self, test_client):
        event = {"port_number": 99999}  # Invalid: must be <= 65535
        response = test_client.post("/api/v1/analyze", json={"events": [event]})
        assert response.status_code == 422


class TestCSVAnalyzeEndpoint:
    def _make_csv_bytes(self, n=10) -> bytes:
        """Helper: create a small valid CSV in memory."""
        import numpy as np
        rng = np.random.default_rng(99)
        rows = []
        for _ in range(n):
            rows.append({
                "failed_logins": int(rng.integers(0, 10)),
                "bytes_in": float(rng.exponential(5000)),
                "bytes_out": float(rng.exponential(2000)),
                "connection_duration": float(rng.exponential(30)),
                "protocol": rng.choice(["TCP", "UDP", "HTTPS"]),
                "unusual_hour": bool(rng.random() > 0.8),
                "port_number": int(rng.choice([80, 443, 22])),
            })
        return pd.DataFrame(rows).to_csv(index=False).encode()

    def test_csv_upload_returns_200(self, test_client):
        csv_bytes = self._make_csv_bytes(20)
        response = test_client.post(
            "/api/v1/analyze/csv",
            files={"file": ("test_data.csv", io.BytesIO(csv_bytes), "text/csv")},
        )
        assert response.status_code == 200

    def test_csv_upload_returns_event_count(self, test_client):
        n = 15
        csv_bytes = self._make_csv_bytes(n)
        response = test_client.post(
            "/api/v1/analyze/csv",
            files={"file": ("test.csv", io.BytesIO(csv_bytes), "text/csv")},
        )
        data = response.json()
        assert data["total_analyzed"] == n

    def test_non_csv_file_returns_415(self, test_client):
        response = test_client.post(
            "/api/v1/analyze/csv",
            files={"file": ("data.txt", b"not a csv", "text/plain")},
        )
        assert response.status_code == 415

    def test_empty_file_returns_422(self, test_client):
        response = test_client.post(
            "/api/v1/analyze/csv",
            files={"file": ("empty.csv", b"", "text/csv")},
        )
        assert response.status_code == 422

    def test_csv_with_no_feature_columns_returns_422(self, test_client):
        bad_csv = b"col_a,col_b,col_c\n1,2,3\n4,5,6\n"
        response = test_client.post(
            "/api/v1/analyze/csv",
            files={"file": ("bad.csv", io.BytesIO(bad_csv), "text/csv")},
        )
        assert response.status_code == 422


class TestEventsEndpoint:
    def _seed_events(self, test_client, count=5):
        """Seed some events via the analyze endpoint."""
        import numpy as np
        rng = np.random.default_rng(123)
        events = []
        for _ in range(count):
            events.append({
                "failed_logins": int(rng.integers(0, 30)),
                "bytes_in": float(rng.exponential(5000)),
                "bytes_out": float(rng.exponential(2000)),
                "protocol": "TCP",
                "unusual_hour": bool(rng.random() > 0.8),
                "port_number": 443,
            })
        test_client.post("/api/v1/analyze", json={"events": events})

    def test_list_events_returns_200(self, test_client):
        response = test_client.get("/api/v1/events")
        assert response.status_code == 200

    def test_list_events_has_pagination(self, test_client):
        response = test_client.get("/api/v1/events")
        data = response.json()
        assert "total" in data
        assert "page" in data
        assert "per_page" in data
        assert "pages" in data
        assert "events" in data

    def test_list_events_filter_by_severity(self, test_client):
        self._seed_events(test_client, 10)
        response = test_client.get("/api/v1/events?severity=Normal")
        assert response.status_code == 200

    def test_invalid_severity_returns_422(self, test_client):
        response = test_client.get("/api/v1/events?severity=INVALID")
        assert response.status_code == 422

    def test_per_page_max_enforced(self, test_client):
        response = test_client.get("/api/v1/events?per_page=101")
        assert response.status_code == 422

    def test_event_detail_404_for_missing(self, test_client):
        response = test_client.get("/api/v1/events/999999")
        assert response.status_code == 404

    def test_event_detail_returns_full_record(self, test_client, normal_event):
        """End-to-end: analyze → persist → retrieve by ID."""
        # Analyze
        resp = test_client.post("/api/v1/analyze", json={"events": [normal_event]})
        event_id = resp.json()["events"][0]["id"]

        # Retrieve
        detail = test_client.get(f"/api/v1/events/{event_id}")
        assert detail.status_code == 200
        data = detail.json()
        assert data["id"] == event_id
        assert "alert_reason" in data
        assert "severity" in data


class TestModelMetricsEndpoint:
    def test_no_model_returns_404(self, test_client):
        response = test_client.get("/api/v1/model/metrics")
        assert response.status_code == 404

    def test_404_has_helpful_message(self, test_client):
        response = test_client.get("/api/v1/model/metrics")
        detail = response.json()["detail"]
        assert "train" in detail.lower() or "model" in detail.lower()
