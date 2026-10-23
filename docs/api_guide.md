# API Guide — CyberSec AI Threat Detection

## Base URL
```
http://localhost:8000
```

## Authentication
None required — this is a local development application.

---

## Endpoints

### 1. GET /health

Returns application health status.

**Response 200:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "model_loaded": true,
  "database_ok": true,
  "total_events": 156
}
```

**Fields:**
- `status`: "healthy" | "degraded"
- `model_loaded`: true if model artifacts exist on disk
- `database_ok`: true if database is reachable
- `total_events`: count of all detection events in DB

---

### 2. GET /

Returns API information and list of all endpoints.

**Response 200:**
```json
{
  "name": "CyberSec AI - Threat Detection",
  "version": "1.0.0",
  "docs": "/docs",
  "endpoints": {
    "health": "GET /health",
    "summary": "GET /api/v1/summary",
    ...
  }
}
```

---

### 3. GET /api/v1/summary

Returns dashboard KPI statistics computed from actual database records.

**Response 200:**
```json
{
  "total_events": 1006,
  "total_anomalies": 120,
  "total_normal": 886,
  "high_severity_count": 42,
  "suspicious_count": 78,
  "total_datasets_imported": 3,
  "total_model_runs": 2,
  "latest_model_run_at": "2026-10-15T10:13:27",
  "model_trained": true,
  "anomaly_rate_pct": 11.93
}
```

---

### 4. POST /api/v1/analyze

Analyze one or more events via JSON. Returns predictions for each event.

**Request:**
```json
{
  "events": [
    {
      "source_ip": "192.0.2.10",
      "dest_ip": "198.51.100.5",
      "protocol": "SSH",
      "failed_logins": 25,
      "bytes_in": 1024.0,
      "bytes_out": 512.0,
      "connection_duration": 45.5,
      "unusual_hour": true,
      "port_number": 22
    }
  ]
}
```

**Field validations:**
- `protocol`: must be one of TCP, UDP, ICMP, HTTP, HTTPS, FTP, SSH, DNS, OTHER
- `failed_logins`: integer ≥ 0, ≤ 1000
- `port_number`: integer ≥ 0, ≤ 65535
- `events`: 1 to 1000 items per request

**Response 200:**
```json
{
  "total_analyzed": 1,
  "anomalies_detected": 1,
  "normal_events": 0,
  "high_severity": 1,
  "suspicious_events": 0,
  "model_used": "both",
  "warning": null,
  "events": [
    {
      "id": 42,
      "event_id": "a1b2c3d4-e5f6-...",
      "timestamp": "2026-10-15T11:15:00Z",
      "source_ip": "192.0.2.10",
      "dest_ip": "198.51.100.5",
      "protocol": "SSH",
      "failed_logins": 25,
      "bytes_in": 1024.0,
      "bytes_out": 512.0,
      "connection_duration": 45.5,
      "unusual_hour": true,
      "port_number": 22,
      "is_anomaly": true,
      "anomaly_score": -0.21,
      "rf_probability": 0.95,
      "severity": "High",
      "prediction_source": "both",
      "alert_reason": "IsolationForest flagged (score=-0.2100) | High failed logins: 25 | Outside business hours | Sensitive port: 22",
      "dataset_import_id": null,
      "model_run_id": null
    }
  ]
}
```

**Error responses:**
- `422` — Validation error (invalid protocol, negative failed_logins, etc.)
- `500` — Internal processing error

**Note on `anomaly_score`:** This is a raw IsolationForest `decision_function()` output,
NOT a probability. More negative = more anomalous. Do not interpret as "% chance of attack".

---

### 5. POST /api/v1/analyze/csv

Upload and analyze a CSV file. Accepts `multipart/form-data`.

**Request:** `multipart/form-data` with field `file` containing a `.csv` file.

```bash
# curl example
curl -X POST http://localhost:8000/api/v1/analyze/csv \
  -F "file=@data/sample/network_events.csv"
```

**CSV format:** Must include at least some of these columns:
```
failed_logins, bytes_in, bytes_out, connection_duration,
protocol, unusual_hour, port_number
```
Optional: `source_ip`, `dest_ip`, `label` (0=normal, 1=anomaly)

Missing columns are imputed automatically with sensible defaults.

**Limits:**
- Maximum file size: 10 MB
- Accepted extension: `.csv` only

**Response:** Same as `/api/v1/analyze` (first 50 events shown in response body)

**Error responses:**
- `415` — Wrong file type (not .csv)
- `422` — Empty file, or no usable feature columns found
- `413` — File too large (> 10 MB)

---

### 6. GET /api/v1/events

List detection events with pagination and filtering.

**Query parameters:**
- `page` (integer, default=1): Page number
- `per_page` (integer, 1-100, default=20): Events per page
- `severity` (string, optional): Filter by "Normal" | "Suspicious" | "High"
- `is_anomaly` (boolean, optional): Filter by anomaly status
- `dataset_import_id` (integer, optional): Filter by import batch

**Example:**
```
GET /api/v1/events?page=1&per_page=10&severity=High
```

**Response 200:**
```json
{
  "total": 42,
  "page": 1,
  "per_page": 10,
  "pages": 5,
  "events": [ ... ]
}
```

**Error responses:**
- `422` — Invalid severity value or per_page > 100

---

### 7. GET /api/v1/events/{event_id}

Retrieve one detection event by its integer ID.

**Example:**
```
GET /api/v1/events/42
```

**Response 200:** Full event object (same schema as events in list response)

**Error responses:**
- `404` — Event not found

---

### 8. GET /api/v1/model/metrics

Get evaluation metrics from the most recent successful model training run.

**Response 200:**
```json
{
  "run_id": "ce3c60be-4853-40ba-8ac0-338b752f2d75",
  "model_type": "both",
  "trained_at": "2026-10-15T11:13:27Z",
  "training_rows": 800,
  "test_rows": 200,
  "has_labels": true,
  "contamination": 0.1,
  "n_estimators": 100,
  "precision": 1.0,
  "recall": 1.0,
  "f1_score": 1.0,
  "accuracy": 1.0,
  "if_anomaly_count": 99,
  "if_normal_count": 901,
  "artifact_path": "artifacts/isolation_forest.joblib",
  "status": "completed",
  "notes": "Trained on network_events.csv. 800 training rows. F1=1.0000..."
}
```

**Notes:**
- `precision`, `recall`, `f1_score`, `accuracy` are null when no labels were available
- Metrics reflect performance on **synthetic** test data only
- F1=1.0 is expected for synthetic data with very clear patterns

**Error responses:**
- `404` — No completed model training run found

---

### 9. POST /api/v1/model/train

Trigger model training via API (uses sample dataset).

**Prerequisites:** Run `python scripts/generate_sample_data.py` first.

**Response 202:**
```json
{
  "status": "completed",
  "run_id": "uuid...",
  "model_type": "both",
  "training_rows": 800,
  "metrics": {
    "precision": 1.0,
    "recall": 1.0,
    "f1_score": 1.0
  },
  "warnings": [],
  "message": "Model trained successfully."
}
```

**Error responses:**
- `404` — Sample dataset not found
- `500` — Training failed

---

## Swagger UI

The full interactive API documentation is available at:
```
http://localhost:8000/docs
```

Use the Swagger UI to:
1. Explore all endpoints
2. Try requests with the "Try it out" button
3. See request/response schemas
4. Test CSV file upload
