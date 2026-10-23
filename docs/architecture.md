# Architecture: AI-Based Cybersecurity Threat Detection

## System Overview

This application is a locally runnable cybersecurity threat detection system for financial institutions.  
It uses **machine learning** (IsolationForest + RandomForest) to detect anomalous network/authentication events.  
All data in the demo is **synthetic** — no real financial institution data is used or required.

---

## Data Flow Diagram

```
                    ┌──────────────────────────────────────┐
                    │           USER INPUTS                │
                    │                                      │
                    │  CSV Upload  │  API JSON  │  Sample  │
                    └──────┬───────┴──────┬─────┴────┬─────┘
                           │              │           │
                           ▼              ▼           ▼
                    ┌─────────────────────────────────────┐
                    │     INGESTION LAYER                 │
                    │   app/services/ingestion.py         │
                    │                                     │
                    │  • File type validation (.csv only) │
                    │  • Size check (max 10 MB)           │
                    │  • Column name normalization        │
                    │  • Empty/malformed row handling     │
                    └──────────────────┬──────────────────┘
                                       │
                                       ▼
                    ┌─────────────────────────────────────┐
                    │     PREPROCESSING PIPELINE          │
                    │   app/services/preprocessing.py     │
                    │                                     │
                    │  • Missing value imputation (median)│
                    │  • Numerical scaling (StandardScaler│
                    │  • Categorical encoding (OneHotEnc) │
                    │  • Boolean → 0/1 integer            │
                    │  • scikit-learn Pipeline (no leak)  │
                    └──────────────────┬──────────────────┘
                                       │
                                       ▼
                    ┌─────────────────────────────────────┐
                    │     ML DETECTION LAYER              │
                    │   app/services/detection.py         │
                    │                                     │
                    │  ┌─────────────┐ ┌───────────────┐ │
                    │  │ Isolation   │ │  RandomForest  │ │
                    │  │ Forest      │ │  (if labels    │ │
                    │  │ (always)    │ │   exist)       │ │
                    │  └──────┬──────┘ └───────┬───────┘ │
                    │         │                 │          │
                    │         └────────┬────────┘          │
                    │                  ▼                   │
                    │         SEVERITY RULES               │
                    │   High / Suspicious / Normal         │
                    └──────────────────┬──────────────────┘
                                       │
                                       ▼
                    ┌─────────────────────────────────────┐
                    │     ALERT EXPLANATION LAYER         │
                    │   app/services/detection.py         │
                    │                                     │
                    │  Rule-based plain-English reasons   │
                    │  (separate from model predictions)  │
                    └──────────────────┬──────────────────┘
                                       │
                                       ▼
                    ┌─────────────────────────────────────┐
                    │     PERSISTENCE LAYER               │
                    │   app/database.py + models/         │
                    │                                     │
                    │  SQLite Database (cybersec_ai.db)   │
                    │  • DetectionEvent                   │
                    │  • DatasetImport                    │
                    │  • ModelRun                         │
                    └──────────────────┬──────────────────┘
                                       │
                             ┌─────────┴─────────┐
                             │                   │
                             ▼                   ▼
              ┌──────────────────────┐  ┌────────────────────┐
              │   FastAPI REST API   │  │  Streamlit         │
              │   app/main.py        │  │  Dashboard         │
              │   port 8000          │  │  port 8501         │
              │                      │  │                    │
              │  GET  /health        │  │  Overview KPIs     │
              │  POST /analyze       │  │  Upload CSV        │
              │  POST /analyze/csv   │  │  Event Table       │
              │  GET  /events        │  │  Model Metrics     │
              │  GET  /summary       │  │  API Docs          │
              │  GET  /model/metrics │  └────────────────────┘
              └──────────────────────┘
```

---

## Component Descriptions

### 1. Ingestion Layer (`app/services/ingestion.py`)
Validates and loads CSV files. Enforces:
- Extension check (.csv only)
- File size limit (10 MB default)
- Column normalization (lowercase, underscores)
- Graceful handling of malformed rows (skipped with warning)

### 2. Preprocessing Pipeline (`app/services/preprocessing.py`)
A scikit-learn `Pipeline` with a `ColumnTransformer`:
- **Numeric** (failed_logins, bytes_in, bytes_out, connection_duration, port_number): median imputation → StandardScaler
- **Categorical** (protocol): most-frequent imputation → OneHotEncoder
- **Boolean** (unusual_hour): constant-0 imputation → kept as int

The pipeline is **fit only on training data**, then applied to inference data without refitting. This prevents data leakage.

### 3. ML Detection Layer (`app/services/detection.py`)
Two models running in sequence:

**IsolationForest** (always active):
- Unsupervised algorithm — no labels needed
- Randomly isolates data points; anomalies require fewer steps
- Returns raw scores (not probabilities): negative = more anomalous
- Threshold: score < -0.15 → "High", score < 0.0 → "Suspicious"

**RandomForest** (when label column exists):
- Supervised classifier trained on labeled data
- Returns calibrated class probabilities (0.0–1.0)
- Takes precedence over IsolationForest when available
- Threshold: prob ≥ 0.70 → "High", prob ≥ 0.50 → "Suspicious"

### 4. Severity Assignment (Rule-Based Layer)
Documented thresholds applied ON TOP of model predictions:
```
IF rf_probability available:
    ≥ 0.70 → "High"
    ≥ 0.50 → "Suspicious"
    < 0.50 → "Normal"
ELSE (IsolationForest only):
    is_anomaly AND score < -0.15 → "High"
    is_anomaly AND score ≥ -0.15 → "Suspicious"
    not is_anomaly               → "Normal"
```

### 5. Database Layer (`app/database.py`)
SQLite database via SQLAlchemy ORM. Three tables:
- `DetectionEvent` — One row per analyzed event
- `DatasetImport` — One row per CSV upload session
- `ModelRun` — One row per training session

### 6. FastAPI Backend (`app/main.py`)
REST API with Swagger UI at `/docs`. Handles validation, routing, and error responses.

### 7. Streamlit Dashboard (`app/dashboard/streamlit_app.py`)
Interactive web UI with 5 pages. Calls the FastAPI backend for all data.

---

## Security Decisions
- No credentials, API keys, or secrets committed to the repository
- CSV uploads limited to 10 MB; only .csv accepted
- No arbitrary code execution from uploaded files
- Parameterized database queries via SQLAlchemy ORM
- Model artifacts use joblib (not pickle directly) — safe for local use

## Limitations
- All demo data is synthetic; real-world performance unknown
- IsolationForest scores are NOT calibrated probabilities
- No real-time streaming; batch analysis only
- No user authentication in the new FastAPI app
- Single-server SQLite; not suitable for distributed production use
