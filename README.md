# AI-Based Cybersecurity Threat Identification in Financial Institutions

> **Using Machine Learning — IsolationForest + RandomForest — to detect anomalous network and authentication events**

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-green)](https://fastapi.tiangolo.com)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.5%2B-orange)](https://scikit-learn.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.40%2B-red)](https://streamlit.io)

---

## ⚠️ Data Disclaimer

All data in this project is **entirely synthetic**. It does NOT represent real financial
institution network traffic, real attack patterns, or any real organization's data.
The synthetic dataset was generated specifically for portfolio demonstration purposes.
Model performance on this dataset does not reflect real-world accuracy.

---

## Project Overview

This is a complete, locally runnable cybersecurity threat detection system built as a
technical portfolio project. It demonstrates a real end-to-end machine learning pipeline:

```
CSV data → Validation → Preprocessing → ML Detection → Alerts → SQLite → FastAPI → Streamlit
```

### Problem Statement
Financial institutions face increasing cybersecurity threats including brute-force attacks,
data exfiltration, and after-hours unauthorized access. Traditional rule-based systems
have high false-positive rates. Machine learning can learn normal baseline patterns and
flag deviations more intelligently.

### Implemented Features
- ✅ Synthetic network/authentication event dataset (1000 rows, labeled)
- ✅ scikit-learn preprocessing Pipeline (imputation → scaling → encoding)
- ✅ IsolationForest anomaly detection (unsupervised — no labels needed)
- ✅ RandomForest classification (supervised — when labels available)
- ✅ Rule-based severity assignment (Normal / Suspicious / High)
- ✅ Human-readable alert explanations
- ✅ FastAPI REST backend with Swagger UI
- ✅ SQLite persistence (DetectionEvent, DatasetImport, ModelRun tables)
- ✅ Streamlit dashboard with 5 interactive pages
- ✅ CSV upload and batch analysis
- ✅ 75+ pytest tests (preprocessing, training, detection, API)
- ✅ Complete documentation (architecture, database, API guide, demo script)

---

## Architecture

```
CSV Upload / API JSON Events
        │
        ▼
┌─────────────────────┐
│  Ingestion Layer    │  ← File validation, column normalization
│  ingestion.py       │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Preprocessing      │  ← Imputation → StandardScaler → OneHotEncoder
│  preprocessing.py   │     scikit-learn Pipeline (no data leakage)
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  ML Detection       │  ← IsolationForest (always)
│  detection.py       │     RandomForest (when labels exist)
│                     │     + Rule-based severity assignment
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  SQLite Database    │  ← DetectionEvent, DatasetImport, ModelRun
│  database.py        │
└────────┬────────────┘
         │
    ┌────┴────┐
    ▼         ▼
FastAPI    Streamlit
port 8000  port 8501
```

See [docs/architecture.md](docs/architecture.md) for the full diagram.

---

## 🔑 No API Keys Required

This project uses **no paid services and no external APIs**:

| Setting | What it is | What to put |
|---------|------------|-------------|
| `SECRET_KEY` | Flask session signing (old app) | Any random string, e.g. `"my-local-key"` |
| `DATABASE_URL` | SQLite connection | Leave as `sqlite:///./cybersec_ai.db` |
| Everything else | Not used | Leave as default |

**You do not need:** OpenAI, VirusTotal, Splunk, or any paid API key.

---

## Technology Stack

| Component | Technology | Version |
|-----------|------------|---------|
| Language | Python | 3.11+ (tested on 3.14) |
| ML | scikit-learn | 1.5+ |
| Data | Pandas, NumPy | 2.2+, 2.0+ |
| Backend | FastAPI + Uvicorn | 0.115+ |
| Database | SQLite + SQLAlchemy | 2.0+ |
| Validation | Pydantic v2 | 2.9+ |
| Dashboard | Streamlit + Plotly | 1.40+, 5.24+ |
| Testing | Pytest + httpx | 8.3+ |
| Serialization | Joblib | 1.4+ |

---

## Folder Structure

```
Cyber-Security/
│
├── app/                          ← New FastAPI application
│   ├── __init__.py
│   ├── config.py                 ← Pydantic Settings (reads from .env)
│   ├── database.py               ← SQLAlchemy engine, session, init_db()
│   ├── main.py                   ← FastAPI app entry point
│   ├── models/
│   │   ├── detection_event.py    ← DetectionEvent table
│   │   ├── dataset_import.py     ← DatasetImport table
│   │   └── model_run.py          ← ModelRun table
│   ├── schemas/
│   │   └── event_schemas.py      ← Pydantic request/response schemas
│   ├── services/
│   │   ├── preprocessing.py      ← scikit-learn Pipeline
│   │   ├── training.py           ← IsolationForest + RandomForest training
│   │   ├── detection.py          ← Run predictions + assign severity
│   │   └── ingestion.py          ← CSV validation and loading
│   ├── api/routes/
│   │   ├── health.py             ← GET /health, GET /
│   │   ├── events.py             ← GET /events, GET /summary
│   │   ├── analyze.py            ← POST /analyze, POST /analyze/csv
│   │   └── model.py              ← GET /model/metrics, POST /model/train
│   └── dashboard/
│       └── streamlit_app.py      ← Interactive Streamlit dashboard
│
├── scripts/
│   ├── generate_sample_data.py   ← Create synthetic dataset
│   ├── initialize_db.py          ← Create tables + seed demo data
│   ├── train_model.py            ← Train and save models
│   └── analyze_csv.py            ← Batch CSV analysis CLI
│
├── data/sample/
│   └── network_events.csv        ← Generated synthetic dataset (1000 rows)
│
├── artifacts/                    ← Saved model files (.joblib)
│   ├── isolation_forest.joblib
│   ├── random_forest.joblib
│   └── preprocessing_pipeline.joblib
│
├── tests/
│   ├── conftest.py               ← Shared fixtures (isolated test DB)
│   ├── test_preprocessing.py     ← Pipeline and validation tests
│   ├── test_training.py          ← Model training and artifact tests
│   ├── test_detection.py         ← Severity rules and detection tests
│   └── test_api.py               ← FastAPI endpoint tests
│
├── docs/
│   ├── architecture.md           ← System design and data flow
│   ├── database_design.md        ← Schema, ER diagram, design decisions
│   ├── api_guide.md              ← Endpoint reference with examples
│   ├── bug_fix_log.md            ← Bugs discovered and fixed
│   └── demo_script.md            ← 10-15 min recording plan
│
├── requirements.txt
├── .env.example                  ← Copy to .env (no real secrets needed)
├── pytest.ini
└── README.md
```

Original Flask code (`app.py`, `routes.py`, `models.py`, etc.) is preserved in the root.

---

## Prerequisites

- Python 3.11 or newer (tested on 3.14.3)
- Windows PowerShell (instructions below)
- No external services, APIs, or cloud accounts required

---

## Setup (Windows PowerShell)

### Step 1 — Create a virtual environment

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

If you get an ExecutionPolicy error:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Step 2 — Install dependencies

```powershell
pip install -r requirements.txt
```

This installs: FastAPI, scikit-learn, Pandas, SQLAlchemy, Streamlit, Plotly, Pytest, etc.

### Step 3 — Configure environment (optional)

```powershell
copy .env.example .env
```

The defaults work out of the box. No API keys or secrets needed.
You can optionally change `SECRET_KEY` to any random string of your choice.

---

## Running the Application

### Step 1 — Generate the synthetic dataset

```powershell
python scripts/generate_sample_data.py
```

Output: `data/sample/network_events.csv` (1000 synthetic events, 120 anomalies)

### Step 2 — Initialize the database

```powershell
python scripts/initialize_db.py
```

Creates `cybersec_ai.db` with all tables and seeds 6 demo events.

### Step 3 — Train the ML models

```powershell
python scripts/train_model.py
```

Trains IsolationForest + RandomForest. Saves `.joblib` files to `artifacts/`.
Shows F1, precision, recall on the test split.

### Step 4 — Start the FastAPI backend

```powershell
uvicorn app.main:app --reload --port 8000
```

- API: http://localhost:8000
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### Step 5 — Start the Streamlit dashboard (new terminal)

```powershell
streamlit run app/dashboard/streamlit_app.py
```

- Dashboard: http://localhost:8501

### Step 6 — Run tests

```powershell
python -m pytest tests/ -v
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | App health check |
| GET | `/` | API info and endpoint list |
| GET | `/api/v1/summary` | Dashboard KPIs (from DB) |
| POST | `/api/v1/analyze` | Analyze 1-1000 JSON events |
| POST | `/api/v1/analyze/csv` | Upload and analyze CSV |
| GET | `/api/v1/events` | List events (paginated, filterable) |
| GET | `/api/v1/events/{id}` | Get one event detail |
| GET | `/api/v1/model/metrics` | Latest model evaluation metrics |
| POST | `/api/v1/model/train` | Trigger training via API |

Full examples in [docs/api_guide.md](docs/api_guide.md).

---

## Database Schema

Three tables:
- **`detection_events`** — One row per analyzed event (features, prediction, severity, explanation)
- **`dataset_imports`** — One row per CSV upload session (audit trail)
- **`model_runs`** — One row per training session (metrics, artifact path)

See [docs/database_design.md](docs/database_design.md) for full schema with types and relationships.

---

## ML Model Approach

### IsolationForest (Unsupervised)
- Trained on ALL data — no labels needed
- Randomly partitions feature space; anomalies isolated in fewer steps
- Outputs raw scores: negative = more anomalous (NOT a probability)
- Contamination parameter: 0.1 (expect ~10% anomalies)

### RandomForest (Supervised)
- Trained only when `label` column present in dataset
- 100 trees with balanced class weights (handles class imbalance)
- Outputs calibrated probabilities (0.0 to 1.0)
- Takes precedence over IsolationForest when available

### Severity Assignment (Rule-Based)
Applied on top of model predictions:
```
RF probability ≥ 0.70 → "High"
RF probability ≥ 0.50 → "Suspicious"
RF probability < 0.50  → "Normal"

— or, if no RF —

IF score < -0.15       → "High"
IF score < 0.0         → "Suspicious"
IF score ≥ 0.0         → "Normal"
```

---

## Test Results

Run: `python -m pytest tests/ -v`

| Test File | Tests | Coverage |
|-----------|-------|----------|
| `test_preprocessing.py` | Validation, pipeline fit/transform, split | 11 tests |
| `test_training.py` | IF training, RF training, artifact save/load | 10 tests |
| `test_detection.py` | Severity rules, alert reasons, model integration | 13 tests |
| `test_api.py` | All endpoints, validation errors, persistence | 20+ tests |

---

## Batch CSV Analysis (CLI)

```powershell
# Analyze a CSV and print results
python scripts/analyze_csv.py --input data/sample/network_events.csv

# Save results to CSV
python scripts/analyze_csv.py --input my_data.csv --output results.csv

# Don't persist to database
python scripts/analyze_csv.py --input my_data.csv --no-persist
```

---

## Known Limitations

1. **Synthetic data only** — F1=1.0 reflects learned synthetic patterns, not real-world accuracy
2. **Anomaly scores are NOT probabilities** — IsolationForest scores are relative measures
3. **Alert reasons are rule-based** — Not direct model explanations (no SHAP values)
4. **Single-server SQLite** — Not suitable for distributed/production use
5. **No authentication** — The new FastAPI app has no user login (the old Flask app does)
6. **Batch only** — No real-time streaming; events are analyzed in batches

---

## Troubleshooting

**"No such table" error:**
```powershell
python scripts/initialize_db.py
```

**"No trained model found":**
```powershell
python scripts/generate_sample_data.py
python scripts/train_model.py
```

**Cannot connect to API (dashboard shows error):**
Make sure the backend is running:
```powershell
uvicorn app.main:app --reload --port 8000
```

**PowerShell ExecutionPolicy error:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**"Pandas not found" or import errors:**
```powershell
pip install -r requirements.txt
```

---

## Future Improvements

- SHAP values for true model explainability
- Real-time streaming analysis (WebSocket or Kafka)
- Authentication and multi-user support in FastAPI
- Feedback loop for analyst-confirmed alerts (retraining)
- Federated learning for privacy-preserving cross-institution training
- Graph Neural Networks for relationship-based threat detection
- Docker containerization for easier deployment

---

## Project Background

This project transforms an existing Flask skeleton (with placeholder ML modules) into
a complete, working application. The original Flask app is preserved in the root directory.
The new FastAPI application lives in `app/` and implements genuine ML pipelines where the
original code had only random number generators and commented-out imports.

See [docs/demo_script.md](docs/demo_script.md) for a 10-15 minute recording plan
with interview preparation notes.
