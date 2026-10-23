# Demo Script: 10-15 Minute Technical Walkthrough

## Recording Plan for Portfolio Demonstration

**Project:** AI-Based Cybersecurity Threat Identification in Financial Institutions  
**Tech stack:** Python, FastAPI, SQLite, scikit-learn, Streamlit  
**Total time:** 10–15 minutes

---

## SEGMENT 1 — Project Purpose (1–2 minutes)

**What to say:**
> "This project builds a locally runnable cybersecurity threat detection system
> for financial institutions. It uses machine learning — specifically IsolationForest
> for unsupervised anomaly detection and RandomForest for supervised classification —
> to identify suspicious network and authentication events.
>
> Everything runs locally. No cloud APIs, no paid services, no real bank data.
> The demo dataset is entirely synthetic and clearly labeled as such.
>
> The system has three main components: a FastAPI backend that exposes REST endpoints,
> a SQLite database that persists every detection result, and a Streamlit dashboard
> for visualization and interaction."

**Show:** The project folder structure in your file explorer.

---

## SEGMENT 2 — Repository Structure (1–2 minutes)

Navigate the repo and point to:
```
app/
  config.py       ← Settings (no hardcoded secrets)
  database.py     ← SQLAlchemy setup
  models/         ← DetectionEvent, DatasetImport, ModelRun
  services/
    preprocessing.py  ← scikit-learn Pipeline
    training.py       ← IsolationForest + RandomForest
    detection.py      ← Runs predictions + severity rules
    ingestion.py      ← CSV validation and loading
  api/routes/     ← FastAPI endpoints
  dashboard/      ← Streamlit dashboard
scripts/          ← CLI: generate data, train, analyze
tests/            ← pytest test suite
data/sample/      ← Synthetic CSV dataset
artifacts/        ← Saved model files (joblib)
docs/             ← Architecture, DB design, API guide
```

**What to say:**
> "The code is organized into clear layers: services handle business logic,
> models define the database schema, and routes handle HTTP concerns.
> The existing Flask code in the root is preserved — the new FastAPI app
> lives in the `app/` directory alongside it."

---

## SEGMENT 3 — Key Python Function Explained (2–3 minutes)

Open `app/services/detection.py` and show `assign_severity()`.

```python
def assign_severity(
    is_anomaly: bool,
    anomaly_score: Optional[float],
    rf_probability: Optional[float] = None,
) -> str:
```

**Walk through line by line:**

1. "This function takes three inputs: the IsolationForest anomaly flag, the raw IF score, and optionally a RandomForest probability."

2. "First, it checks if we have a RandomForest prediction — supervised models are more reliable when we have labels, so we use RF first."

3. "RF probability ≥ 0.70 → High. Between 0.50 and 0.70 → Suspicious. Below 0.50 → Normal."

4. "If no RF model, we fall back to IsolationForest. The score threshold -0.15 was chosen based on the IsolationForest decision boundary — it's documented in the code."

5. "Notice this is RULE-BASED logic applied ON TOP of the model output. It's not the model itself deciding severity — that's an important distinction."

6. **Mention the bug fix:** "I actually found a bug here during development — the original threshold comparison used `<=` instead of `<`, which caused borderline events with score=0.0 to be wrongly classified as High severity. I fixed it and added a regression test. It's documented in docs/bug_fix_log.md."

---

## SEGMENT 4 — FastAPI Swagger UI (2 minutes)

**Open browser to: http://localhost:8000/docs**

1. Show the automatically generated Swagger UI
2. Click **GET /health** → Try it out → Execute
   - Show the response: `database_ok: true, model_loaded: true`
3. Click **POST /api/v1/analyze** → Try it out → paste this body:
```json
{
  "events": [
    {
      "protocol": "TCP",
      "failed_logins": 45,
      "bytes_out": 3000000.0,
      "unusual_hour": true,
      "port_number": 4444
    }
  ]
}
```
4. Execute → Show response with `severity: "High"` and `alert_reason`

**What to say:**
> "The Swagger UI is auto-generated from the FastAPI code and Pydantic schemas.
> Every field has validation — try submitting a negative failed_logins or an
> invalid protocol like 'BADPROTO' and it returns a 422 with a clear error message."

---

## SEGMENT 5 — Database and Persisted Records (1–2 minutes)

**Open a terminal:**
```powershell
python -c "
from app.database import get_db_session
from app.models.detection_event import DetectionEvent
with get_db_session() as db:
    events = db.query(DetectionEvent).order_by(DetectionEvent.id.desc()).limit(3).all()
    for e in events:
        print(f'ID={e.id} | {e.severity} | score={e.anomaly_score:.4f} | {e.alert_reason[:60]}')
"
```

**What to say:**
> "Every event analyzed through the API is persisted to SQLite.
> The DetectionEvent table stores the raw features, the model prediction,
> the anomaly score, and the explanation — creating a complete audit trail.
> Restarting the application doesn't lose any data."

Also show the ModelRun record:
```powershell
python -c "
from app.database import get_db_session
from app.models.model_run import ModelRun
with get_db_session() as db:
    run = db.query(ModelRun).filter(ModelRun.status=='completed').first()
    print(f'F1={run.f1_score} | Precision={run.precision} | Recall={run.recall}')
    print(f'Trained: {run.trained_at} | Rows: {run.training_rows}')
"
```

---

## SEGMENT 6 — Streamlit Dashboard (2–3 minutes)

**Open browser to: http://localhost:8501**

Walk through:
1. **Overview page:** KPI cards (all real database values), pie chart, bar chart
2. **Upload page:** Drag and drop a CSV → show analysis results populate
3. **Events page:** Filter by "High" severity → show filtered table
4. **Event detail:** Enter event ID → show full prediction + explanation
5. **Model Training page:** Show F1 gauge chart and metrics

**What to say about metrics:**
> "The RandomForest shows F1=1.0 on this synthetic dataset — that's actually expected
> because the synthetic data has very clear, distinct patterns between normal and anomalous.
> This does NOT mean the model would perform this well on real financial network traffic.
> In production, you'd evaluate on real labeled data and expect significantly lower numbers.
> The documentation explicitly states this."

---

## SEGMENT 7 — Bug Fix Walkthrough (1–2 minutes)

Open `docs/bug_fix_log.md`:
> "During development, I discovered that events with anomaly score exactly 0.0
> were being wrongly classified as High severity instead of Suspicious.
> The root cause was using `<=` instead of `<` in the threshold comparison.
> I fixed it, wrote two regression tests, and documented it in the bug fix log."

Open `tests/test_detection.py` and show:
```python
def test_borderline_anomaly_gets_suspicious(self):
    result = assign_severity(is_anomaly=True, anomaly_score=-0.05)
    assert result == "Suspicious"

def test_strong_anomaly_gets_high(self):
    result = assign_severity(is_anomaly=True, anomaly_score=-0.20)
    assert result == "High"
```

Run the tests:
```powershell
python -m pytest tests/test_detection.py::TestSeverityAssignment -v
```

---

## SEGMENT 8 — Test Suite Results (1 minute)

```powershell
python -m pytest tests/ -v
```

Show the test results passing. Mention:
- `test_preprocessing.py` — Pipeline fit/transform, no leakage
- `test_training.py` — Model save/load, metrics computation
- `test_detection.py` — Severity rules, alert reasons
- `test_api.py` — All endpoints, validation, persistence

---

## SEGMENT 9 — Limitations and Honest Assessment (1 minute)

**What to say:**
> "A few important limitations to be honest about:
> 
> First, the dataset is entirely synthetic. F1=1.0 means the model learned
> the synthetic patterns perfectly — not that it would work on real attacks.
>
> Second, IsolationForest scores are relative measures, not probabilities.
> A score of -0.2 doesn't mean '20% chance of attack'.
>
> Third, the alert reasons are rule-based explanations, not direct model interpretations.
> For true model explainability, you'd use SHAP values.
>
> Fourth, this runs as a single local process. Production would need authentication,
> rate limiting, encrypted storage, and distributed infrastructure."

---

## Interview Questions You Might Be Asked

**Q: Why IsolationForest?**
> "IsolationForest works well for unsupervised anomaly detection because it doesn't need
> labeled attack data. It randomly partitions the feature space — anomalies are isolated
> in fewer steps because they're in sparse regions."

**Q: What does contamination=0.1 mean?**
> "It tells IsolationForest that approximately 10% of the training data is anomalous.
> This sets the decision threshold — if you set it too high, you get too many false positives.
> Too low, you miss real anomalies."

**Q: Why SQLite instead of PostgreSQL?**
> "SQLite is perfect for a local portfolio demo — zero configuration, single file,
> works everywhere. For production, you'd switch to PostgreSQL and change just the
> DATABASE_URL connection string. SQLAlchemy makes this easy."

**Q: Why Pydantic for validation?**
> "Pydantic v2 gives automatic validation, clear error messages, and auto-generated
> API documentation for free. When someone sends `protocol: 'BADVALUE'`, they get
> a descriptive 422 error instead of a cryptic 500."

**Q: What's the difference between anomaly_score and rf_probability?**
> "anomaly_score is a raw IsolationForest output — a relative measure not a probability.
> rf_probability is from RandomForest and is a genuine probability (0-1) since it was
> trained on labeled data. That's why RF takes precedence when available."
