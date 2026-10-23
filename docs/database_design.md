# Database Design

## Overview

The application uses **SQLite** with **SQLAlchemy ORM**.  
The database file is `cybersec_ai.db` in the project root directory.  
Tables are created automatically on first run via `init_db()`.

---

## Entity-Relationship Diagram

```
DatasetImport                    ModelRun
─────────────                    ────────
id (PK)                          id (PK)
import_id (UUID)                 run_id (UUID)
filename                         model_type
source_type                      training_rows
row_count                        test_rows
anomaly_count                    has_labels
error_count                      random_seed
has_labels                       contamination
status                           n_estimators
error_message                    precision
notes                            recall
imported_at                      f1_score
completed_at                     accuracy
                                 if_anomaly_count
        │                        if_normal_count
        │                        artifact_path
        │                        status
        │                        error_message    
        │                        trained_at       ─────────┐
        │                        completed_at              │
        │                        notes                     │
        │                                                  │
        └──────────────────────────────────────────────────┤
                                                           │
                            DetectionEvent                 │
                            ──────────────                 │
                            id (PK)                        │
                            event_id (UUID)                │
                            timestamp                      │
                            source_ip                      │
                            dest_ip                        │
                            protocol                       │
                            failed_logins                  │
                            bytes_in                       │
                            bytes_out                      │
                            connection_duration            │
                            unusual_hour                   │
                            port_number                    │
                            raw_features_json              │
                            is_anomaly                     │
                            anomaly_score                  │
                            rf_probability                 │
                            severity                       │
                            prediction_source              │
                            alert_reason                   │
                            dataset_import_id (FK) ────────┘
                            model_run_id (FK) ─────────────┘
```

---

## Table Definitions

### `detection_events`
Primary output table. One row per analyzed event.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | INTEGER | NOT NULL | Auto-increment primary key |
| `event_id` | VARCHAR(36) | NOT NULL | UUID (for external references) |
| `timestamp` | DATETIME | NOT NULL | When the event was analyzed (UTC) |
| `source_ip` | VARCHAR(45) | YES | Source IP address |
| `dest_ip` | VARCHAR(45) | YES | Destination IP address |
| `protocol` | VARCHAR(10) | YES | Network protocol (TCP/UDP/etc.) |
| `failed_logins` | INTEGER | YES | Failed authentication attempts |
| `bytes_in` | FLOAT | YES | Inbound bytes |
| `bytes_out` | FLOAT | YES | Outbound bytes |
| `connection_duration` | FLOAT | YES | Duration in seconds |
| `unusual_hour` | BOOLEAN | YES | Outside 8am-6pm business hours |
| `port_number` | INTEGER | YES | Destination port |
| `raw_features_json` | TEXT | YES | Full feature set as JSON string |
| `is_anomaly` | BOOLEAN | NOT NULL | Model anomaly flag |
| `anomaly_score` | FLOAT | YES | IsolationForest raw score (NOT a probability) |
| `rf_probability` | FLOAT | YES | RandomForest class-1 probability (0-1) |
| `severity` | VARCHAR(20) | NOT NULL | "Normal" / "Suspicious" / "High" |
| `prediction_source` | VARCHAR(50) | YES | Which model produced the result |
| `alert_reason` | TEXT | YES | Human-readable explanation |
| `dataset_import_id` | INTEGER (FK) | YES | → `dataset_imports.id` |
| `model_run_id` | INTEGER (FK) | YES | → `model_runs.id` |

**Note on `anomaly_score`**: This is a raw IsolationForest `decision_function()` output.
It is a relative measure — more negative = more anomalous. It is **not** a calibrated probability.

---

### `dataset_imports`
Audit trail of every data ingestion session.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | INTEGER | NOT NULL | Auto-increment primary key |
| `import_id` | VARCHAR(36) | NOT NULL | UUID |
| `filename` | VARCHAR(255) | NOT NULL | Original filename |
| `source_type` | VARCHAR(50) | NOT NULL | "csv_upload" / "sample_data" / "demo_seed" |
| `row_count` | INTEGER | YES | Rows successfully processed |
| `anomaly_count` | INTEGER | YES | Anomalies detected in this batch |
| `error_count` | INTEGER | YES | Rows that failed parsing |
| `has_labels` | BOOLEAN | YES | Whether ground-truth labels were present |
| `status` | VARCHAR(20) | NOT NULL | "processing" / "completed" / "failed" |
| `error_message` | TEXT | YES | Error details if status="failed" |
| `notes` | TEXT | YES | Summary notes including warnings |
| `imported_at` | DATETIME | NOT NULL | Import start time (UTC) |
| `completed_at` | DATETIME | YES | Import end time (UTC) |

---

### `model_runs`
Records each model training session.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | INTEGER | NOT NULL | Auto-increment primary key |
| `run_id` | VARCHAR(36) | NOT NULL | UUID |
| `model_type` | VARCHAR(30) | NOT NULL | "isolation_forest" / "both" |
| `training_rows` | INTEGER | YES | Rows used for training |
| `test_rows` | INTEGER | YES | Rows held out for testing |
| `has_labels` | BOOLEAN | NOT NULL | Whether supervised training occurred |
| `random_seed` | INTEGER | YES | Seed used (42 by default) |
| `contamination` | FLOAT | YES | IsolationForest contamination parameter |
| `n_estimators` | INTEGER | YES | Number of trees |
| `precision` | FLOAT | YES | RandomForest precision on test set |
| `recall` | FLOAT | YES | RandomForest recall on test set |
| `f1_score` | FLOAT | YES | RandomForest F1 on test set |
| `accuracy` | FLOAT | YES | RandomForest accuracy on test set |
| `if_anomaly_count` | INTEGER | YES | Events flagged by IsolationForest |
| `if_normal_count` | INTEGER | YES | Events classified as normal |
| `artifact_path` | VARCHAR(500) | YES | Path to saved .joblib file |
| `status` | VARCHAR(20) | NOT NULL | "running" / "completed" / "failed" |
| `error_message` | TEXT | YES | Error if training failed |
| `trained_at` | DATETIME | NOT NULL | Training start time |
| `completed_at` | DATETIME | YES | Training end time |
| `notes` | TEXT | YES | Human-readable summary |

---

## Relationships

- `DetectionEvent.dataset_import_id` → `DatasetImport.id` (many-to-one)
- `DetectionEvent.model_run_id` → `ModelRun.id` (many-to-one)

Both FK columns are nullable — demo-seeded events don't require a model run record.

---

## Design Decisions

1. **SQLite** chosen for simplicity, portability, and zero-configuration.
   Suitable for single-user portfolio demonstration. Not for distributed production.

2. **UUIDs** stored as VARCHAR(36) strings rather than binary BLOB for readability in queries.

3. **`raw_features_json`** stores the full input feature set for auditability,
   allowing post-hoc review of what data triggered an alert.

4. **`anomaly_score` is always stored** even when no model is trained (as NULL),
   making it easy to distinguish model-based from rule-based results.

5. **WAL mode** is enabled for SQLite (`PRAGMA journal_mode=WAL`) to allow
   concurrent reads while writes are happening.

6. **No cascade deletes** — deleting a DatasetImport does not cascade to DetectionEvents.
   This preserves audit history.
