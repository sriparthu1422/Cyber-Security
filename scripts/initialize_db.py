"""
scripts/initialize_db.py — Database initialization and demo data seeding.

Run this once before starting the application:
    python scripts/initialize_db.py

What this script does:
1. Creates all SQLite database tables
2. Seeds a small set of demo detection events for immediate dashboard display
3. Adds sample dataset import and model run records

Safe to run multiple times — checks for existing data before inserting.
Does NOT delete existing records.
"""
import sys
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.database import init_db, get_db_session
from app.models.detection_event import DetectionEvent
from app.models.dataset_import import DatasetImport
from app.models.model_run import ModelRun


DEMO_EVENTS = [
    # Normal events
    {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc) - timedelta(hours=2),
        "source_ip": "192.0.2.10",
        "dest_ip": "192.0.2.100",
        "protocol": "HTTPS",
        "failed_logins": 0,
        "bytes_in": 4096.0,
        "bytes_out": 1024.0,
        "connection_duration": 12.5,
        "unusual_hour": False,
        "port_number": 443,
        "is_anomaly": False,
        "anomaly_score": 0.12,
        "rf_probability": None,
        "severity": "Normal",
        "prediction_source": "demo_seed",
        "alert_reason": "Normal HTTPS traffic within business hours.",
    },
    {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc) - timedelta(hours=3),
        "source_ip": "192.0.2.15",
        "dest_ip": "198.51.100.5",
        "protocol": "HTTP",
        "failed_logins": 1,
        "bytes_in": 2048.0,
        "bytes_out": 512.0,
        "connection_duration": 8.0,
        "unusual_hour": False,
        "port_number": 80,
        "is_anomaly": False,
        "anomaly_score": 0.08,
        "rf_probability": None,
        "severity": "Normal",
        "prediction_source": "demo_seed",
        "alert_reason": "Normal HTTP traffic, low activity within baseline.",
    },
    # Suspicious event
    {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc) - timedelta(hours=1),
        "source_ip": "192.0.2.55",
        "dest_ip": "203.0.113.10",
        "protocol": "SSH",
        "failed_logins": 12,
        "bytes_in": 1024.0,
        "bytes_out": 512.0,
        "connection_duration": 45.0,
        "unusual_hour": True,
        "port_number": 22,
        "is_anomaly": True,
        "anomaly_score": -0.08,
        "rf_probability": None,
        "severity": "Suspicious",
        "prediction_source": "demo_seed",
        "alert_reason": (
            "IsolationForest flagged this event as anomalous (score=-0.0800) | "
            "High failed login count: 12 attempts | "
            "Activity occurred outside normal business hours"
        ),
    },
    # High severity event
    {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc) - timedelta(minutes=30),
        "source_ip": "192.0.2.77",
        "dest_ip": "203.0.113.99",
        "protocol": "TCP",
        "failed_logins": 47,
        "bytes_in": 512.0,
        "bytes_out": 2_500_000.0,  # ~2.5 MB outbound — data exfiltration pattern
        "connection_duration": 320.0,
        "unusual_hour": True,
        "port_number": 4444,
        "is_anomaly": True,
        "anomaly_score": -0.22,
        "rf_probability": None,
        "severity": "High",
        "prediction_source": "demo_seed",
        "alert_reason": (
            "IsolationForest flagged this event as anomalous (score=-0.2200) | "
            "High failed login count: 47 attempts | "
            "Activity occurred outside normal business hours | "
            "High outbound data transfer: 2,500,000 bytes | "
            "Activity on sensitive port: 4444"
        ),
    },
    # Another normal event
    {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc) - timedelta(hours=4),
        "source_ip": "198.51.100.20",
        "dest_ip": "192.0.2.5",
        "protocol": "DNS",
        "failed_logins": 0,
        "bytes_in": 128.0,
        "bytes_out": 64.0,
        "connection_duration": 0.5,
        "unusual_hour": False,
        "port_number": 53,
        "is_anomaly": False,
        "anomaly_score": 0.15,
        "rf_probability": None,
        "severity": "Normal",
        "prediction_source": "demo_seed",
        "alert_reason": "Normal DNS lookup with expected traffic volume.",
    },
    # Suspicious event 2
    {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc) - timedelta(minutes=90),
        "source_ip": "203.0.113.15",
        "dest_ip": "192.0.2.8",
        "protocol": "TCP",
        "failed_logins": 8,
        "bytes_in": 256.0,
        "bytes_out": 128.0,
        "connection_duration": 1.2,
        "unusual_hour": True,
        "port_number": 3389,
        "is_anomaly": True,
        "anomaly_score": -0.05,
        "rf_probability": None,
        "severity": "Suspicious",
        "prediction_source": "demo_seed",
        "alert_reason": (
            "IsolationForest flagged this event as anomalous (score=-0.0500) | "
            "High failed login count: 8 attempts | "
            "Activity occurred outside normal business hours | "
            "Activity on sensitive port: 3389 (RDP)"
        ),
    },
]


def seed_demo_data():
    """Insert demo detection events if the table is empty."""
    with get_db_session() as db:
        existing_count = db.query(DetectionEvent).count()
        if existing_count > 0:
            print(f"Database already has {existing_count} detection events. Skipping seed.")
            return

        # Create a demo dataset import record
        demo_import = DatasetImport(
            import_id=str(uuid.uuid4()),
            filename="demo_seed_data",
            source_type="demo_seed",
            row_count=len(DEMO_EVENTS),
            anomaly_count=sum(1 for e in DEMO_EVENTS if e["is_anomaly"]),
            error_count=0,
            has_labels=True,
            status="completed",
            imported_at=datetime.now(timezone.utc) - timedelta(hours=5),
            completed_at=datetime.now(timezone.utc) - timedelta(hours=5),
            notes="Demo seed data for dashboard demonstration. Synthetic records only.",
        )
        db.add(demo_import)
        db.flush()

        # Insert demo events
        for event_data in DEMO_EVENTS:
            event_data["dataset_import_id"] = demo_import.id
            event = DetectionEvent(**event_data)
            db.add(event)

        print(f"Seeded {len(DEMO_EVENTS)} demo detection events.")


def main():
    print("Initializing database...")
    init_db()
    print("Database tables created.")

    print("Seeding demo data...")
    seed_demo_data()

    print("\nDatabase initialization complete!")
    print("Run the API with: uvicorn app.main:app --reload --port 8000")
    print("API docs: http://localhost:8000/docs")


if __name__ == "__main__":
    main()
