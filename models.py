from datetime import datetime
from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import json

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    # One-to-many relationship with alerts and logs
    alerts = db.relationship('ThreatAlert', backref='raised_by', lazy=True)
    ingested_data_logs = db.relationship('IngestedDataLog', backref='ingested_by', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

class IngestedDataLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=True) # If uploaded file
    source_type = db.Column(db.String(50), nullable=False) # e.g., 'network_traffic', 'system_log', 'user_activity', 'transaction_record', 'email'
    ingestion_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    data_summary = db.Column(db.Text, nullable=True) # Short summary or sample of ingested data
    status = db.Column(db.String(20), nullable=False, default='Processed') # 'Processing', 'Processed', 'Error'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"IngestedDataLog('{self.source_type}', '{self.ingestion_timestamp}')"

class ThreatAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(100), nullable=False) # e.g., 'Anomaly Detection', 'Malware Detected', 'Phishing Attempt', 'Intrusion Attempt', 'Insider Threat'
    severity = db.Column(db.String(20), nullable=False) # 'Low', 'Medium', 'High', 'Critical'
    description = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # Store relevant data as JSON (e.g., affected user, IP, file hash, email sender)
    details_json = db.Column(db.Text, nullable=True)
    is_resolved = db.Column(db.Boolean, default=False)
    resolved_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    resolved_timestamp = db.Column(db.DateTime, nullable=True)
    ingested_log_id = db.Column(db.Integer, db.ForeignKey('ingested_data_log.id'), nullable=True) # Link to the data that triggered the alert
    # Relationship to user who raised the alert (optional, if alerts can be manual)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def set_details(self, details_dict):
        self.details_json = json.dumps(details_dict)

    def get_details(self):
        return json.loads(self.details_json) if self.details_json else {}

    def __repr__(self):
        return f"ThreatAlert('{self.alert_type}', '{self.severity}', '{self.timestamp}')"

class ThreatIntelligence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ioc_type = db.Column(db.String(50), nullable=False) # e.g., 'IP_Address', 'Domain', 'File_Hash', 'URL'
    ioc_value = db.Column(db.String(255), unique=True, nullable=False)
    threat_name = db.Column(db.String(100), nullable=True) # e.g., 'Ryuk Ransomware'
    description = db.Column(db.Text, nullable=True)
    source = db.Column(db.String(100), nullable=True) # e.g., 'OSINT', 'Commercial Feed X'
    last_updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    severity = db.Column(db.String(20), nullable=True)

    def __repr__(self):
        return f"ThreatIntelligence('{self.ioc_type}', '{self.ioc_value}')"

# Add more specific models as needed, e.g., UserBehaviorProfile, SystemBaseline