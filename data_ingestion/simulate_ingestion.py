# data_ingestion/simulate_ingestion.py
import os
import time
import random

import numpy as np
from app import db
from models import IngestedDataLog, ThreatAlert
from ml_core.anomaly_detection import AnomalyDetector
from ml_core.malware_detection import MalwareDetector
from ml_core.phishing_detection import PhishingDetector
from ml_core.network_intrusion import NetworkIntrusionDetector
from ml_core.insider_threat import InsiderThreatDetector
from ml_core.threat_intel import ThreatIntelligenceIntegrator

# Initialize ML models globally (in a real app, manage this with a proper ML serving layer)
anomaly_detector = AnomalyDetector()
malware_detector = MalwareDetector()
phishing_detector = PhishingDetector()
network_intrusion_detector = NetworkIntrusionDetector()
insider_threat_detector = InsiderThreatDetector()
threat_intel_integrator = ThreatIntelligenceIntegrator()

def process_ingested_data(file_path, source_type, user_id, data_summary=""):
    """
    Simulates processing of ingested data, running it through ML models,
    and generating alerts.
    In a real system, this would be a background task (e.g., Celery, Spark).
    """
    print(f"Starting processing for {file_path} (Source: {source_type})...")

    # Create an IngestedDataLog entry
    ingested_log = IngestedDataLog(
        filename=os.path.basename(file_path),
        source_type=source_type,
        data_summary=data_summary,
        ingested_by_user_id=user_id,
        status='Processing'
    )
    db.session.add(ingested_log)
    db.session.commit() # Commit to get an ID for linking alerts

    alerts_generated = []

    try:
        with open(file_path, 'r') as f:
            content = f.read()

        # --- Behavioral Anomaly Detection (UEBA) ---
        if source_type == 'user_activity':
            features = anomaly_detector.preprocess_user_activity(content) # A new preprocessing function needed
            result = anomaly_detector.predict_anomaly(features)
            if result["is_anomaly"]:
                alert = ThreatAlert(
                    alert_type='Behavioral Anomaly',
                    severity='High' if result['score'] > 0.8 else 'Medium',
                    description=f"Unusual user activity detected. Score: {result['score']:.2f}",
                    user_id=user_id,
                    ingested_log_id=ingested_log.id
                )
                alert.set_details({"user_activity_snippet": content[:200], "anomaly_score": result['score']})
                db.session.add(alert)
                alerts_generated.append(alert)

        # --- Advanced Malware Detection ---
        if source_type == 'malware_sample' or source_type == 'system_log':
            # In real system, this would be binary file analysis or log analysis for hashes
            features = malware_detector.extract_features_from_sample(content)
            result = malware_detector.predict_malware(features)
            if result["is_malware"]:
                alert = ThreatAlert(
                    alert_type='Malware Detected',
                    severity='Critical' if result['confidence'] > 0.9 else 'High',
                    description=f"Potential malware detected in sample/log. Confidence: {result['confidence']:.2f}",
                    user_id=user_id,
                    ingested_log_id=ingested_log.id
                )
                alert.set_details({"source_file": os.path.basename(file_path), "malware_confidence": result['confidence']})
                db.session.add(alert)
                alerts_generated.append(alert)

        # --- Intelligent Phishing Detection ---
        if source_type == 'email_content':
            # Simulate parsing email for content, headers, URLs
            email_content = content
            email_headers = "From: badsender@example.com\nSubject: Urgent Action!" # Placeholder
            urls_in_email = ["http://badurl.com/phish", "http://legit.com"] # Placeholder
            features = phishing_detector.extract_features_from_email(email_content, email_headers, urls_in_email)
            result = phishing_detector.predict_phishing(features)
            if result["is_phishing"]:
                alert = ThreatAlert(
                    alert_type='Phishing Attempt',
                    severity='High' if result['probability'] > 0.8 else 'Medium',
                    description=f"Sophisticated phishing attempt detected. Probability: {result['probability']:.2f}",
                    user_id=user_id,
                    ingested_log_id=ingested_log.id
                )
                alert.set_details({"email_subject_snippet": email_content.split('\n')[0][:100], "phishing_prob": result['probability']})
                db.session.add(alert)
                alerts_generated.append(alert)

        # --- Network Intrusion Detection ---
        if source_type == 'network_traffic':
            features = network_intrusion_detector.extract_features_from_traffic(content)
            result = network_intrusion_detector.predict_intrusion(features)
            if result["is_intrusion"]:
                alert = ThreatAlert(
                    alert_type='Network Intrusion',
                    severity='Critical' if result['score'] > 0.85 else 'High',
                    description=f"Suspicious network activity detected. Score: {result['score']:.2f}",
                    user_id=user_id,
                    ingested_log_id=ingested_log.id
                )
                alert.set_details({"network_traffic_snippet": content[:200], "intrusion_score": result['score']})
                db.session.add(alert)
                alerts_generated.append(alert)

        # --- Threat Intelligence Integration (Example check) ---
        # Simulate checking an IP or hash found in logs against TI
        if source_type in ['network_traffic', 'system_log']:
            # Example: Try to extract a random IP from the content for TI check
            import re
            ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            ips = re.findall(ip_pattern, content)
            if ips:
                checked_ip = random.choice(ips)
                matching_iocs = threat_intel_integrator.check_against_iocs(checked_ip, 'IP_Address')
                if matching_iocs:
                    for ioc in matching_iocs:
                        alert = ThreatAlert(
                            alert_type='Threat Intel Match',
                            severity=ioc.severity or 'High',
                            description=f"IOC Match: {ioc.ioc_type} {ioc.ioc_value} linked to {ioc.threat_name or 'unknown threat'}",
                            user_id=user_id,
                            ingested_log_id=ingested_log.id
                        )
                        alert.set_details({"ioc_value": ioc.ioc_value, "ioc_type": ioc.ioc_type, "threat_name": ioc.threat_name})
                        db.session.add(alert)
                        alerts_generated.append(alert)

        ingested_log.status = 'Processed'
        db.session.commit()
        print(f"Finished processing {file_path}. Generated {len(alerts_generated)} alerts.")
        return len(alerts_generated)

    except Exception as e:
        ingested_log.status = 'Error'
        ingested_log.data_summary = f"Processing Error: {str(e)}"
        db.session.commit()
        print(f"Error processing {file_path}: {e}")
        return 0

# Functions to simulate data for model training (would be loaded from real datasets)
def simulate_training_data():
    """Generates dummy data for training placeholder ML models."""
    # Anomaly Detection: Normal user behavior features
    anomaly_detector.train_baseline(np.random.rand(1000, 15)) # 15 features for user activity

    # Malware Detection: Features from benign and malicious files
    malware_detector.train_models(np.random.rand(500, 20), np.random.randint(0, 2, 500))

    # Phishing Detection: Email content (features) and labels
    phishing_detector.train_models(
        ["This is a legitimate email about your account.", "Hello, your bank statement is ready.",
         "URGENT: Your account has been compromised, click this link now!", "Win a free iPhone, just enter your credit card details!"],
        [0, 0, 1, 1]
    )

    # Network Intrusion Detection: Normal and attack traffic features
    network_intrusion_detector.train_models(np.random.rand(1000, 30), np.random.randint(0, 2, 1000))

    # Insider Threat: Sequences of normal user actions
    sequences = [np.random.rand(random.randint(5, 20), 5) for _ in range(100)]
    insider_threat_detector.train_hmm_baseline(sequences)

    # Initial Threat Intel Sync
    threat_intel_integrator.update_database_from_feed()

    print("All ML models (placeholders) and Threat Intel synced with dummy data.")