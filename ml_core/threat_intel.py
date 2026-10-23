# ml_core/threat_intel.py
import requests
from config import Config
from app import db
from models import ThreatIntelligence
from datetime import datetime

class ThreatIntelligenceIntegrator:
    def __init__(self):
        self.api_key = Config.THREAT_INTEL_API_KEY
        self.base_url = "https://api.threatintel.example.com/v1/" # Placeholder for a real API

    def fetch_latest_iocs(self, limit=100):
        """
        Fetches the latest Indicators of Compromise (IOCs) from external feeds.
        This would involve making actual API calls to services like VirusTotal, MISP, etc.
        """
        print(f"Fetching latest IOCs from external threat intelligence feeds (simulated)...")
        # Simulate API call
        if self.api_key == 'your_threat_intel_api_key':
            print("Warning: Threat Intelligence API key is default. Using dummy data.")
            dummy_iocs = [
                {"ioc_type": "IP_Address", "ioc_value": "192.168.1.100", "threat_name": "Dummy C2 Server", "source": "Simulated Feed", "severity": "High"},
                {"ioc_type": "Domain", "ioc_value": "phishing.example.com", "threat_name": "Dummy Phishing Site", "source": "Simulated Feed", "severity": "Medium"},
                {"ioc_type": "File_Hash", "ioc_value": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0", "threat_name": "Dummy Malware Variant", "source": "Simulated Feed", "severity": "Critical"},
            ]
            return dummy_iocs
        
        # In a real scenario:
        # try:
        #     headers = {'Authorization': f'Bearer {self.api_key}'}
        #     response = requests.get(f"{self.base_url}/iocs?limit={limit}", headers=headers)
        #     response.raise_for_status()
        #     return response.json().get('iocs', [])
        # except requests.exceptions.RequestException as e:
        #     print(f"Error fetching threat intelligence: {e}")
        #     return []

    def update_database_from_feed(self):
        """
        Fetches IOCs and updates the local database.
        """
        iocs = self.fetch_latest_iocs()
        if not iocs:
            print("No new IOCs to update.")
            return

        for ioc_data in iocs:
            existing_ioc = ThreatIntelligence.query.filter_by(ioc_value=ioc_data['ioc_value']).first()
            if not existing_ioc:
                new_ioc = ThreatIntelligence(
                    ioc_type=ioc_data['ioc_type'],
                    ioc_value=ioc_data['ioc_value'],
                    threat_name=ioc_data.get('threat_name'),
                    description=ioc_data.get('description'),
                    source=ioc_data.get('source'),
                    severity=ioc_data.get('severity')
                )
                db.session.add(new_ioc)
            else:
                # Update existing IOCs if necessary (e.g., severity, threat_name)
                existing_ioc.threat_name = ioc_data.get('threat_name', existing_ioc.threat_name)
                existing_ioc.description = ioc_data.get('description', existing_ioc.description)
                existing_ioc.source = ioc_data.get('source', existing_ioc.source)
                existing_ioc.severity = ioc_data.get('severity', existing_ioc.severity)
                existing_ioc.last_updated = datetime.utcnow()
        db.session.commit()
        print(f"Updated database with {len(iocs)} IOCs.")

    def check_against_iocs(self, data_point_value, ioc_type):
        """
        Checks a given data point (e.g., IP, hash, URL) against the local IOC database.
        Returns matching IOCs or None.
        """
        matching_iocs = ThreatIntelligence.query.filter_by(ioc_type=ioc_type, ioc_value=data_point_value).all()
        return matching_iocs if matching_iocs else []

# Global instance
# threat_intel_integrator = ThreatIntelligenceIntegrator()
# threat_intel_integrator.update_database_from_feed() # Initial sync at startup