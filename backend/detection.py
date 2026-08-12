import logging
from typing import List, Dict, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class Threatrule:
    def __init__(self, rule_id: str, name: str, description: str, severity: str):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.severity = severity

    def check(self, data: Dict) -> bool:
        raise NotImplementedError

class PortScanRule(Threatrule):
    def __init__(self):
        super().__init__("PORT_SCAN", "Port Scan Detected", "Multiple port connections in short time", "high")
        self.port_threshold = 10
        self.time_window = 60

    def check(self, data: Dict) -> bool:
        return data.get("port_count", 0) > self.port_threshold

class SuspiciousDNSRule(Threatrule):
    def __init__(self):
        super().__init__("SUSPICIOUS_DNS", "Suspicious DNS Query", "Query to known malicious domain", "critical")
        self.malicious_domains = [
            "malware.com",
            "phishing.site",
            "c2.server.net",
            "ransomware.xyz"
        ]

    def check(self, data: Dict) -> bool:
        domain = data.get("dns_query", "").lower()
        return any(malicious in domain for malicious in self.malicious_domains)

class UnknownDeviceRule(Threatrule):
    def __init__(self):
        super().__init__("UNKNOWN_DEVICE", "Unknown Device connected", "New device detected on network", "medium")
    def check(self, data: Dict) -> bool:
        return data.get("is_new_device", False)

class BruteForceRule(Threatrule):
    def __init__(self):
        super().__init__("BRUTE_FORCE", "Brute Force Attempt", "Multiple failed login attempts", "high")
        self.attempt_threshold = 5
        self.time_window = 60

    def check(self, data: Dict) -> bool:
        return data.get("failed_attempts", 0) > self.attempt_threshold

class ThreatDetectionEngine:
    def __init__(self):
        self.rules: List[Threatrule] = [
            PortScanRule(),
            SuspiciousDNSRule(),
            UnknownDeviceRule(),
            BruteForceRule()
        ]
        self.alert_history = {}

    def analyze(self, data: Dict) -> List[Dict]:
        alerts = []
        for rule in self.rules:
            try:
                if rule.check(data):
                    alert = {
                        "rule_id": rule.rule_id,
                        "name": rule.name,
                        "description": rule.description,
                        "severity": rule.severity,
                        "timestamp": datetime.now().isoformat(),
                        "data": data
                    }
                    alerts.append(alert)
                    logger.warning(f"Alert triggered: {rule.name} - {data}")
            except Exception as e:
                logger.error(f"Error checking rule {rule.rule_id}: {e}")

        return alerts

    def deduplicate_alerts(self, device_id: int, alert_type: str, time_window: int = 300) -> bool:
        key = f"{device_id}_{alert_type}"
        now = datetime.now()

        if key in self.alert_history:
            last_alert = self.alert_history[key]
            if (now - last_alert).seconds < time_window:
                return False

        self.alert_history[key] = now
        return True

    def get_threat_level(self, alerts: List[Dict]) -> str:
        if not alerts:
            return "safe"

        severity_levels = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_severity = max(severity_levels.get(a.get("severity", "low"), 0) for a in alerts)

        if max_severity >= 4:
            return "critical"
        elif max_severity >= 3:
            return "high"
        elif max_severity >= 2:
            return "medium"
        else:
            return "low"
