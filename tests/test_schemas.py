import unittest
from datetime import datetime

from src.models.schemas import (
    Alert,
    Confidence,
    Evidence,
    Finding,
    Investigation,
    InvestigationStatus,
    Recommendation,
    Severity,
)


class TestSchemas(unittest.TestCase):

    def test_alert_creation(self):
        alert = Alert(
            alert_id="ALT-001",
            rule="Multiple Failed Logins",
            severity=Severity.HIGH,
            source_ip="185.10.10.20",
            username="admin",
            failed_attempts=37,
            timestamp=datetime.now(),
        )

        self.assertEqual(alert.alert_id, "ALT-001")
        self.assertEqual(alert.severity, Severity.HIGH)
        self.assertEqual(alert.failed_attempts, 37)

    def test_evidence_creation(self):
        evidence = Evidence(
            source="threat_intelligence",
            description="Source IP associated with suspicious activity.",
            relevance="Supports malicious activity hypothesis.",
            confidence=Confidence.HIGH,
        )

        self.assertEqual(evidence.source, "threat_intelligence")
        self.assertEqual(evidence.confidence, Confidence.HIGH)

    def test_investigation_creation(self):
        alert = Alert(
            alert_id="ALT-002",
            rule="Brute Force Detection",
            severity=Severity.CRITICAL,
            source_ip="192.168.1.50",
            username="admin",
            failed_attempts=50,
            timestamp=datetime.now(),
        )

        finding = Finding(
            title="Possible Brute Force Attack",
            description=(
                "Repeated authentication failures indicate "
                "possible credential attack."
            ),
            severity=Severity.HIGH,
            confidence=Confidence.VERY_HIGH,
        )

        recommendation = Recommendation(
            action="Investigate source IP and review authentication logs.",
            priority=Severity.HIGH,
            reason="High volume of failed authentication attempts.",
        )

        investigation = Investigation(
            investigation_id="INV-001",
            alert=alert,
            status=InvestigationStatus.IN_PROGRESS,
            findings=[finding],
            recommendations=[recommendation],
        )

        self.assertEqual(investigation.investigation_id, "INV-001")
        self.assertEqual(len(investigation.findings), 1)
        self.assertEqual(len(investigation.recommendations), 1)


if __name__ == "__main__":
    unittest.main()