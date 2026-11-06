import unittest

from src.agent.investigation import InvestigationAgent
from src.models.schemas import (
    Alert,
    Severity,
)


class TestEvidenceEvaluationIntegration(unittest.TestCase):

    def test_investigation_stores_evidence_evaluation(self):
        alert = Alert(
            alert_id="ALT-TEST",
            rule="Brute Force",
            severity=Severity.HIGH,
            source_ip="185.10.10.20",
            username="admin",
            failed_attempts=20,
            timestamp="2026-11-06T10:00:00",
        )

        agent = InvestigationAgent()

        investigation = agent.investigate(alert)

        self.assertIsNotNone(
            investigation.evidence_evaluation
        )

        self.assertGreaterEqual(
            investigation.evidence_evaluation.score,
            0,
        )

        self.assertIsInstance(
            investigation.evidence_evaluation.sufficient,
            bool,
        )


if __name__ == "__main__":
    unittest.main()