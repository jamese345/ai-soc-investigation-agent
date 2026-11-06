import unittest
from datetime import datetime
from unittest.mock import patch

from src.agent.investigation import InvestigationAgent
from src.models.schemas import (
    Alert,
    InvestigationStatus,
    Severity,
)


class TestInvestigationAgent(unittest.TestCase):

    @patch("src.agent.investigation.build_tool_registry")
    def test_complete_investigation(self, mock_registry):

        mock_ioc_tool = unittest.mock.Mock()
        mock_log_tool = unittest.mock.Mock()
        mock_mitre_tool = unittest.mock.Mock()

        from src.models.schemas import Confidence, Evidence

        mock_ioc_tool.execute.return_value = {
            "evidence": Evidence(
                source="AlienVault OTX",
                description="IOC is suspicious.",
                relevance="HIGH",
                confidence=Confidence.HIGH,
            )
        }

        mock_log_tool.execute.return_value = {
            "evidence": Evidence(
                source="Security Logs",
                description="Multiple failed login attempts detected.",
                relevance="HIGH",
                confidence=Confidence.HIGH,
            )
        }

        mock_mitre_tool.execute.return_value = {
            "evidence": Evidence(
                source="MITRE ATT&CK",
                description="Brute Force maps to T1110.",
                relevance="HIGH",
                confidence=Confidence.HIGH,
            )
        }

        mock_registry.return_value = {
            "IOC_LOOKUP": mock_ioc_tool,
            "LOG_SEARCH": mock_log_tool,
            "MITRE_LOOKUP": mock_mitre_tool,
        }

        agent = InvestigationAgent()

        alert = Alert(
            alert_id="ALT-001",
            rule="Brute Force",
            severity=Severity.HIGH,
            source_ip="185.10.10.20",
            username="admin",
            failed_attempts=35,
            timestamp=datetime.now(),
        )

        investigation = agent.investigate(alert)

        self.assertEqual(
            investigation.status,
            InvestigationStatus.COMPLETED,
        )

        self.assertIsNotNone(
            investigation.started_at
        )

        self.assertIsNotNone(
            investigation.completed_at
        )

        self.assertEqual(
            len(investigation.findings),
            3,
        )

        sources = {
            finding.evidence[0].source
            for finding in investigation.findings
        }

        self.assertEqual(
            sources,
            {
                "AlienVault OTX",
                "Security Logs",
                "MITRE ATT&CK",
            },
        )


if __name__ == "__main__":
    unittest.main()