import unittest
from datetime import datetime

from src.agent.planner import InvestigationPlanner
from src.models.schemas import Alert, Severity


class TestInvestigationPlanner(unittest.TestCase):

    def setUp(self):
        self.planner = InvestigationPlanner()

    def test_full_alert_creates_full_plan(self):
        alert = Alert(
            alert_id="ALT-001",
            rule="Brute Force",
            severity=Severity.HIGH,
            source_ip="185.10.10.20",
            username="admin",
            failed_attempts=35,
            timestamp=datetime.now(),
        )

        plan = self.planner.create_plan(alert)

        self.assertEqual(
            [step["action"] for step in plan],
            [
                "LOG_SEARCH",
                "IOC_LOOKUP",
                "MITRE_LOOKUP",
            ],
        )

        self.assertIn(
            "authentication activity",
            plan[0]["reason"],
        )

        self.assertIn(
            "threat intelligence",
            plan[1]["reason"],
        )

        self.assertIn(
            "MITRE ATT&CK",
            plan[2]["reason"],
        )

    def test_alert_without_username_skips_log_search(self):
        alert = Alert(
            alert_id="ALT-002",
            rule="Suspicious Network Activity",
            severity=Severity.MEDIUM,
            source_ip="185.10.10.20",
            failed_attempts=0,
            timestamp=datetime.now(),
        )

        plan = self.planner.create_plan(alert)

        actions = [
            step["action"]
            for step in plan
        ]

        self.assertNotIn(
            "LOG_SEARCH",
            actions,
        )

        self.assertIn(
            "IOC_LOOKUP",
            actions,
        )

        self.assertIn(
            "MITRE_LOOKUP",
            actions,
        )

    def test_alert_without_source_ip_skips_ioc_lookup(self):
        alert = Alert(
            alert_id="ALT-003",
            rule="Brute Force",
            severity=Severity.HIGH,
            username="admin",
            failed_attempts=20,
            timestamp=datetime.now(),
        )

        plan = self.planner.create_plan(alert)

        actions = [
            step["action"]
            for step in plan
        ]

        self.assertIn(
            "LOG_SEARCH",
            actions,
        )

        self.assertNotIn(
            "IOC_LOOKUP",
            actions,
        )

        self.assertIn(
            "MITRE_LOOKUP",
            actions,
        )

    def test_alert_without_rule_skips_mitre_lookup(self):
        alert = Alert(
            alert_id="ALT-004",
            rule="",
            severity=Severity.MEDIUM,
            source_ip="10.0.0.10",
            username="john",
            failed_attempts=3,
            timestamp=datetime.now(),
        )

        plan = self.planner.create_plan(alert)

        actions = [
            step["action"]
            for step in plan
        ]

        self.assertIn(
            "LOG_SEARCH",
            actions,
        )

        self.assertIn(
            "IOC_LOOKUP",
            actions,
        )

        self.assertNotIn(
            "MITRE_LOOKUP",
            actions,
        )


if __name__ == "__main__":
    unittest.main()

