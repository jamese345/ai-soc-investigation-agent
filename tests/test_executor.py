import unittest
from unittest.mock import Mock

from src.agent.executor import InvestigationExecutor
from src.models.schemas import (
    Alert,
    Confidence,
    Evidence,
    Severity,
)


class TestInvestigationExecutor(unittest.TestCase):

    def setUp(self):
        self.alert = Alert(
            alert_id="ALT-001",
            rule="Brute Force",
            severity=Severity.HIGH,
            source_ip="185.10.10.20",
            username="admin",
            failed_attempts=35,
            timestamp="2026-11-06T10:00:00",
        )

    def test_ioc_tool_execution(self):
        ioc_tool = Mock()

        evidence = Evidence(
            source="AlienVault OTX",
            description="IOC is malicious.",
            relevance="CRITICAL",
            confidence=Confidence.VERY_HIGH,
        )

        ioc_tool.execute.return_value = {
            "evidence": evidence,
        }

        executor = InvestigationExecutor(
            tools={
                "IOC_LOOKUP": ioc_tool,
            }
        )

        results = executor.execute(
            self.alert,
            ["IOC_LOOKUP"],
        )

        ioc_tool.execute.assert_called_once_with(
            ioc="185.10.10.20"
        )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].source, "AlienVault OTX")

    def test_multiple_tools(self):
        ioc_tool = Mock()
        log_tool = Mock()
        mitre_tool = Mock()

        ioc_tool.execute.return_value = {
            "evidence": Evidence(
                source="AlienVault OTX",
                description="IOC evidence.",
                relevance="HIGH",
                confidence=Confidence.HIGH,
            )
        }

        log_tool.execute.return_value = {
            "evidence": Evidence(
                source="Security Logs",
                description="User activity evidence.",
                relevance="HIGH",
                confidence=Confidence.HIGH,
            )
        }

        mitre_tool.execute.return_value = {
            "evidence": Evidence(
                source="MITRE ATT&CK",
                description="Brute Force maps to T1110.",
                relevance="HIGH",
                confidence=Confidence.HIGH,
            )
        }

        executor = InvestigationExecutor(
            tools={
                "IOC_LOOKUP": ioc_tool,
                "LOG_SEARCH": log_tool,
                "MITRE_LOOKUP": mitre_tool,
            }
        )

        results = executor.execute(
            self.alert,
            [
                "IOC_LOOKUP",
                "LOG_SEARCH",
                "MITRE_LOOKUP",
            ],
        )

        self.assertEqual(len(results), 3)

        ioc_tool.execute.assert_called_once_with(
            ioc="185.10.10.20"
        )

        log_tool.execute.assert_called_once_with(
            username="admin"
        )

        mitre_tool.execute.assert_called_once_with(
            rule="Brute Force"
        )

    def test_unknown_action_is_skipped(self):
        executor = InvestigationExecutor(tools={})

        results = executor.execute(
            self.alert,
            ["UNKNOWN_ACTION"],
        )

        self.assertEqual(results, [])

    def test_priority_ordering(self):
        execution_order = []

        class TrackingTool:
            def __init__(self, name):
                self.name = name

            def execute(self, **kwargs):
                execution_order.append(self.name)

                return {
                    "evidence": None
                }

        tools = {
            "LOG_SEARCH": TrackingTool("LOG_SEARCH"),
            "IOC_LOOKUP": TrackingTool("IOC_LOOKUP"),
            "MITRE_LOOKUP": TrackingTool("MITRE_LOOKUP"),
        }

        executor = InvestigationExecutor(tools)

        plan = [
            {
                "action": "MITRE_LOOKUP",
                "reason": "Map the detection.",
                "priority": "MEDIUM",
            },
            {
                "action": "LOG_SEARCH",
                "reason": "Investigate authentication.",
                "priority": "HIGH",
            },
            {
                "action": "IOC_LOOKUP",
                "reason": "Enrich the source IP.",
                "priority": "CRITICAL",
            },
        ]

        executor.execute(
            self.alert,
            plan,
        )

        self.assertEqual(
            execution_order,
            [
                "IOC_LOOKUP",
                "LOG_SEARCH",
                "MITRE_LOOKUP",
            ],
        )

    def test_step_status_becomes_completed(self):
        class SuccessfulTool:
            def execute(self, **kwargs):
                return {
                    "evidence": None
                }

        tools = {
            "IOC_LOOKUP": SuccessfulTool()
        }

        executor = InvestigationExecutor(tools)

        plan = [
            {
                "action": "IOC_LOOKUP",
                "reason": "Enrich the source IP.",
                "priority": "HIGH",
            }
        ]

        executor.execute(
            self.alert,
            plan,
        )

        self.assertEqual(
            plan[0]["status"],
            "COMPLETED",
        )

    def test_step_status_becomes_skipped_for_unknown_tool(self):
        executor = InvestigationExecutor({})

        plan = [
            {
                "action": "UNKNOWN_ACTION",
                "reason": "Test unknown action.",
                "priority": "LOW",
            }
        ]

        executor.execute(
            self.alert,
            plan,
        )

        self.assertEqual(
            plan[0]["status"],
            "SKIPPED",
        )


if __name__ == "__main__":
    unittest.main()