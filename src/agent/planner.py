from typing import List

from src.models.schemas import Alert, Severity


class InvestigationPlanner:
    """Creates a context-aware and explainable investigation plan."""

    def create_plan(self, alert: Alert) -> List[dict]:
        plan = []

        if alert.username:
            plan.append(
                {
                    "action": "LOG_SEARCH",
                    "reason": (
                        "Investigate authentication activity "
                        "associated with the affected account."
                    ),
                    "priority": self._authentication_priority(alert),
                }
            )

        if alert.source_ip:
            plan.append(
                {
                    "action": "IOC_LOOKUP",
                    "reason": (
                        "Enrich the source IP with "
                        "threat intelligence."
                    ),
                    "priority": self._ioc_priority(alert),
                }
            )

        if alert.rule:
            plan.append(
                {
                    "action": "MITRE_LOOKUP",
                    "reason": (
                        "Map the detection rule to "
                        "MITRE ATT&CK."
                    ),
                    "priority": self._mitre_priority(alert),
                }
            )

        return plan

    @staticmethod
    def _authentication_priority(alert: Alert) -> str:
        if alert.severity in {
            Severity.CRITICAL,
            Severity.HIGH,
        }:
            return "HIGH"

        return "MEDIUM"

    @staticmethod
    def _ioc_priority(alert: Alert) -> str:
        if alert.severity == Severity.CRITICAL:
            return "CRITICAL"

        if alert.severity == Severity.HIGH:
            return "HIGH"

        return "MEDIUM"

    @staticmethod
    def _mitre_priority(alert: Alert) -> str:
        if alert.severity == Severity.CRITICAL:
            return "HIGH"

        return "MEDIUM"