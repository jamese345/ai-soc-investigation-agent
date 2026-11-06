from typing import Dict, List

from src.models.schemas import Alert, Evidence


class InvestigationExecutor:
    """Executes investigation steps in priority order."""

    PRIORITY_ORDER = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
    }

    def __init__(self, tools: Dict[str, object]):
        self.tools = tools

    def execute(
        self,
        alert: Alert,
        plan: List,
    ) -> List[Evidence]:
        """Execute investigation steps and collect evidence."""

        evidence = []

        ordered_plan = self._sort_plan(plan)

        for step in ordered_plan:
            action = self._get_action(step)

            tool = self.tools.get(action)

            if tool is None:
                self._update_status(
                    step,
                    "SKIPPED",
                )
                continue

            self._update_status(
                step,
                "IN_PROGRESS",
            )

            try:
                result = self._execute_tool(
                    tool,
                    action,
                    alert,
                )

                if isinstance(result, dict):
                    tool_evidence = result.get(
                        "evidence"
                    )

                    if tool_evidence is not None:
                        evidence.append(
                            tool_evidence
                        )

                elif isinstance(
                    result,
                    Evidence,
                ):
                    evidence.append(result)

                self._update_status(
                    step,
                    "COMPLETED",
                )

            except Exception:
                self._update_status(
                    step,
                    "FAILED",
                )
                raise

        return evidence

    def _sort_plan(
        self,
        plan: List,
    ) -> List:
        """Sort investigation steps by priority."""

        if not plan:
            return []

        def priority_value(step):
            if isinstance(step, str):
                priority = "MEDIUM"

            elif isinstance(step, dict):
                priority = step.get(
                    "priority",
                    "MEDIUM",
                )

            else:
                priority = getattr(
                    step,
                    "priority",
                    "MEDIUM",
                )

            return self.PRIORITY_ORDER.get(
                str(priority).upper(),
                self.PRIORITY_ORDER["MEDIUM"],
            )

        return sorted(
            plan,
            key=priority_value,
        )

    @staticmethod
    def _get_action(step) -> str:
        """Get action from any supported step format."""

        if isinstance(step, str):
            return step

        if isinstance(step, dict):
            return step.get("action")

        return step.action

    @staticmethod
    def _update_status(
        step,
        status: str,
    ):
        """Update execution status."""

        if isinstance(step, dict):
            step["status"] = status

        elif not isinstance(step, str):
            step.status = status

    def _execute_tool(
        self,
        tool,
        action: str,
        alert: Alert,
    ):
        """Execute a registered investigation tool."""

        if action == "IOC_LOOKUP":
            return tool.execute(
                ioc=alert.source_ip
            )

        if action == "LOG_SEARCH":
            return tool.execute(
                username=alert.username
            )

        if action == "MITRE_LOOKUP":
            return tool.execute(
                rule=alert.rule
            )

        return None