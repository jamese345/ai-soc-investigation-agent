from datetime import datetime
from uuid import uuid4

from src.agent.evidence_evaluator import (
    EvidenceEvaluator,
)
from src.agent.executor import (
    InvestigationExecutor,
)
from src.agent.planner import (
    InvestigationPlanner,
)
from src.agent.tool_registry import (
    build_tool_registry,
)
from src.models.schemas import (
    Alert,
    EvidenceEvaluation,
    Finding,
    Investigation,
    InvestigationStatus,
    InvestigationStep,
    Recommendation,
)



class InvestigationAgent:
    """Coordinates adaptive investigation planning, execution, and AI reasoning."""

    MAX_ESCALATION_ROUNDS = 1

    def __init__(
        self,
        reasoner=None,
        report_generator=None,
    ):
        self.planner = InvestigationPlanner()

        self.tools = build_tool_registry()

        self.executor = InvestigationExecutor(
            self.tools
        )

        self.evidence_evaluator = (
            EvidenceEvaluator()
        )

        self.reasoner = reasoner

        self.report_generator = (
            report_generator
        )
    @staticmethod
    def _recommendation_priority(
        severity,
    ) -> str:
        """Map investigation severity to recommendation priority."""

        if severity.value == "CRITICAL":
            return "CRITICAL"

        if severity.value == "HIGH":
            return "HIGH"

        if severity.value == "MEDIUM":
            return "MEDIUM"

        return "LOW"

    def investigate(
        self,
        alert: Alert,
    ) -> Investigation:
        """Run an adaptive security investigation."""

        investigation = Investigation(
            investigation_id=(
                f"INV-{uuid4().hex[:8].upper()}"
            ),
            alert=alert,
            status=InvestigationStatus.IN_PROGRESS,
            started_at=datetime.now(),
        )

        try:
            # -------------------------------------------------
            # 1. CREATE INITIAL INVESTIGATION PLAN
            # -------------------------------------------------

            plan = self.planner.create_plan(
                alert
            )

            investigation.plan = [
                InvestigationStep(
                    action=step["action"],
                    reason=step["reason"],
                    priority=step.get(
                        "priority",
                        "MEDIUM",
                    ),
                )
                for step in plan
            ]

            # -------------------------------------------------
            # 2. EXECUTE INITIAL INVESTIGATION
            # -------------------------------------------------

            evidence = self.executor.execute(
                alert,
                investigation.plan,
            )

            # -------------------------------------------------
            # 3. EVALUATE INITIAL EVIDENCE
            # -------------------------------------------------

            evaluation = (
                self._evaluate_evidence(
                    investigation,
                    evidence,
                )
            )

            # -------------------------------------------------
            # 4. CONTROLLED ADAPTIVE ESCALATION
            # -------------------------------------------------

            escalation_round = 0

            while (
                not evaluation.sufficient
                and escalation_round
                < self.MAX_ESCALATION_ROUNDS
            ):
                escalation_round += 1

                additional_step = (
                    self._select_escalation_step(
                        investigation
                    )
                )

                if additional_step is None:
                    break

                escalation_step = (
                    InvestigationStep(
                        action=(
                            additional_step[
                                "action"
                            ]
                        ),
                        reason=(
                            additional_step[
                                "reason"
                            ]
                        ),
                        priority=(
                            additional_step.get(
                                "priority",
                                "MEDIUM",
                            )
                        ),
                    )
                )

                investigation.plan.append(
                    escalation_step
                )

                additional_evidence = (
                    self.executor.execute(
                        alert,
                        [escalation_step],
                    )
                )

                evidence.extend(
                    additional_evidence
                )

                evaluation = (
                    self._evaluate_evidence(
                        investigation,
                        evidence,
                    )
                )

            # -------------------------------------------------
            # 5. BUILD FINDINGS
            # -------------------------------------------------

            for item in evidence:
                finding = Finding(
                    title=(
                        f"Evidence from "
                        f"{item.source}"
                    ),
                    description=(
                        item.description
                    ),
                    severity=alert.severity,
                    confidence=item.confidence,
                    evidence=[item],
                )

                investigation.findings.append(
                    finding
                )

            # -------------------------------------------------
            # 6. AI REASONING
            # -------------------------------------------------
            if self.reasoner is not None:
                investigation.reasoning = (
                    self.reasoner.analyze(
                        investigation
                    )
                )

                # Convert AI recommended actions into
                # structured SOC recommendations.
                if investigation.reasoning.recommended_actions:
                    investigation.recommendations = [
                        Recommendation(
                            action=action,
                            priority=self._recommendation_priority(
                                investigation.reasoning.severity
                            ),
                            reason=(
                                "Recommended by the AI SOC "
                                "investigation based on the "
                                "collected evidence."
                            ),
                        )
                        for action in (
                            investigation.reasoning
                            .recommended_actions
                        )
                    ]
            # -------------------------------------------------
            # 7. COMPLETE INVESTIGATION
            # -------------------------------------------------

            investigation.status = (
                InvestigationStatus.COMPLETED
            )

            investigation.completed_at = (
                datetime.now()
            )

            # -------------------------------------------------
            # 8. SAVE REPORT
            # -------------------------------------------------

            if self.report_generator is not None:
                self.report_generator.save(
                    investigation
                )

        except Exception:
            investigation.status = (
                InvestigationStatus.FAILED
            )

            investigation.completed_at = (
                datetime.now()
            )

            raise

        return investigation

    def _evaluate_evidence(
        self,
        investigation: Investigation,
        evidence,
    ):
        """Evaluate evidence and store the result."""

        evaluation = (
            self.evidence_evaluator.evaluate(
                evidence
            )
        )

        investigation.evidence_evaluation = (
            EvidenceEvaluation(
                sufficient=(
                    evaluation.sufficient
                ),
                score=evaluation.score,
                reasons=evaluation.reasons,
                missing_evidence=(
                    evaluation.missing_evidence
                ),
            )
        )

        return evaluation

    def _select_escalation_step(
        self,
        investigation: Investigation,
    ):
        """
        Select an additional investigation action
        based on identified evidence gaps.
        """

        evaluation = (
            investigation.evidence_evaluation
        )

        missing = (
            evaluation.missing_evidence
            if evaluation
            else []
        )

        alert = investigation.alert

        # -------------------------------------------------
        # BEHAVIORAL EVIDENCE
        # -------------------------------------------------

        if (
            "BEHAVIORAL" in missing
            and alert.username
        ):
            return {
                "action": "LOG_SEARCH",
                "reason": (
                    "Behavioral evidence is insufficient. "
                    "Additional authentication log analysis "
                    "is required."
                ),
                "priority": "CRITICAL",
            }

        # -------------------------------------------------
        # THREAT INTELLIGENCE
        # -------------------------------------------------

        if (
            "THREAT_INTELLIGENCE" in missing
            and alert.source_ip
        ):
            return {
                "action": "IOC_LOOKUP",
                "reason": (
                    "Threat intelligence evidence is missing. "
                    "Additional IOC enrichment is required."
                ),
                "priority": "CRITICAL",
            }

        # -------------------------------------------------
        # ATTACK CONTEXT
        # -------------------------------------------------

        if (
            "ATTACK_CONTEXT" in missing
            and alert.rule
        ):
            return {
                "action": "MITRE_LOOKUP",
                "reason": (
                    "Attack-context evidence is missing. "
                    "Additional MITRE ATT&CK analysis is required."
                ),
                "priority": "HIGH",
            }

        # -------------------------------------------------
        # FALLBACK
        # -------------------------------------------------

        if (
            evaluation
            and not evaluation.sufficient
            and alert.username
        ):
            return {
                "action": "LOG_SEARCH",
                "reason": (
                    "Evidence remains insufficient. "
                    "Additional authentication log analysis "
                    "is required to strengthen the investigation."
                ),
                "priority": "HIGH",
            }

        return None