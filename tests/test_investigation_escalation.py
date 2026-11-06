import unittest

from src.agent.investigation import InvestigationAgent
from src.models.schemas import (
    Alert,
    Severity,
)


class TestInvestigationEscalation(unittest.TestCase):

    def create_alert(self):
        return Alert(
            alert_id="ALT-ESC-001",
            rule="Brute Force",
            severity=Severity.HIGH,
            source_ip="185.10.10.20",
            username="admin",
            failed_attempts=20,
            timestamp="2026-11-06T10:00:00",
        )

    def test_escalation_step_is_selected_when_evidence_is_insufficient(self):
        agent = InvestigationAgent()

        class FakeEvaluator:
            def __init__(self):
                self.calls = 0

            def evaluate(self, evidence):
                self.calls += 1

                from src.agent.evidence_evaluator import (
                    EvidenceEvaluation,
                )

                if self.calls == 1:
                    return EvidenceEvaluation(
                        sufficient=False,
                        score=10,
                        reasons=[
                            "Evidence is insufficient."
                        ],
                    )

                return EvidenceEvaluation(
                    sufficient=True,
                    score=60,
                    reasons=[
                        "Additional evidence improved coverage."
                    ],
                )

        agent.evidence_evaluator = FakeEvaluator()

        investigation = agent.investigate(
            self.create_alert()
        )

        self.assertGreaterEqual(
            len(investigation.plan),
            4,
        )

        self.assertTrue(
            investigation.evidence_evaluation.sufficient
        )

    def test_escalation_is_limited_to_one_round(self):
        agent = InvestigationAgent()

        class AlwaysInsufficientEvaluator:
            def evaluate(self, evidence):
                from src.agent.evidence_evaluator import (
                    EvidenceEvaluation,
                )

                return EvidenceEvaluation(
                    sufficient=False,
                    score=5,
                    reasons=[
                        "Evidence remains insufficient."
                    ],
                )

        agent.evidence_evaluator = (
            AlwaysInsufficientEvaluator()
        )

        investigation = agent.investigate(
            self.create_alert()
        )

        self.assertEqual(
            len(investigation.plan),
            4,
        )

        self.assertFalse(
            investigation.evidence_evaluation.sufficient
        )

    def test_behavioral_gap_selects_log_search(self):
        agent = InvestigationAgent()

        class FakeEvaluator:
            def evaluate(self, evidence):
                from src.agent.evidence_evaluator import (
                    EvidenceEvaluation,
                )

                return EvidenceEvaluation(
                    sufficient=False,
                    score=20,
                    reasons=[
                        "Behavioral evidence is missing."
                    ],
                    missing_evidence=[
                        "BEHAVIORAL"
                    ],
                )

        agent.evidence_evaluator = FakeEvaluator()

        investigation = agent.investigate(
            self.create_alert()
        )

        actions = [
            step.action
            for step in investigation.plan
        ]

        self.assertIn(
            "LOG_SEARCH",
            actions,
        )


    def test_threat_intelligence_gap_selects_ioc_lookup(self):
        agent = InvestigationAgent()

        class FakeEvaluator:
            def evaluate(self, evidence):
                from src.agent.evidence_evaluator import (
                    EvidenceEvaluation,
                )

                return EvidenceEvaluation(
                    sufficient=False,
                    score=20,
                    reasons=[
                        "Threat intelligence is missing."
                    ],
                    missing_evidence=[
                        "THREAT_INTELLIGENCE"
                    ],
                )

        agent.evidence_evaluator = FakeEvaluator()

        investigation = agent.investigate(
            self.create_alert()
        )

        actions = [
            step.action
            for step in investigation.plan
        ]

        self.assertIn(
            "IOC_LOOKUP",
            actions,
        )


if __name__ == "__main__":
    unittest.main()