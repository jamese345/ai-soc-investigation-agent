import unittest

from src.agent.evidence_evaluator import EvidenceEvaluator
from src.models.schemas import (
    Confidence,
    Evidence,
)


class TestEvidenceEvaluator(unittest.TestCase):

    def setUp(self):
        self.evaluator = EvidenceEvaluator()

    def test_no_evidence_requires_escalation(self):
        result = self.evaluator.evaluate([])

        self.assertFalse(result.sufficient)
        self.assertEqual(result.score, 0)

    def test_strong_multi_source_evidence_is_sufficient(self):
        evidence = [
            Evidence(
                source="Security Logs",
                description="Multiple failed authentication attempts.",
                relevance="HIGH",
                confidence=Confidence.HIGH,
            ),
            Evidence(
                source="MITRE ATT&CK",
                description="Brute Force maps to T1110.",
                relevance="HIGH",
                confidence=Confidence.HIGH,
            ),
            Evidence(
                source="AlienVault OTX",
                description="IOC reputation checked.",
                relevance="MEDIUM",
                confidence=Confidence.MEDIUM,
            ),
        ]

        result = self.evaluator.evaluate(evidence)

        self.assertTrue(result.sufficient)
        self.assertGreaterEqual(
            result.score,
            EvidenceEvaluator.SUFFICIENT_SCORE,
        )

    def test_low_quality_single_source_may_require_escalation(self):
        evidence = [
            Evidence(
                source="AlienVault OTX",
                description="No known malicious activity.",
                relevance="LOW",
                confidence=Confidence.LOW,
            )
        ]

        result = self.evaluator.evaluate(evidence)

        self.assertFalse(result.sufficient)

    def test_multiple_sources_receive_coverage_bonus(self):
        evidence = [
            Evidence(
                source="Security Logs",
                description="Failed login activity.",
                relevance="HIGH",
                confidence=Confidence.HIGH,
            ),
            Evidence(
                source="MITRE ATT&CK",
                description="Technique identified.",
                relevance="HIGH",
                confidence=Confidence.HIGH,
            ),
        ]

        result = self.evaluator.evaluate(evidence)

        self.assertIn(
            "Evidence was collected from multiple sources.",
            result.reasons,
        )

    def test_missing_behavioral_evidence_is_identified(self):
        evidence = [
            Evidence(
                source="AlienVault OTX",
                description="IOC reputation checked.",
                relevance="MEDIUM",
                confidence=Confidence.MEDIUM,
            )
        ]

        result = self.evaluator.evaluate(evidence)

        self.assertIn(
            "BEHAVIORAL",
            result.missing_evidence,
        )


    def test_missing_threat_intelligence_is_identified(self):
        evidence = [
            Evidence(
                source="Security Logs",
                description="Authentication activity found.",
                relevance="HIGH",
                confidence=Confidence.HIGH,
            )
        ]

        result = self.evaluator.evaluate(evidence)

        self.assertIn(
            "THREAT_INTELLIGENCE",
            result.missing_evidence,
        )


    def test_missing_attack_context_is_identified(self):
        evidence = [
            Evidence(
                source="Security Logs",
                description="Authentication activity found.",
                relevance="HIGH",
                confidence=Confidence.HIGH,
            ),
            Evidence(
                source="AlienVault OTX",
                description="IOC reputation checked.",
                relevance="MEDIUM",
                confidence=Confidence.MEDIUM,
            ),
        ]

        result = self.evaluator.evaluate(evidence)

        self.assertIn(
            "ATTACK_CONTEXT",
            result.missing_evidence,
        )


if __name__ == "__main__":
    unittest.main()