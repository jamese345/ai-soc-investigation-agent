import unittest

from src.models.schemas import Confidence, IOCResult, Severity
from src.tools.evidence_builder import ioc_result_to_evidence


class TestEvidenceBuilder(unittest.TestCase):

    def test_malicious_ioc_conversion(self):
        result = IOCResult(
            ioc="185.10.10.20",
            ioc_type="IPv4",
            reputation="Malicious",
            risk=Severity.CRITICAL,
            confidence=Confidence.VERY_HIGH,
            sources=["AlienVault OTX"],
        )

        evidence = ioc_result_to_evidence(result)

        self.assertEqual(evidence.source, "AlienVault OTX")
        self.assertEqual(evidence.confidence, Confidence.VERY_HIGH)
        self.assertIn("185.10.10.20", evidence.description)
        self.assertIn("Malicious", evidence.description)
        self.assertIn("CRITICAL", evidence.description)

    def test_suspicious_ioc_conversion(self):
        result = IOCResult(
            ioc="malicious-example.com",
            ioc_type="domain",
            reputation="Suspicious",
            risk=Severity.HIGH,
            confidence=Confidence.HIGH,
            sources=["AlienVault OTX"],
        )

        evidence = ioc_result_to_evidence(result)

        self.assertEqual(evidence.source, "AlienVault OTX")
        self.assertEqual(evidence.relevance, "HIGH")
        self.assertEqual(evidence.confidence, Confidence.HIGH)
        self.assertIn("Suspicious", evidence.description)

    def test_low_risk_ioc_conversion(self):
        result = IOCResult(
            ioc="8.8.8.8",
            ioc_type="IPv4",
            reputation="No known malicious pulses",
            risk=Severity.LOW,
            confidence=Confidence.MEDIUM,
            sources=["AlienVault OTX"],
        )

        evidence = ioc_result_to_evidence(result)

        self.assertEqual(evidence.relevance, "LOW")
        self.assertEqual(evidence.confidence, Confidence.MEDIUM)
        self.assertIn("8.8.8.8", evidence.description)


if __name__ == "__main__":
    unittest.main()