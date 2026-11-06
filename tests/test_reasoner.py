
import json
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

from src.agent.reasoner import InvestigationReasoner
from src.models.schemas import (
    Alert,
    Confidence,
    Evidence,
    Finding,
    Investigation,
    InvestigationStatus,
    Severity,
)


class TestInvestigationReasoner(unittest.TestCase):

    def _create_investigation(self):
        alert = Alert(
            alert_id="ALT-TEST",
            rule="Brute Force",
            severity=Severity.HIGH,
            source_ip="185.10.10.20",
            username="admin",
            failed_attempts=12,
            timestamp=datetime.now(),
        )

        evidence = Evidence(
            source="Security Logs",
            description=(
                "Multiple failed authentication attempts "
                "were observed."
            ),
            relevance="HIGH",
            confidence=Confidence.HIGH,
        )

        finding = Finding(
            title="Brute-force activity",
            description=(
                "Multiple failed authentication attempts "
                "were observed."
            ),
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            evidence=[evidence],
        )

        return Investigation(
            investigation_id="INV-TEST",
            alert=alert,
            status=InvestigationStatus.IN_PROGRESS,
            findings=[finding],
        )

    def _create_llm_response(self):
        mock_response = MagicMock()

        mock_response.output_text = json.dumps(
            {
                "summary": (
                    "Multiple failed authentication attempts "
                    "were observed."
                ),
                "conclusion": (
                    "The evidence is consistent with a "
                    "brute-force attack."
                ),
                "severity": "HIGH",
                "confidence": "HIGH",
                "key_findings": [
                    "Three failed authentication events "
                    "were observed.",
                    "The activity originated from the "
                    "same source IP.",
                ],
                "recommended_actions": [
                    "Review the affected account.",
                    "Monitor the source IP for "
                    "additional activity.",
                ],
            }
        )

        return mock_response

    @patch("src.agent.reasoner.OpenAI")
    def test_reasoning_result(self, mock_openai):
        mock_client = MagicMock()

        mock_client.responses.create.return_value = (
            self._create_llm_response()
        )

        mock_openai.return_value = mock_client

        reasoner = InvestigationReasoner()

        investigation = self._create_investigation()

        result = reasoner.analyze(
            investigation
        )

        self.assertEqual(
            result.severity,
            Severity.HIGH,
        )

        self.assertEqual(
            result.confidence,
            Confidence.HIGH,
        )

        self.assertEqual(
            len(result.key_findings),
            2,
        )

        self.assertEqual(
            len(result.recommended_actions),
            2,
        )

        mock_client.responses.create.assert_called_once()

    @patch("src.agent.reasoner.OpenAI")
    def test_reasoner_uses_retriever(
        self,
        mock_openai,
    ):
        mock_client = MagicMock()

        mock_client.responses.create.return_value = (
            self._create_llm_response()
        )

        mock_openai.return_value = mock_client

        retriever = MagicMock()

        retriever.retrieve.return_value = [
            {
                "source": "brute_force.md",
                "content": (
                    "Multiple failed login attempts "
                    "can indicate brute force activity."
                ),
                "score": 5,
            }
        ]

        reasoner = InvestigationReasoner(
            retriever=retriever
        )

        investigation = self._create_investigation()

        result = reasoner.analyze(
            investigation
        )

        self.assertEqual(
            result.severity,
            Severity.HIGH,
        )

        retriever.retrieve.assert_called_once()

        retrieval_query = (
            retriever.retrieve.call_args.args[0]
        )

        self.assertIn(
            "Brute Force",
            retrieval_query,
        )

        self.assertIn(
            "failed authentication",
            retrieval_query,
        )

    @patch("src.agent.reasoner.OpenAI")
    def test_rate_limit_error_is_handled(
        self,
        mock_openai,
    ):
        from openai import RateLimitError

        mock_client = MagicMock()

        mock_client.responses.create.side_effect = (
            RateLimitError(
                "No credits remaining",
                response=MagicMock(),
                body=None,
            )
        )

        mock_openai.return_value = mock_client

        reasoner = InvestigationReasoner()

        investigation = self._create_investigation()

        with self.assertRaises(RuntimeError) as context:
            reasoner.analyze(
                investigation
            )

        self.assertIn(
            "API rate limit or account credit limit reached",
            str(context.exception),
        )

    @patch("src.agent.reasoner.OpenAI")
    def test_invalid_json_is_handled(
        self,
        mock_openai,
    ):
        mock_client = MagicMock()

        mock_response = MagicMock()

        mock_response.output_text = (
            "This is not valid JSON."
        )

        mock_client.responses.create.return_value = (
            mock_response
        )

        mock_openai.return_value = mock_client

        reasoner = InvestigationReasoner()

        investigation = self._create_investigation()

        with self.assertRaises(RuntimeError) as context:
            reasoner.analyze(
                investigation
            )

        self.assertEqual(
            str(context.exception),
            "LLM returned invalid JSON.",
        )

    @patch("src.agent.reasoner.OpenAI")
    def test_api_connection_error_is_handled(
        self,
        mock_openai,
    ):
        from openai import APIConnectionError

        mock_client = MagicMock()

        mock_client.responses.create.side_effect = (
            APIConnectionError(
                request=MagicMock()
            )
        )

        mock_openai.return_value = mock_client

        reasoner = InvestigationReasoner()

        investigation = self._create_investigation()

        with self.assertRaises(RuntimeError) as context:
            reasoner.analyze(
                investigation
            )

        self.assertIn(
            "could not connect to the OpenAI API",
            str(context.exception),
        )


if __name__ == "__main__":
    unittest.main()