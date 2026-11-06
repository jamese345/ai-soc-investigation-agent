import unittest
from unittest.mock import Mock

from src.models.schemas import Confidence, Severity
from src.tools.ioc_tool import IOCTool


class TestIOCTool(unittest.TestCase):

    def test_tool_metadata(self):
        mock_lookup = Mock()
        tool = IOCTool(lookup_client=mock_lookup)

        self.assertEqual(tool.name, "ioc_lookup")
        self.assertIn("AlienVault OTX", tool.description)

    def test_execute_returns_ioc_result_and_evidence(self):
        mock_lookup = Mock()

        mock_result = Mock()
        mock_result.ioc = "185.10.10.20"
        mock_result.ioc_type = "IPv4"
        mock_result.reputation = "Malicious"
        mock_result.risk = Severity.CRITICAL
        mock_result.confidence = Confidence.VERY_HIGH
        mock_result.sources = ["AlienVault OTX"]

        mock_lookup.lookup.return_value = mock_result

        tool = IOCTool(lookup_client=mock_lookup)

        response = tool.execute(ioc="185.10.10.20")

        mock_lookup.lookup.assert_called_once_with("185.10.10.20")

        self.assertIn("ioc_result", response)
        self.assertIn("evidence", response)

        self.assertEqual(
            response["ioc_result"].ioc,
            "185.10.10.20",
        )

        self.assertEqual(
            response["evidence"].source,
            "AlienVault OTX",
        )

        self.assertEqual(
            response["evidence"].confidence,
            Confidence.VERY_HIGH,
        )

    def test_execute_propagates_lookup_error(self):
        mock_lookup = Mock()
        mock_lookup.lookup.side_effect = RuntimeError(
            "OTX API authentication failed."
        )

        tool = IOCTool(lookup_client=mock_lookup)

        with self.assertRaises(RuntimeError):
            tool.execute(ioc="185.10.10.20")


if __name__ == "__main__":
    unittest.main()