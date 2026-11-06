import unittest
from unittest.mock import Mock, patch

from src.models.schemas import Confidence, Severity
from src.tools.ioc_lookup import IOCLookup


class TestIOCLookup(unittest.TestCase):

    def setUp(self):
        self.lookup = IOCLookup(
            api_key="test-api-key"
        )

    @patch("src.tools.ioc_lookup.requests.get")
    def test_malicious_ioc(self, mock_get):
        mock_response = Mock()
        mock_response.ok = True
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pulse_info": {
                "count": 8
            }
        }

        mock_get.return_value = mock_response

        result = self.lookup.lookup(
            "185.10.10.20"
        )

        self.assertEqual(
            result.ioc,
            "185.10.10.20"
        )

        self.assertEqual(
            result.ioc_type,
            "IPv4"
        )

        self.assertEqual(
            result.risk,
            Severity.CRITICAL
        )

        self.assertEqual(
            result.confidence,
            Confidence.VERY_HIGH
        )

    @patch("src.tools.ioc_lookup.requests.get")
    def test_suspicious_ioc(self, mock_get):
        mock_response = Mock()
        mock_response.ok = True
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pulse_info": {
                "count": 3
            }
        }

        mock_get.return_value = mock_response

        result = self.lookup.lookup(
            "malicious-example.com"
        )

        self.assertEqual(
            result.ioc_type,
            "domain"
        )

        self.assertEqual(
            result.reputation,
            "Suspicious"
        )

        self.assertEqual(
            result.risk,
            Severity.HIGH
        )

    @patch("src.tools.ioc_lookup.requests.get")
    def test_unknown_ioc(self, mock_get):
        mock_response = Mock()
        mock_response.ok = True
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pulse_info": {
                "count": 0
            }
        }

        mock_get.return_value = mock_response

        result = self.lookup.lookup(
            "8.8.8.8"
        )

        self.assertEqual(
            result.risk,
            Severity.LOW
        )

        self.assertEqual(
            result.confidence,
            Confidence.MEDIUM
        )

    @patch("src.tools.ioc_lookup.requests.get")
    def test_api_authentication_failure(self, mock_get):
        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 401

        mock_get.return_value = mock_response

        with self.assertRaises(RuntimeError):
            self.lookup.lookup(
                "185.10.10.20"
            )

    def test_empty_ioc(self):
        with self.assertRaises(ValueError):
            self.lookup.lookup("")


if __name__ == "__main__":
    unittest.main()