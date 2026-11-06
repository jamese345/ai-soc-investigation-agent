import tempfile
import unittest
from pathlib import Path

from src.models.schemas import Confidence
from src.tools.log_search import LogSearchTool


class TestLogSearchTool(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        self.log_path = Path(self.temp_dir.name) / "security_events.csv"

        self.log_path.write_text(
            """timestamp,src_ip,username,event_type,status,failed_attempts
2026-11-06T09:42:11,185.10.10.20,admin,login,failed,12
2026-11-06T09:43:02,185.10.10.20,admin,login,failed,8
2026-11-06T09:44:18,185.10.10.20,admin,login,success,0
2026-11-06T09:50:31,10.0.0.15,john,login,success,0
""",
            encoding="utf-8",
        )

        self.tool = LogSearchTool(self.log_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_admin_activity(self):
        result = self.tool.execute("admin")

        self.assertEqual(result["matches"], 3)
        self.assertEqual(result["failed_events"], 2)
        self.assertEqual(
            result["source_ips"],
            ["185.10.10.20"],
        )

        self.assertEqual(
            result["evidence"].source,
            "Security Logs",
        )

        self.assertEqual(
            result["evidence"].confidence,
            Confidence.HIGH,
        )

        self.assertIn(
            "2 events were failed authentication attempts",
            result["evidence"].description,
        )

    def test_username_case_insensitive(self):
        result = self.tool.execute("ADMIN")

        self.assertEqual(result["matches"], 3)

    def test_unknown_user(self):
        result = self.tool.execute("unknown-user")

        self.assertEqual(result["matches"], 0)
        self.assertEqual(
            result["evidence"].relevance,
            "LOW",
        )

        self.assertIn(
            "No security events",
            result["evidence"].description,
        )

    def test_empty_username(self):
        with self.assertRaises(ValueError):
            self.tool.execute("")

    def test_missing_log_file(self):
        tool = LogSearchTool(
            Path(self.temp_dir.name) / "missing.csv"
        )

        with self.assertRaises(FileNotFoundError):
            tool.execute("admin")


if __name__ == "__main__":
    unittest.main()