import json
import tempfile
import unittest
from pathlib import Path

from src.models.schemas import Confidence
from src.tools.mitre_tool import MITRETool


class TestMITRETool(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        self.data_path = Path(
            self.temp_dir.name
        ) / "enterprise-attack.json"

        dataset = {
            "objects": [
                {
                    "type": "attack-pattern",
                    "name": "Brute Force",
                    "description": (
                        "Adversaries may use brute force techniques "
                        "to gain access."
                    ),
                    "external_references": [
                        {
                            "external_id": "T1110",
                            "source_name": "mitre-attack",
                        }
                    ],
                    "kill_chain_phases": [
                        {
                            "phase_name": "credential-access"
                        }
                    ],
                }
            ]
        }

        self.data_path.write_text(
            json.dumps(dataset),
            encoding="utf-8",
        )

        self.tool = MITRETool(self.data_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_brute_force_lookup(self):
        result = self.tool.execute("Brute Force")

        self.assertEqual(len(result["matches"]), 1)

        match = result["matches"][0]

        self.assertEqual(
            match["technique_id"],
            "T1110",
        )

        self.assertEqual(
            match["name"],
            "Brute Force",
        )

        self.assertIn(
            "credential-access",
            match["tactics"],
        )

        self.assertEqual(
            result["evidence"].source,
            "MITRE ATT&CK",
        )

        self.assertEqual(
            result["evidence"].confidence,
            Confidence.HIGH,
        )

    def test_case_insensitive_lookup(self):
        result = self.tool.execute("brute force")

        self.assertEqual(
            result["matches"][0]["technique_id"],
            "T1110",
        )

    def test_unknown_rule(self):
        result = self.tool.execute(
            "Completely Unknown Detection"
        )

        self.assertEqual(
            result["matches"],
            [],
        )

        self.assertEqual(
            result["evidence"].relevance,
            "LOW",
        )

        self.assertEqual(
            result["evidence"].confidence,
            Confidence.LOW,
        )

    def test_empty_rule(self):
        with self.assertRaises(ValueError):
            self.tool.execute("")

    def test_missing_dataset(self):
        tool = MITRETool(
            Path(self.temp_dir.name) / "missing.json"
        )

        with self.assertRaises(FileNotFoundError):
            tool.execute("Brute Force")


if __name__ == "__main__":
    unittest.main()