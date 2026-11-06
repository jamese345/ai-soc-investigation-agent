import json
from pathlib import Path

from src.models.schemas import Confidence, Evidence
from src.tools.base import InvestigationTool


class MITRETool(InvestigationTool):
    name = "mitre_lookup"

    description = (
        "Maps security alert rules to MITRE ATT&CK techniques "
        "and provides tactical context."
    )

    def __init__(self, data_path=None):
        self.data_path = Path(
            data_path or "data/knowledge/enterprise-attack.json"
        )

    def execute(self, rule: str):
        if not rule:
            raise ValueError("Rule cannot be empty.")

        if not self.data_path.exists():
            raise FileNotFoundError(
                f"MITRE ATT&CK dataset not found: {self.data_path}"
            )

        try:
            with self.data_path.open("r", encoding="utf-8") as file:
                data = json.load(file)

        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Invalid MITRE ATT&CK JSON: {exc}"
            ) from exc

        rule_normalized = rule.strip().lower()

        exact_matches = []
        name_matches = []
        description_matches = []

        for technique in data.get("objects", []):

            if technique.get("type") != "attack-pattern":
                continue

            name = technique.get("name", "")
            description = technique.get("description", "")

            name_normalized = name.lower()
            description_normalized = description.lower()

            match = {
                "technique_id": self._get_external_id(technique),
                "name": name,
                "tactics": self._get_tactics(technique),
            }

            # Highest confidence: exact technique name.
            if name_normalized == rule_normalized:
                exact_matches.append(match)

            # Second priority: rule appears in technique name.
            elif rule_normalized in name_normalized:
                name_matches.append(match)

            # Lowest priority: rule only appears in description.
            elif rule_normalized in description_normalized:
                description_matches.append(match)

        # Prefer exact technique-name matches.
        if exact_matches:
            matches = exact_matches

        elif name_matches:
            matches = name_matches

        else:
            matches = description_matches

        if not matches:
            return {
                "matches": [],
                "evidence": Evidence(
                    source="MITRE ATT&CK",
                    description=(
                        f"No MITRE ATT&CK technique was directly "
                        f"identified for rule '{rule}'."
                    ),
                    relevance="LOW",
                    confidence=Confidence.LOW,
                ),
            }

        primary = matches[0]

        tactic_text = (
            ", ".join(primary["tactics"])
            if primary["tactics"]
            else "Unknown"
        )

        description = (
            f"Rule '{rule}' maps to MITRE ATT&CK technique "
            f"{primary['technique_id']} ({primary['name']}). "
            f"Associated tactic(s): {tactic_text}."
        )

        evidence = Evidence(
            source="MITRE ATT&CK",
            description=description,
            relevance="HIGH",
            confidence=Confidence.HIGH,
        )

        return {
            "matches": matches,
            "evidence": evidence,
        }

    @staticmethod
    def _get_external_id(technique):
        for reference in technique.get("external_references", []):
            external_id = reference.get("external_id")

            if external_id and external_id.startswith("T"):
                return external_id

        return "Unknown"

    @staticmethod
    def _get_tactics(technique):
        return [
            tactic.get("phase_name")
            for tactic in technique.get("kill_chain_phases", [])
            if tactic.get("phase_name")
        ]