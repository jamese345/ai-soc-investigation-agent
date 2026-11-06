from pathlib import Path

import pandas as pd

from src.tools.base import InvestigationTool
from src.models.schemas import Confidence, Evidence


class LogSearchTool(InvestigationTool):
    """Searches security logs for investigation evidence."""

    name = "log_search"

    description = (
        "Searches security event logs for activity associated "
        "with a username."
    )

    def __init__(self, log_path=None):
        self.log_path = Path(
            log_path or "data/logs/security_events.csv"
        )

    def execute(self, username: str):
        if not username:
            raise ValueError("Username cannot be empty.")

        if not self.log_path.exists():
            raise FileNotFoundError(
                f"Log file not found: {self.log_path}"
            )

        try:
            logs = pd.read_csv(self.log_path)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to read security logs: {exc}"
            ) from exc

        if "username" not in logs.columns:
            raise ValueError(
                "Security log is missing the 'username' column."
            )

        matches = logs[
            logs["username"].astype(str).str.lower()
            == username.lower()
        ]

        if matches.empty:
            return {
                "matches": 0,
                "evidence": Evidence(
                    source="Security Logs",
                    description=(
                        f"No security events were found for "
                        f"username '{username}'."
                    ),
                    relevance="LOW",
                    confidence=Confidence.MEDIUM,
                ),
            }

        failed_events = 0

        if "status" in matches.columns:
            failed_events = int(
                (matches["status"].astype(str).str.lower() == "failed")
                .sum()
            )

        source_ips = []

        if "src_ip" in matches.columns:
            source_ips = sorted(
                matches["src_ip"]
                .dropna()
                .astype(str)
                .unique()
                .tolist()
            )

        description = (
            f"Found {len(matches)} security events for username "
            f"'{username}'. "
            f"{failed_events} events were failed authentication attempts. "
            f"Associated source IPs: "
            f"{', '.join(source_ips) if source_ips else 'None'}."
        )

        evidence = Evidence(
            source="Security Logs",
            description=description,
            relevance="HIGH" if failed_events > 0 else "MEDIUM",
            confidence=Confidence.HIGH,
        )

        return {
            "matches": len(matches),
            "failed_events": failed_events,
            "source_ips": source_ips,
            "evidence": evidence,
        }