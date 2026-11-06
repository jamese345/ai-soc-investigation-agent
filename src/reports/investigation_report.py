from pathlib import Path

from src.models.schemas import Investigation


class InvestigationReportGenerator:
    """Generates SOC investigation reports."""

    def __init__(self, output_dir=None):
        self.output_dir = Path(
            output_dir or "reports"
        )

        self.output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

    def generate(
        self,
        investigation: Investigation,
    ) -> str:
        """Generate a formatted SOC investigation report."""

        alert = investigation.alert

        lines = []

        # ============================================================
        # HEADER
        # ============================================================

        lines.append("# AI SOC Investigation Report")
        lines.append("")

        # ============================================================
        # INVESTIGATION SUMMARY
        # ============================================================

        lines.append("## Investigation Summary")
        lines.append("")

        lines.append(
            f"- **Investigation ID:** "
            f"{investigation.investigation_id}"
        )

        lines.append(
            f"- **Alert ID:** "
            f"{alert.alert_id}"
        )

        lines.append(
            f"- **Rule:** "
            f"{alert.rule}"
        )

        lines.append(
            f"- **Severity:** "
            f"{alert.severity.value}"
        )

        lines.append(
            f"- **Source IP:** "
            f"{alert.source_ip or 'N/A'}"
        )

        lines.append(
            f"- **Username:** "
            f"{alert.username or 'N/A'}"
        )

        lines.append(
            f"- **Failed Attempts:** "
            f"{alert.failed_attempts}"
        )

        lines.append(
            f"- **Status:** "
            f"{investigation.status.value}"
        )

        lines.append("")

        # ============================================================
        # INVESTIGATION PLAN
        # ============================================================

        lines.append("## Investigation Plan")
        lines.append("")

        if not investigation.plan:
            lines.append(
                "No investigation plan was generated."
            )
            lines.append("")
        else:
            for index, step in enumerate(
                investigation.plan,
                start=1,
            ):
                lines.append(
                    f"### Step {index}: "
                    f"{step.action}"
                )

                lines.append("")

                lines.append(
                    f"- **Priority:** "
                    f"{step.priority}"
                )

                lines.append(
                    f"- **Status:** "
                    f"{step.status}"
                )

                lines.append(
                    f"- **Reason:** "
                    f"{step.reason}"
                )

                lines.append("")

        # ============================================================
        # EVIDENCE EVALUATION
        # ============================================================

        lines.append("## Evidence Evaluation")
        lines.append("")

        evaluation = (
            investigation.evidence_evaluation
        )

        if evaluation is None:
            lines.append(
                "Evidence evaluation was not performed."
            )
            lines.append("")

        else:
            sufficient = (
                "YES"
                if evaluation.sufficient
                else "NO"
            )

            lines.append(
                f"- **Score:** "
                f"{evaluation.score}"
            )

            lines.append(
                f"- **Sufficient:** "
                f"{sufficient}"
            )

            lines.append("")

            # --------------------------------------------------------
            # Evaluation Reasons
            # --------------------------------------------------------

            if evaluation.reasons:
                lines.append(
                    "### Evaluation Reasons"
                )

                lines.append("")

                for reason in evaluation.reasons:
                    lines.append(
                        f"- {reason}"
                    )

                lines.append("")

            # --------------------------------------------------------
            # Missing Evidence
            # --------------------------------------------------------

            if evaluation.missing_evidence:
                lines.append(
                    "### Missing Evidence"
                )

                lines.append("")

                for missing in (
                    evaluation.missing_evidence
                ):
                    lines.append(
                        f"- {missing}"
                    )

                lines.append("")

            else:
                lines.append(
                    "**Missing Evidence:** None"
                )

                lines.append("")

        # ============================================================
        # FINDINGS
        # ============================================================

        lines.append("## Findings")
        lines.append("")

        if not investigation.findings:
            lines.append(
                "No findings were generated."
            )

            lines.append("")

        else:
            for index, finding in enumerate(
                investigation.findings,
                start=1,
            ):
                lines.append(
                    f"### Finding {index}: "
                    f"{finding.title}"
                )

                lines.append("")

                lines.append(
                    f"- **Severity:** "
                    f"{finding.severity.value}"
                )

                lines.append(
                    f"- **Confidence:** "
                    f"{finding.confidence.value}"
                )

                lines.append("")

                lines.append(
                    finding.description
                )

                lines.append("")

        # ============================================================
        # AI SOC ANALYSIS
        # ============================================================

        lines.append("## AI SOC Analysis")
        lines.append("")

        if investigation.reasoning is None:
            lines.append(
                "AI reasoning was not available."
            )

            lines.append("")

        else:
            reasoning = investigation.reasoning

            lines.append(
                f"**Summary:** "
                f"{reasoning.summary}"
            )

            lines.append("")

            lines.append(
                f"**Conclusion:** "
                f"{reasoning.conclusion}"
            )

            lines.append("")

            lines.append(
                f"- **Severity:** "
                f"{reasoning.severity.value}"
            )

            lines.append(
                f"- **Confidence:** "
                f"{reasoning.confidence.value}"
            )

            lines.append("")

            # --------------------------------------------------------
            # Key Findings
            # --------------------------------------------------------

            if reasoning.key_findings:
                lines.append(
                    "### Key Findings"
                )

                lines.append("")

                for finding in (
                    reasoning.key_findings
                ):
                    lines.append(
                        f"- {finding}"
                    )

                lines.append("")

            # --------------------------------------------------------
            # Recommended Actions
            # --------------------------------------------------------

            if reasoning.recommended_actions:
                lines.append(
                    "### Recommended Actions"
                )

                lines.append("")

                for action in (
                    reasoning.recommended_actions
                ):
                    lines.append(
                        f"- {action}"
                    )

                lines.append("")

        # ============================================================
        # SOC RECOMMENDATIONS
        # ============================================================

        lines.append("## SOC Recommendations")
        lines.append("")

        if not investigation.recommendations:
            lines.append(
                "No recommendations were generated."
            )

            lines.append("")

        else:
            for index, recommendation in enumerate(
                investigation.recommendations,
                start=1,
            ):
                lines.append(
                    f"{index}. "
                    f"**{recommendation.action}**"
                )

                lines.append(
                    f"   - Priority: "
                    f"{recommendation.priority}"
                )

                lines.append(
                    f"   - Reason: "
                    f"{recommendation.reason}"
                )

                lines.append("")

        return "\n".join(lines)

    def save(
        self,
        investigation: Investigation,
        output_path=None,
    ) -> Path:
        """Generate and save the investigation report."""

        report = self.generate(
            investigation
        )

        if output_path is None:
            output_path = (
                self.output_dir
                / (
                    f"{investigation.investigation_id}"
                    ".md"
                )
            )

        else:
            output_path = Path(
                output_path
            )

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        output_path.write_text(
            report,
            encoding="utf-8",
        )

        return output_path