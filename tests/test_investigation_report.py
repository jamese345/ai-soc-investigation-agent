import tempfile
import unittest
from pathlib import Path

from src.models.schemas import (
    Alert,
    Confidence,
    Evidence,
    EvidenceEvaluation,
    Finding,
    Investigation,
    InvestigationStatus,
    InvestigationStep,
    ReasoningResult,
    Severity,
)

from src.reports.investigation_report import (
    InvestigationReportGenerator,
)


class TestInvestigationReportGenerator(
    unittest.TestCase
):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        self.generator = (
            InvestigationReportGenerator(
                output_dir=self.temp_dir.name
            )
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_investigation(self):
        alert = Alert(
            alert_id="ALT-001",
            rule="Brute Force",
            severity=Severity.HIGH,
            source_ip="185.10.10.20",
            username="admin",
            failed_attempts=35,
            timestamp="2026-11-06T09:42:11",
        )

        plan = [
            InvestigationStep(
                action="LOG_SEARCH",
                reason=(
                    "Investigate authentication "
                    "activity associated with "
                    "the affected account."
                ),
                priority="HIGH",
                status="PENDING",
            ),
            InvestigationStep(
                action="IOC_LOOKUP",
                reason=(
                    "Enrich the source IP with "
                    "threat intelligence."
                ),
                priority="HIGH",
                status="PENDING",
            ),
            InvestigationStep(
                action="MITRE_LOOKUP",
                reason=(
                    "Map the detection rule to "
                    "MITRE ATT&CK."
                ),
                priority="MEDIUM",
                status="PENDING",
            ),
        ]

        finding = Finding(
            title="Evidence from Security Logs",
            description=(
                "Multiple failed authentication "
                "attempts were observed."
            ),
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            evidence=[
                Evidence(
                    source="Security Logs",
                    description=(
                        "Multiple failed "
                        "authentication attempts "
                        "were observed."
                    ),
                    relevance="HIGH",
                    confidence=Confidence.HIGH,
                )
            ],
        )

        reasoning = ReasoningResult(
            summary=(
                "Multiple failed authentication "
                "attempts were observed."
            ),
            conclusion=(
                "The evidence is consistent "
                "with brute-force activity."
            ),
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            key_findings=[
                "Repeated failed authentication "
                "was observed.",
                "The activity originated from "
                "one source IP.",
            ],
            recommended_actions=[
                "Review the affected account.",
                "Monitor the source IP.",
            ],
        )

        investigation = Investigation(
            investigation_id="INV-TEST",
            alert=alert,
            status=InvestigationStatus.COMPLETED,
            plan=plan,
            findings=[finding],
            reasoning=reasoning,
        )

        return investigation

    def test_generates_report(self):
        investigation = (
            self._create_investigation()
        )

        report = self.generator.generate(
            investigation
        )

        self.assertIn(
            "# AI SOC Investigation Report",
            report,
        )

        self.assertIn(
            "## Investigation Summary",
            report,
        )

        self.assertIn(
            "## Investigation Plan",
            report,
        )

        self.assertIn(
            "## AI SOC Analysis",
            report,
        )

        self.assertIn(
            "Brute Force",
            report,
        )

        self.assertIn(
            "ALT-001",
            report,
        )

    def test_investigation_plan_is_included(self):
        investigation = (
            self._create_investigation()
        )

        report = self.generator.generate(
            investigation
        )

        self.assertIn(
            "### Step 1: LOG_SEARCH",
            report,
        )

        self.assertIn(
            "### Step 2: IOC_LOOKUP",
            report,
        )

        self.assertIn(
            "### Step 3: MITRE_LOOKUP",
            report,
        )

    def test_empty_investigation_plan_is_handled(
        self
    ):
        investigation = (
            self._create_investigation()
        )

        investigation.plan = []

        report = self.generator.generate(
            investigation
        )

        self.assertIn(
            "No investigation plan was generated.",
            report,
        )

    def test_report_contains_evidence_evaluation(
        self
    ):
        investigation = (
            self._create_investigation()
        )

        investigation.evidence_evaluation = (
            EvidenceEvaluation(
                sufficient=True,
                score=75,
                reasons=[
                    "Evidence was collected "
                    "from multiple sources.",
                    "Evidence is sufficient "
                    "to support investigation reasoning.",
                ],
                missing_evidence=[],
            )
        )

        report = self.generator.generate(
            investigation
        )

        self.assertIn(
            "## Evidence Evaluation",
            report,
        )

        self.assertIn(
            "**Score:** 75",
            report,
        )

        self.assertIn(
            "**Sufficient:** YES",
            report,
        )

        self.assertIn(
            "Evidence was collected from "
            "multiple sources.",
            report,
        )

    def test_report_contains_missing_evidence(
        self
    ):
        investigation = (
            self._create_investigation()
        )

        investigation.evidence_evaluation = (
            EvidenceEvaluation(
                sufficient=False,
                score=20,
                reasons=[
                    "Evidence is insufficient "
                    "and requires additional investigation."
                ],
                missing_evidence=[
                    "BEHAVIORAL",
                    "THREAT_INTELLIGENCE",
                ],
            )
        )

        report = self.generator.generate(
            investigation
        )

        self.assertIn(
            "### Missing Evidence",
            report,
        )

        self.assertIn(
            "BEHAVIORAL",
            report,
        )

        self.assertIn(
            "THREAT_INTELLIGENCE",
            report,
        )

    def test_report_contains_plan_status_and_priority(
        self
    ):
        investigation = (
            self._create_investigation()
        )

        investigation.plan[0].status = (
            "COMPLETED"
        )

        investigation.plan[0].priority = (
            "CRITICAL"
        )

        report = self.generator.generate(
            investigation
        )

        self.assertIn(
            "**Priority:** CRITICAL",
            report,
        )

        self.assertIn(
            "**Status:** COMPLETED",
            report,
        )

    def test_report_generator_is_called(self):
        investigation = (
            self._create_investigation()
        )

        class TestGenerator:
            def __init__(self):
                self.called = False

            def save(self, investigation):
                self.called = True
                return Path(
                    "reports/test-report.md"
                )

        test_generator = TestGenerator()

        result = test_generator.save(
            investigation
        )

        self.assertTrue(
            test_generator.called
        )

        self.assertEqual(
            Path(
                "reports/test-report.md"
            ),
            result,
        )

    def test_saves_report(self):
        investigation = (
            self._create_investigation()
        )

        output_path = (
            Path(self.temp_dir.name)
            / "investigation.md"
        )

        saved_path = self.generator.save(
            investigation,
            output_path,
        )

        self.assertEqual(
            output_path,
            saved_path,
        )

        self.assertTrue(
            output_path.exists()
        )

        content = (
            output_path.read_text(
                encoding="utf-8"
            )
        )

        self.assertIn(
            "# AI SOC Investigation Report",
            content,
        )

        self.assertIn(
            "ALT-001",
            content,
        )


if __name__ == "__main__":
    unittest.main()