from datetime import datetime

from src.agent.investigation import InvestigationAgent
from src.agent.reasoner import InvestigationReasoner
from src.models.schemas import Alert, Severity
from src.rag.knowledge_retriever import KnowledgeRetriever
from src.reports.investigation_report import InvestigationReportGenerator


def main():
    alert = Alert(
        alert_id="ALT-001",
        rule="Brute Force",
        severity=Severity.HIGH,
        source_ip="185.10.10.20",
        username="admin",
        failed_attempts=35,
        timestamp=datetime.now(),
    )

    retriever = KnowledgeRetriever()

    reasoner = InvestigationReasoner(
        retriever=retriever
    )

    report_generator = InvestigationReportGenerator()

    agent = InvestigationAgent(
        reasoner=reasoner,
        report_generator=report_generator,
    )

    investigation = agent.investigate(alert)

    print("\n" + "=" * 60)
    print("AI SOC INVESTIGATION")
    print("=" * 60)

    print(
        f"\nInvestigation ID: "
        f"{investigation.investigation_id}"
    )
    print(
        f"Alert ID: "
        f"{investigation.alert.alert_id}"
    )
    print(
        f"Rule: "
        f"{investigation.alert.rule}"
    )
    print(
        f"Severity: "
        f"{investigation.alert.severity.value}"
    )
    print(
        f"Status: "
        f"{investigation.status.value}"
    )

    print("\n--- FINDINGS ---")

    for index, finding in enumerate(
        investigation.findings,
        start=1,
    ):
        print(f"\nFinding {index}")
        print(
            f"Source: "
            f"{finding.evidence[0].source}"
        )
        print(
            f"Description: "
            f"{finding.description}"
        )
        print(
            f"Severity: "
            f"{finding.severity.value}"
        )
        print(
            f"Confidence: "
            f"{finding.confidence.value}"
        )

    if investigation.reasoning:
        reasoning = investigation.reasoning

        print("\n" + "-" * 60)
        print("AI SOC ANALYSIS")
        print("-" * 60)

        print(
            f"\nSummary:\n"
            f"{reasoning.summary}"
        )

        print(
            f"\nConclusion:\n"
            f"{reasoning.conclusion}"
        )

        print(
            f"\nSeverity: "
            f"{reasoning.severity.value}"
        )

        print(
            f"Confidence: "
            f"{reasoning.confidence.value}"
        )

        print("\nKey Findings:")

        for item in reasoning.key_findings:
            print(f"- {item}")

        print("\nRecommended Actions:")

        for action in reasoning.recommended_actions:
            print(f"- {action}")

    print("\n" + "-" * 60)
    print("SOC REPORT")
    print("-" * 60)

    report_path = (
        f"reports/"
        f"{investigation.investigation_id}.md"
    )

    print(
        f"\nReport generated: "
        f"{report_path}"
    )

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()