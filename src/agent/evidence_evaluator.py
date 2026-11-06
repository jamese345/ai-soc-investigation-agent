from typing import List, Optional

from src.models.schemas import (
    Confidence,
    Evidence,
)


class EvidenceEvaluation:
    """Represents the result of evaluating investigation evidence."""

    def __init__(
        self,
        sufficient: bool,
        score: int,
        reasons: List[str],
        missing_evidence: Optional[List[str]] = None,
    ):
        self.sufficient = sufficient
        self.score = score
        self.reasons = reasons
        self.missing_evidence = (
            missing_evidence
            if missing_evidence is not None
            else []
        )


class EvidenceEvaluator:
    """Evaluates investigation evidence and identifies evidence gaps."""

    CONFIDENCE_SCORES = {
        Confidence.VERY_HIGH: 30,
        Confidence.HIGH: 20,
        Confidence.MEDIUM: 10,
        Confidence.LOW: 5,
    }

    RELEVANCE_SCORES = {
        "HIGH": 20,
        "MEDIUM": 10,
        "LOW": 5,
    }

    SUFFICIENT_SCORE = 40

    def evaluate(
        self,
        evidence: List[Evidence],
    ) -> EvidenceEvaluation:
        """Evaluate collected evidence."""

        if not evidence:
            return EvidenceEvaluation(
                sufficient=False,
                score=0,
                reasons=[
                    "No investigation evidence was collected."
                ],
                missing_evidence=[
                    "BEHAVIORAL",
                    "THREAT_INTELLIGENCE",
                    "ATTACK_CONTEXT",
                ],
            )

        score = 0
        reasons = []

        sources = {
            item.source
            for item in evidence
        }

        for item in evidence:
            score += self.CONFIDENCE_SCORES.get(
                item.confidence,
                0,
            )

            score += self.RELEVANCE_SCORES.get(
                item.relevance.upper(),
                0,
            )

        if len(sources) >= 2:
            score += 15

            reasons.append(
                "Evidence was collected from multiple sources."
            )

        if len(sources) >= 3:
            score += 10

            reasons.append(
                "Evidence has strong multi-source coverage."
            )

        missing_evidence = (
            self._identify_missing_evidence(
                sources
            )
        )

        if missing_evidence:
            reasons.append(
                "Evidence gaps identified: "
                + ", ".join(missing_evidence)
                + "."
            )

        if score >= self.SUFFICIENT_SCORE:
            sufficient = True

            reasons.append(
                "Evidence is sufficient to support investigation reasoning."
            )

        else:
            sufficient = False

            reasons.append(
                "Evidence is insufficient and requires additional investigation."
            )

        return EvidenceEvaluation(
            sufficient=sufficient,
            score=score,
            reasons=reasons,
            missing_evidence=missing_evidence,
        )

    @staticmethod
    def _identify_missing_evidence(
        sources,
    ):
        """Identify missing investigation evidence categories."""

        missing = []

        if "Security Logs" not in sources:
            missing.append(
                "BEHAVIORAL"
            )

        if "AlienVault OTX" not in sources:
            missing.append(
                "THREAT_INTELLIGENCE"
            )

        if "MITRE ATT&CK" not in sources:
            missing.append(
                "ATTACK_CONTEXT"
            )

        return missing