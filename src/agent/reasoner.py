import json
import os

from dotenv import load_dotenv
from openai import (
    APIConnectionError,
    APIError,
    OpenAI,
    RateLimitError,
)

from src.models.schemas import (
    Confidence,
    Investigation,
    ReasoningResult,
    Severity,
)

load_dotenv()


class InvestigationReasoner:
    """Uses retrieved cybersecurity knowledge and investigation
    evidence to reason over a security alert.
    """

    def __init__(
        self,
        client=None,
        model=None,
        retriever=None,
    ):
        self.client = client or OpenAI(
            api_key=os.getenv("OPENAI_API_KEY")
        )

        self.model = model or os.getenv(
            "OPENAI_MODEL",
            "gpt-4.1-mini",
        )

        self.retriever = retriever

    def analyze(self, investigation: Investigation) -> ReasoningResult:
        evidence = []

        for finding in investigation.findings:
            evidence.append(
                {
                    "source": finding.evidence[0].source,
                    "description": finding.description,
                    "severity": finding.severity.value,
                    "confidence": finding.confidence.value,
                }
            )

        knowledge = []

        if self.retriever is not None:
            query = self._build_retrieval_query(
                investigation
            )

            knowledge = self.retriever.retrieve(
                query,
                top_k=3,
            )

        prompt = self._build_prompt(
            investigation,
            evidence,
            knowledge,
        )

        try:
            response = self.client.responses.create(
                model=self.model,
                input=prompt,
            )
        except RateLimitError as exc:
            raise RuntimeError(
                "LLM service unavailable: API rate limit or "
                "account credit limit reached."
            ) from exc
        except APIConnectionError as exc:
            raise RuntimeError(
                "LLM service unavailable: could not connect to "
                "the OpenAI API."
            ) from exc
        except APIError as exc:
            raise RuntimeError(
                f"LLM service returned an API error: {exc}"
            ) from exc

        text = response.output_text.strip()

        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "LLM returned invalid JSON."
            ) from exc

        return ReasoningResult(
            summary=data["summary"],
            conclusion=data["conclusion"],
            severity=Severity(data["severity"]),
            confidence=Confidence(data["confidence"]),
            key_findings=data.get(
                "key_findings",
                [],
            ),
            recommended_actions=data.get(
                "recommended_actions",
                [],
            ),
        )

    @staticmethod
    def _build_retrieval_query(
        investigation: Investigation,
    ) -> str:
        parts = [
            investigation.alert.rule,
        ]

        if investigation.alert.username:
            parts.append(
                "suspicious login"
            )

        if investigation.alert.failed_attempts:
            parts.append(
                "failed authentication"
            )

        for finding in investigation.findings:
            parts.append(finding.description)

        return " ".join(parts)

    def _build_prompt(
        self,
        investigation,
        evidence,
        knowledge,
    ):
        knowledge_context = []

        for item in knowledge:
            knowledge_context.append(
                {
                    "source": item["source"],
                    "content": item["content"],
                    "relevance_score": item["score"],
                }
            )

        return f"""
You are an experienced SOC analyst.

Analyze the security investigation below.

IMPORTANT RULES:

1. Use ONLY the supplied investigation evidence and
   retrieved cybersecurity knowledge.
2. Do not invent facts, indicators, events, or threat intelligence.
3. Clearly distinguish direct evidence from general cybersecurity
   knowledge.
4. Retrieved knowledge provides investigation guidance and context.
   It does NOT prove that an event occurred.
5. If the evidence is insufficient, say so.
6. Return ONLY valid JSON.
7. The severity must be one of:
   LOW, MEDIUM, HIGH, CRITICAL
8. The confidence must be one of:
   LOW, MEDIUM, HIGH, VERY_HIGH

Alert:
{json.dumps(
    {
        "alert_id": investigation.alert.alert_id,
        "rule": investigation.alert.rule,
        "severity": investigation.alert.severity.value,
        "source_ip": investigation.alert.source_ip,
        "username": investigation.alert.username,
        "failed_attempts": investigation.alert.failed_attempts,
        "timestamp": investigation.alert.timestamp.isoformat(),
    },
    indent=2,
)}

Investigation Evidence:
{json.dumps(
    evidence,
    indent=2,
)}

Retrieved Cybersecurity Knowledge:
{json.dumps(
    knowledge_context,
    indent=2,
)}

Return exactly this JSON structure:

{{
    "summary": "Short summary of what happened.",
    "conclusion": "Overall SOC analyst conclusion.",
    "severity": "HIGH",
    "confidence": "HIGH",
    "key_findings": [
        "Important finding 1",
        "Important finding 2"
    ],
    "recommended_actions": [
        "Recommended action 1",
        "Recommended action 2"
    ]
}}
"""