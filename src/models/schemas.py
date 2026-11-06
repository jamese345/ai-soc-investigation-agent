from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERY_HIGH = "VERY_HIGH"


class InvestigationStatus(str, Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class Alert(BaseModel):
    alert_id: str
    rule: str
    severity: Severity
    source_ip: Optional[str] = None
    username: Optional[str] = None
    failed_attempts: int = 0
    timestamp: datetime


class Evidence(BaseModel):
    source: str
    description: str
    relevance: str
    confidence: Confidence = Confidence.MEDIUM


class Finding(BaseModel):
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    evidence: List[Evidence] = Field(default_factory=list)


class Recommendation(BaseModel):
    action: str
    priority: str
    reason: str


class ReasoningResult(BaseModel):
    summary: str
    conclusion: str
    severity: Severity
    confidence: Confidence
    key_findings: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)

class InvestigationStep(BaseModel):
    action: str
    reason: str
    priority: str =  "MEDIUM"
    status: str = "PENDING"

class EvidenceEvaluation(BaseModel):
    sufficient: bool
    score: int
    reasons: List[str] = Field(default_factory=list)
    missing_evidence: List[str] = Field(
        default_factory=list
    )


class Investigation(BaseModel):
    investigation_id: str
    alert: Alert
    status: InvestigationStatus = InvestigationStatus.PENDING
    plan: List[InvestigationStep] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    recommendations: List[Recommendation] = Field(default_factory=list)
    reasoning: Optional[ReasoningResult] = None
    evidence_evaluation: Optional[EvidenceEvaluation] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class IOCResult(BaseModel):
    ioc: str
    ioc_type: str
    reputation: str
    risk: Severity
    confidence: Confidence
    sources: List[str] = Field(default_factory=list)