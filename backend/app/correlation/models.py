from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class FinalAssessment(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    INCONCLUSIVE = "INCONCLUSIVE"


class CorrelationConfidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class SignalAvailability(str, Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    PARTIAL = "partial"


class EngineSignal(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    engine_name: str
    availability: SignalAvailability
    raw_value: Any
    normalized_value: float = 0.0  # 0.0 to 1.0
    base_weight: float = 0.0
    effective_weight: float = 0.0
    contribution: float = 0.0  # normalized_value * effective_weight * 100
    summary_text: str = ""


class EvidenceObservation(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    engine: str
    observation_type: str
    indicator_value: str
    severity: str  # info, low, medium, high, critical
    details: str


class EvidenceEntity(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    entity_id: str  # e.g., IP:203.0.113.10 or DOMAIN:example.com
    entity_type: str  # IP, DOMAIN, URL, HASH, SENDER, HEADER
    value: str
    observations: List[EvidenceObservation] = Field(default_factory=list)
    is_cross_engine: bool = False


class EvidenceGraph(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    entities: List[EvidenceEntity] = Field(default_factory=list)
    cross_engine_entity_count: int = 0


class EvidenceCoverage(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    rules: SignalAvailability = SignalAvailability.UNAVAILABLE
    ml: SignalAvailability = SignalAvailability.UNAVAILABLE
    ioc: SignalAvailability = SignalAvailability.UNAVAILABLE
    geo: SignalAvailability = SignalAvailability.UNAVAILABLE
    coverage_percent: float = 0.0


class TopEvidenceItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    rank: int
    engine: str
    evidence_type: str
    impact: str  # high, medium, low
    description: str


class CorrelationConflict(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    conflict_type: str
    engines_involved: List[str]
    description: str
    reconciliation: str


class UpstreamVersions(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    parser_version: Optional[str] = None
    rules_engine_version: Optional[str] = None
    ml_model_version: Optional[str] = None
    ml_preprocessing_version: Optional[str] = None
    ioc_engine_version: Optional[str] = None
    ioc_feed_version: Optional[str] = None
    ioc_feed_sha256: Optional[str] = None
    geo_analysis_version: Optional[str] = None
    geo_database_version: Optional[str] = None
    geo_database_sha256: Optional[str] = None
    network_feed_version: Optional[str] = None
    network_feed_sha256: Optional[str] = None
    correlation_engine_version: str
    correlation_policy_version: str


class CorrelationResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    case_id: str
    correlation_engine_version: str
    policy_version: str
    evaluated_timestamp: str

    final_score: float  # 0.0 to 100.0
    final_assessment: FinalAssessment
    correlation_confidence: CorrelationConfidence
    evidence_coverage: EvidenceCoverage

    engine_breakdown: Dict[str, EngineSignal] = Field(default_factory=dict)
    top_evidence: List[TopEvidenceItem] = Field(default_factory=list)
    evidence_graph: EvidenceGraph = Field(default_factory=EvidenceGraph)
    conflicts: List[CorrelationConflict] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)

    explanation: str
    upstream_versions: UpstreamVersions
    disclaimer: str = (
        "Forensic Disclaimer: The correlation score is an explainable multi-signal risk rating "
        "synthesizing observed technical, statistical, intelligence, and network origin evidence. "
        "It is NOT a mathematically calibrated probability of fraud."
    )
