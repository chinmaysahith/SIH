"""Stage 8 Forensic Audit Trail & Lifecycle Pydantic Schemas.

Defines models for event logging, hash-chain verification,
analysis executions, provenance snapshots, and evidence manifests.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class CaseLifecycleState(str, Enum):
    UPLOADED = "uploaded"
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETE = "complete"
    FAILED = "failed"
    QUEUE_FAILED = "queue_failed"


class ActorType(str, Enum):
    SYSTEM = "SYSTEM"
    ANALYST = "ANALYST"


class AuditEventType(str, Enum):
    # Ingestion & Lifecycle
    CASE_CREATED = "CASE_CREATED"
    EVIDENCE_STORED = "EVIDENCE_STORED"
    JOB_QUEUED = "JOB_QUEUED"
    PROCESSING_STARTED = "PROCESSING_STARTED"

    # Stage 2 Parser
    PARSER_STARTED = "PARSER_STARTED"
    PARSER_COMPLETED = "PARSER_COMPLETED"
    PARSER_FAILED = "PARSER_FAILED"

    # Stage 3 Rules
    RULES_STARTED = "RULES_STARTED"
    RULES_COMPLETED = "RULES_COMPLETED"
    RULES_FAILED = "RULES_FAILED"

    # Stage 4 ML
    ML_STARTED = "ML_STARTED"
    ML_COMPLETED = "ML_COMPLETED"
    ML_FAILED = "ML_FAILED"

    # Stage 5 IOC
    IOC_STARTED = "IOC_STARTED"
    IOC_COMPLETED = "IOC_COMPLETED"
    IOC_FAILED = "IOC_FAILED"

    # Stage 6 Geo / Origin
    GEO_STARTED = "GEO_STARTED"
    GEO_COMPLETED = "GEO_COMPLETED"
    GEO_FAILED = "GEO_FAILED"

    # Stage 7 Correlation
    CORRELATION_STARTED = "CORRELATION_STARTED"
    CORRELATION_COMPLETED = "CORRELATION_COMPLETED"
    CORRELATION_FAILED = "CORRELATION_FAILED"

    # Final Lifecycle & Integrity
    CASE_ANALYSIS_COMPLETED = "CASE_ANALYSIS_COMPLETED"
    CASE_ANALYSIS_FAILED = "CASE_ANALYSIS_FAILED"
    ANALYSIS_RERUN = "ANALYSIS_RERUN"
    EVIDENCE_INTEGRITY_VERIFIED = "EVIDENCE_INTEGRITY_VERIFIED"
    EVIDENCE_INTEGRITY_FAILURE = "EVIDENCE_INTEGRITY_FAILURE"
    ANALYST_VIEWED = "ANALYST_VIEWED"
    REPORT_GENERATED = "REPORT_GENERATED"


class EngineName(str, Enum):
    PARSER = "parser"
    RULES = "rules"
    ML = "ml"
    IOC = "ioc"
    GEO = "geo"
    CORRELATION = "correlation"


class RunStatus(str, Enum):
    STARTED = "STARTED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class ArtifactType(str, Enum):
    RAW_EMAIL = "RAW_EMAIL"
    ATTACHMENT = "ATTACHMENT"
    PARSED_RESULT = "PARSED_RESULT"
    RULE_RESULT = "RULE_RESULT"
    ML_RESULT = "ML_RESULT"
    IOC_RESULT = "IOC_RESULT"
    GEO_RESULT = "GEO_RESULT"
    CORRELATION_RESULT = "CORRELATION_RESULT"


# ---------------------------------------------------------------------
# API Responses & Data Transfer Objects
# ---------------------------------------------------------------------

class TimelineEventItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: int
    case_id: str
    event_sequence: int
    event_type: str
    event_timestamp: str
    actor_type: str
    actor_id: Optional[str] = None
    message: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    previous_event_hash: Optional[str] = None
    event_hash: str


class TimelineResponse(BaseModel):
    case_id: str
    total_events: int
    events: List[TimelineEventItem]


class AuditChainVerificationError(BaseModel):
    event_id: Optional[int] = None
    event_sequence: Optional[int] = None
    error_type: str  # sequence_gap, sequence_duplicate, previous_hash_mismatch, event_hash_mismatch
    message: str


class AuditVerificationResponse(BaseModel):
    case_id: str
    valid: bool
    event_count: int
    first_event_hash: Optional[str] = None
    last_event_hash: Optional[str] = None
    errors: List[AuditChainVerificationError] = Field(default_factory=list)
    verification_timestamp: str


class AnalysisRunItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    run_id: str
    engine_name: str
    status: str
    started_timestamp: str
    completed_timestamp: Optional[str] = None
    duration_seconds: Optional[float] = None
    error_message: Optional[str] = None
    engine_version: Optional[str] = None
    model_version: Optional[str] = None
    feed_version: Optional[str] = None
    input_fingerprint: str
    output_fingerprint: Optional[str] = None


class AnalysisRunsResponse(BaseModel):
    case_id: str
    total_runs: int
    runs: List[AnalysisRunItem]


class ProvenanceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    case_id: str
    created_timestamp: str
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
    correlation_engine_version: Optional[str] = None
    correlation_policy_version: Optional[str] = None
    raw_evidence_sha256: str
    attachment_manifest_sha256: Optional[str] = None


class EvidenceArtifactItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    artifact_id: int
    artifact_type: str
    artifact_name: str
    relative_path: Optional[str] = None
    size_bytes: int
    sha256: str
    created_timestamp: str
    source: str
    immutable: bool


class EvidenceManifestResponse(BaseModel):
    case_id: str
    raw_evidence_sha256: str
    manifest_sha256: str
    total_artifacts: int
    artifacts: List[EvidenceArtifactItem]
