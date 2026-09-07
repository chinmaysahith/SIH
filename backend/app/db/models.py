from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.db.database import Base


class Case(Base):
    __tablename__ = "cases"

    case_id = Column(String(64), primary_key=True, index=True)
    original_filename = Column(String(255), nullable=False)
    stored_path = Column(String(512), nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    file_size = Column(Integer, nullable=False)
    file_extension = Column(String(16), nullable=False)
    status = Column(String(32), nullable=False, default="uploaded")
    upload_timestamp = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Stage 1.5 Queue & Worker Tracking
    job_id = Column(String(64), nullable=True, index=True)
    queue_status = Column(String(32), nullable=True)
    processing_started_at = Column(DateTime, nullable=True)
    processing_completed_at = Column(DateTime, nullable=True)
    error_message = Column(String(512), nullable=True)

    # Relationships
    parsed_data = relationship("ParsedData", back_populates="case", uselist=False, cascade="all, delete-orphan")
    rule_results = relationship("RuleResultRecord", back_populates="case", cascade="all, delete-orphan")
    ml_results = relationship("MLResultRecord", back_populates="case", cascade="all, delete-orphan")
    ioc_results = relationship("IOCResultRecord", back_populates="case", cascade="all, delete-orphan")
    geo_origin_results = relationship("GeoOriginResultRecord", back_populates="case", uselist=False, cascade="all, delete-orphan")
    correlation_results = relationship("CorrelationResultRecord", back_populates="case", uselist=False, cascade="all, delete-orphan")
    # Stage 8 Audit and Case Lifecycle Tracking
    events = relationship("CaseEventRecord", back_populates="case", cascade="all, delete-orphan", order_by="CaseEventRecord.event_sequence.asc()")
    analysis_runs = relationship("AnalysisRunRecord", back_populates="case", cascade="all, delete-orphan", order_by="AnalysisRunRecord.started_timestamp.asc()")
    provenance_snapshots = relationship("ProvenanceSnapshotRecord", back_populates="case", cascade="all, delete-orphan", order_by="ProvenanceSnapshotRecord.created_timestamp.desc()")
    evidence_manifests = relationship("EvidenceManifestRecord", back_populates="case", cascade="all, delete-orphan")
    # Stage 9 Forensic Report Generations
    report_generations = relationship("ReportGenerationRecord", back_populates="case", cascade="all, delete-orphan", order_by="ReportGenerationRecord.generated_timestamp.desc()")


class ParsedData(Base):
    __tablename__ = "parsed_data"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), unique=True, index=True, nullable=False)
    parser_version = Column(String(32), nullable=False)
    parsed_timestamp = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Structured representation (stored as serialized JSON strings for SQLite portability)
    headers_json = Column(Text, nullable=True)
    received_headers_json = Column(Text, nullable=True)
    sender_json = Column(Text, nullable=True)
    recipients_json = Column(Text, nullable=True)
    subject = Column(Text, nullable=True)
    body_text = Column(Text, nullable=True)
    body_html = Column(Text, nullable=True)
    urls_json = Column(Text, nullable=True)
    attachments_json = Column(Text, nullable=True)
    parser_status = Column(String(32), nullable=False, default="success")
    error_message = Column(Text, nullable=True)

    # Back-reference to Case
    case = relationship("Case", back_populates="parsed_data")


class RuleResultRecord(Base):
    """Stores deterministic Rules Engine evaluation results per case and version."""

    __tablename__ = "rule_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), index=True, nullable=False)
    rules_engine_version = Column(String(32), nullable=False)
    evaluated_timestamp = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    total_score = Column(Integer, nullable=False, default=0)
    rules_verdict = Column(String(32), nullable=False, default="BENIGN")
    matched_rules_count = Column(Integer, nullable=False, default=0)
    total_rules_evaluated = Column(Integer, nullable=False, default=0)

    # Serialized JSON representations
    category_scores_json = Column(Text, nullable=False)
    results_json = Column(Text, nullable=False)

    # Back-reference to Case
    case = relationship("Case", back_populates="rule_results")


class MLResultRecord(Base):
    """Stores ML Engine prediction and likelihood results per case."""

    __tablename__ = "ml_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), index=True, nullable=False)
    model_version = Column(String(32), nullable=False)
    preprocessing_version = Column(String(32), nullable=False)
    prediction_timestamp = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    prediction = Column(String(32), nullable=False, default="UNCERTAIN")
    phishing_probability = Column(Float, nullable=False, default=0.5)
    confidence = Column(String(32), nullable=False, default="LOW")
    model_status = Column(String(32), nullable=False, default="ready")

    # Serialized JSON list of top features
    features_json = Column(Text, nullable=False, default="[]")
    error_message = Column(Text, nullable=True)

    # Back-reference to Case
    case = relationship("Case", back_populates="ml_results")


class IOCResultRecord(Base):
    """Stores IOC threat intelligence evaluation findings per indicator and case."""

    __tablename__ = "ioc_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), index=True, nullable=False)
    ioc_id = Column(String(64), nullable=False)
    ioc_type = Column(String(32), nullable=False)
    original_value = Column(Text, nullable=False)
    normalized_value = Column(Text, nullable=False)
    source_context = Column(String(64), nullable=False)
    matched = Column(Boolean, nullable=False, default=False)
    status = Column(String(32), nullable=False, default="not_found")
    confidence = Column(Integer, nullable=False, default=0)
    source = Column(String(64), nullable=False)
    reason = Column(Text, nullable=False)
    feed_version = Column(String(32), nullable=False)
    feed_sha256 = Column(String(64), nullable=True)
    lookup_timestamp = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    error_message = Column(Text, nullable=True)

    # Back-reference to Case
    case = relationship("Case", back_populates="ioc_results")


class GeoOriginResultRecord(Base):
    """Stores Stage 6 Geo / Origin forensic evaluation findings per case."""

    __tablename__ = "geo_origin_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), unique=True, index=True, nullable=False)
    analysis_version = Column(String(32), nullable=False)
    analysis_timestamp = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    selected_origin_ip = Column(String(64), nullable=True)
    selection_method = Column(String(64), nullable=False, default="earliest_plausible_public_ip")
    confidence = Column(String(32), nullable=False, default="UNKNOWN")
    status = Column(String(32), nullable=False, default="SUCCESS")

    candidate_ips_json = Column(Text, nullable=False, default="[]")
    geo_data_json = Column(Text, nullable=True)
    network_intel_json = Column(Text, nullable=True)
    limitations_json = Column(Text, nullable=False, default="[]")

    geo_database_version = Column(String(32), nullable=True)
    geo_database_sha256 = Column(String(64), nullable=True)
    network_feed_version = Column(String(32), nullable=True)
    network_feed_sha256 = Column(String(64), nullable=True)

    disclaimer = Column(Text, nullable=False)
    error_message = Column(Text, nullable=True)

    # Back-reference to Case
    case = relationship("Case", back_populates="geo_origin_results")


class CorrelationResultRecord(Base):
    """Stores Stage 7 Correlated Forensic Assessment findings per case."""

    __tablename__ = "correlation_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), unique=True, index=True, nullable=False)
    correlation_version = Column(String(32), nullable=False)
    policy_version = Column(String(32), nullable=False)
    evaluated_timestamp = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    final_score = Column(Float, nullable=False)
    final_assessment = Column(String(32), nullable=False)  # BENIGN, SUSPICIOUS, HIGH_RISK, INCONCLUSIVE
    correlation_confidence = Column(String(32), nullable=False)  # HIGH, MEDIUM, LOW
    evidence_coverage_percent = Column(Float, nullable=False)

    engine_breakdown_json = Column(Text, nullable=False, default="{}")
    top_evidence_json = Column(Text, nullable=False, default="[]")
    evidence_graph_json = Column(Text, nullable=False, default="{}")
    conflicts_json = Column(Text, nullable=False, default="[]")
    limitations_json = Column(Text, nullable=False, default="[]")

    explanation = Column(Text, nullable=False)
    upstream_versions_json = Column(Text, nullable=False, default="{}")
    disclaimer = Column(Text, nullable=False)

    # Back-reference to Case
    case = relationship("Case", back_populates="correlation_results")


# =====================================================================
# Stage 8: Forensic Audit Trail & Lifecycle Models
# =====================================================================

class CaseEventRecord(Base):
    """Append-only, tamper-evident hash-chained log of forensic case lifecycle events."""

    __tablename__ = "case_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), index=True, nullable=False)
    event_sequence = Column(Integer, nullable=False)
    event_type = Column(String(64), nullable=False)
    event_timestamp = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    actor_type = Column(String(32), nullable=False, default="SYSTEM")  # SYSTEM or ANALYST
    actor_id = Column(String(64), nullable=True)
    message = Column(Text, nullable=False)
    metadata_json = Column(Text, nullable=False, default="{}")
    previous_event_hash = Column(String(64), nullable=True)
    event_hash = Column(String(64), nullable=False)

    # Back-reference to Case
    case = relationship("Case", back_populates="events")


class AnalysisRunRecord(Base):
    """Explicit, reproducible execution tracking for analytical engines."""

    __tablename__ = "analysis_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), index=True, nullable=False)
    run_id = Column(String(64), unique=True, index=True, nullable=False)
    engine_name = Column(String(32), nullable=False)  # parser, rules, ml, ioc, geo, correlation
    status = Column(String(32), nullable=False)  # STARTED, COMPLETED, FAILED, SKIPPED
    started_timestamp = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    completed_timestamp = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    engine_version = Column(String(32), nullable=True)
    model_version = Column(String(32), nullable=True)
    feed_version = Column(String(32), nullable=True)

    input_fingerprint = Column(String(64), nullable=False)
    output_fingerprint = Column(String(64), nullable=True)

    # Back-reference to Case
    case = relationship("Case", back_populates="analysis_runs")


class ProvenanceSnapshotRecord(Base):
    """Captures the exact analytical software, model, and intelligence environment for a case."""

    __tablename__ = "provenance_snapshots"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), index=True, nullable=False)
    created_timestamp = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    parser_version = Column(String(32), nullable=True)
    rules_engine_version = Column(String(32), nullable=True)
    ml_model_version = Column(String(32), nullable=True)
    ml_preprocessing_version = Column(String(32), nullable=True)
    ioc_engine_version = Column(String(32), nullable=True)
    ioc_feed_version = Column(String(32), nullable=True)
    ioc_feed_sha256 = Column(String(64), nullable=True)
    geo_analysis_version = Column(String(32), nullable=True)
    geo_database_version = Column(String(32), nullable=True)
    geo_database_sha256 = Column(String(64), nullable=True)
    network_feed_version = Column(String(32), nullable=True)
    network_feed_sha256 = Column(String(64), nullable=True)
    correlation_engine_version = Column(String(32), nullable=True)
    correlation_policy_version = Column(String(32), nullable=True)

    raw_evidence_sha256 = Column(String(64), nullable=False)
    attachment_manifest_sha256 = Column(String(64), nullable=True)

    # Back-reference to Case
    case = relationship("Case", back_populates="provenance_snapshots")


class EvidenceManifestRecord(Base):
    """Cryptographic catalog of primary evidence and derived forensic artifacts."""

    __tablename__ = "evidence_manifest"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), index=True, nullable=False)
    artifact_type = Column(String(32), nullable=False)  # RAW_EMAIL, ATTACHMENT, PARSED_RESULT, etc.
    artifact_name = Column(String(255), nullable=False)
    relative_path = Column(String(512), nullable=True)
    size_bytes = Column(Integer, nullable=False)
    sha256 = Column(String(64), nullable=False)
    created_timestamp = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    source = Column(String(64), nullable=False)  # quarantine, parser, engine
    immutable = Column(Boolean, nullable=False, default=True)

    # Back-reference to Case
    case = relationship("Case", back_populates="evidence_manifests")


# =====================================================================
# Stage 9: Forensic Report Models
# =====================================================================

class ReportGenerationRecord(Base):
    """Stores metadata and content hashes for generated forensic investigation reports."""

    __tablename__ = "report_generations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    report_id = Column(String(64), unique=True, index=True, nullable=False)
    case_id = Column(String(64), ForeignKey("cases.case_id"), index=True, nullable=False)
    report_version = Column(String(32), nullable=False, default="1.0.0")
    generated_timestamp = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    report_sha256 = Column(String(64), nullable=False)
    format = Column(String(16), nullable=False)  # JSON, HTML, PDF
    generation_status = Column(String(32), nullable=False, default="SUCCESS")
    error_message = Column(Text, nullable=True)

    # Back-reference to Case
    case = relationship("Case", back_populates="report_generations")


