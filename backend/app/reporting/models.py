"""Pydantic Models and Schemas for Stage 9 Forensic Reporting."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ReportMetadata(BaseModel):
    report_id: str
    case_id: str
    report_version: str = "1.0.0"
    generated_timestamp: str
    generation_duration_ms: Optional[int] = None
    report_sha256: str


class ExecutiveSummary(BaseModel):
    final_assessment: str
    risk_score: float
    confidence: str
    evidence_coverage_percent: float
    concise_summary: str


class CaseInfo(BaseModel):
    case_id: str
    original_filename: str
    upload_timestamp: str
    file_size_bytes: int
    evidence_sha256: str
    case_status: str
    message_id: Optional[str] = None
    subject: Optional[str] = None
    sender: Optional[str] = None
    recipients: List[str] = []
    email_date: Optional[str] = None


class EvidenceIntegrityReport(BaseModel):
    original_sha256: str
    current_sha256: str
    integrity_status: str  # VERIFIED, COMPROMISED, FILE_MISSING
    bytes_altered: int
    message: str


class EmailOverview(BaseModel):
    sender_from: str
    to: List[str] = []
    cc: List[str] = []
    reply_to: Optional[str] = None
    subject: str
    date: Optional[str] = None
    message_id: Optional[str] = None
    return_path: Optional[str] = None
    content_type: Optional[str] = None
    body_plain_snippet: Optional[str] = None
    urls_count: int = 0
    attachments_count: int = 0


class HeaderHopItem(BaseModel):
    hop_index: int
    by_host: Optional[str] = None
    from_host: Optional[str] = None
    ip: Optional[str] = None
    timestamp: Optional[str] = None
    protocol: Optional[str] = None
    raw_snippet: str


class HeaderAnalysisReport(BaseModel):
    received_chain: List[HeaderHopItem] = []
    total_hops: int = 0
    notes: Optional[str] = None


class MatchedRuleItem(BaseModel):
    rule_id: str
    rule_name: str
    category: str
    points: int
    severity: str
    description: str
    evidence: Dict[str, Any] = {}


class RulesFindingsReport(BaseModel):
    rules_engine_version: str
    total_score: int
    verdict: str
    category_scores: Dict[str, int] = {}
    matched_rules: List[MatchedRuleItem] = []
    total_rules_evaluated: int = 0
    status: str = "COMPLETED"


class MLFeatureItem(BaseModel):
    token: str
    weight: float
    direction: str


class MLFindingsReport(BaseModel):
    model_version: str
    preprocessing_version: str
    prediction: str
    phishing_probability: float
    confidence: str
    model_status: str
    top_features: List[MLFeatureItem] = []
    interpretation_note: str = (
        "Model probability represents phishing-classifier likelihood, not overall fraud probability."
    )
    error_message: Optional[str] = None


class IOCReportItem(BaseModel):
    ioc_type: str
    value: str
    status: str  # KNOWN_MALICIOUS, SUSPICIOUS, NOT_FOUND, CONFLICT
    matched: bool
    source: str
    confidence: int
    reason: str
    feed_version: str
    feed_sha256: Optional[str] = None


class IOCFindingsReport(BaseModel):
    total_iocs: int = 0
    malicious_iocs: int = 0
    suspicious_iocs: int = 0
    not_found_iocs: int = 0
    indicators: List[IOCReportItem] = []
    feed_provenance: List[str] = []


class AttachmentReportItem(BaseModel):
    filename: str
    size_bytes: int
    sha256: str
    content_type: str
    safe_handling_note: str = "Quarantined without execution. Never detonated or executed."


class AttachmentFindingsReport(BaseModel):
    total_attachments: int = 0
    attachments: List[AttachmentReportItem] = []


class GeoFindingsReport(BaseModel):
    analysis_version: str
    selected_origin_ip: Optional[str] = None
    selection_method: str
    confidence: str
    status: str
    country: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    is_tor: Optional[bool] = None
    is_vpn: Optional[bool] = None
    is_proxy: Optional[bool] = None
    is_hosting: Optional[bool] = None
    is_documentation_range: bool = False
    candidate_ips_count: int = 0
    limitations: List[str] = []
    disclaimer: str


class EngineSignalBreakdownItem(BaseModel):
    engine_name: str
    availability: str
    normalized_value: float
    effective_weight: float
    contribution: float
    summary_text: str


class TopEvidenceItem(BaseModel):
    rank: int
    engine: str
    evidence_type: str
    impact: str
    description: str


class ConflictItem(BaseModel):
    conflict_type: str
    engines_involved: List[str] = []
    description: str
    reconciliation: str


class CorrelationReport(BaseModel):
    correlation_version: str
    policy_version: str
    final_score: float
    final_assessment: str
    correlation_confidence: str
    evidence_coverage_percent: float
    score_explanation: str = (
        "The correlation score is an explainable multi-signal risk rating based on configured analytical policy. "
        "It is NOT a mathematically calibrated probability of fraud."
    )
    engine_breakdown: Dict[str, EngineSignalBreakdownItem] = {}
    top_evidence: List[TopEvidenceItem] = []
    conflicts: List[ConflictItem] = []
    limitations: List[str] = []
    evidence_graph_entities: List[Dict[str, Any]] = []
    explanation: str


class AuditTimelineItem(BaseModel):
    event_sequence: int
    event_type: str
    timestamp: str
    actor: str
    message: str
    event_hash: str


class AuditTimelineReport(BaseModel):
    audit_chain_valid: bool
    total_events: int = 0
    events: List[AuditTimelineItem] = []


class AnalysisRunItem(BaseModel):
    run_id: str
    engine_name: str
    status: str
    version: str
    started_timestamp: str
    duration_ms: Optional[int] = None
    input_fingerprint: Optional[str] = None
    output_fingerprint: Optional[str] = None


class AnalysisRunsReport(BaseModel):
    total_runs: int = 0
    runs: List[AnalysisRunItem] = []


class ProvenanceReport(BaseModel):
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


class ManifestArtifactItem(BaseModel):
    artifact_type: str
    artifact_name: str
    size_bytes: int
    sha256: str
    source: str
    immutable: bool


class EvidenceManifestReport(BaseModel):
    manifest_sha256: str
    total_artifacts: int = 0
    artifacts: List[ManifestArtifactItem] = []


class ForensicReport(BaseModel):
    metadata: ReportMetadata
    executive_summary: ExecutiveSummary
    case_info: CaseInfo
    evidence_integrity: EvidenceIntegrityReport
    email_overview: Optional[EmailOverview] = None
    header_analysis: Optional[HeaderAnalysisReport] = None
    rules_findings: Optional[RulesFindingsReport] = None
    ml_findings: Optional[MLFindingsReport] = None
    ioc_findings: Optional[IOCFindingsReport] = None
    attachment_findings: Optional[AttachmentFindingsReport] = None
    geo_findings: Optional[GeoFindingsReport] = None
    correlation: Optional[CorrelationReport] = None
    audit_timeline: Optional[AuditTimelineReport] = None
    analysis_runs: Optional[AnalysisRunsReport] = None
    provenance: Optional[ProvenanceReport] = None
    evidence_manifest: Optional[EvidenceManifestReport] = None
    forensic_disclaimer: str = (
        "This report presents analytical findings generated by the Email Fraud Forensic Analysis Platform "
        "from preserved email evidence and locally available analytical data. The correlation score is an "
        "explainable multi-signal risk rating and is not a mathematically calibrated probability of fraud. "
        "Network-origin analysis identifies plausible infrastructure based on available headers and enrichment "
        "data and does not establish an attacker's exact physical location or identity. Findings should be "
        "reviewed by a qualified investigator in context."
    )


class ReportHistoryItem(BaseModel):
    report_id: str
    format: str
    version: str
    generated_timestamp: str
    report_sha256: str
    status: str
    error_message: Optional[str] = None


class ReportHistoryResponse(BaseModel):
    case_id: str
    total_reports: int
    reports: List[ReportHistoryItem] = []
