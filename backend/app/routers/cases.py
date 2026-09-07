import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.models import Case, ParsedData, RuleResultRecord, MLResultRecord, IOCResultRecord, GeoOriginResultRecord, CorrelationResultRecord
from app.rules.models import RulesEvaluationSummary

router = APIRouter(prefix="/cases", tags=["Cases"])



class CaseStatusResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    case_id: str
    status: str
    job_id: Optional[str] = None
    queue_status: Optional[str] = None
    upload_timestamp: datetime
    processing_started_at: Optional[datetime] = None
    processing_completed_at: Optional[datetime] = None
    error_message: Optional[str] = None


class ParsedSummaryResponse(BaseModel):
    case_id: str
    parser_version: str
    parsed_timestamp: datetime
    parser_status: str
    subject: Optional[str] = None
    urls: List[str] = []
    attachments_count: int = 0
    has_body_text: bool = False
    has_body_html: bool = False
    error_message: Optional[str] = None


@router.get(
    "/{case_id}/status",
    response_model=CaseStatusResponse,
    summary="Get case processing status",
    description="Returns the current lifecycle and queue status for a specific case.",
)
def get_case_status(
    case_id: str,
    db: Session = Depends(get_db),
):
    case = db.query(Case).filter(Case.case_id == case_id).one_or_none()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )
    return case


@router.get(
    "/{case_id}/parsed",
    response_model=ParsedSummaryResponse,
    summary="Get parsed email summary",
    description="Returns structured metadata and summary of the parsed email evidence.",
)
def get_parsed_data(
    case_id: str,
    db: Session = Depends(get_db),
):
    parsed = db.query(ParsedData).filter(ParsedData.case_id == case_id).one_or_none()
    if not parsed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Parsed data for case '{case_id}' not found",
        )

    urls = json.loads(parsed.urls_json) if parsed.urls_json else []
    attachments = json.loads(parsed.attachments_json) if parsed.attachments_json else []

    return ParsedSummaryResponse(
        case_id=parsed.case_id,
        parser_version=parsed.parser_version,
        parsed_timestamp=parsed.parsed_timestamp,
        parser_status=parsed.parser_status,
        subject=parsed.subject,
        urls=urls,
        attachments_count=len(attachments),
        has_body_text=bool(parsed.body_text),
        has_body_html=bool(parsed.body_html),
        error_message=parsed.error_message,
    )


@router.get(
    "/{case_id}/rules",
    response_model=RulesEvaluationSummary,
    summary="Get rules engine evaluation results",
    description="Returns deterministic rules evaluation results, category score breakdown, and fraud verdict.",
)
def get_case_rules(
    case_id: str,
    db: Session = Depends(get_db),
):
    case = db.query(Case).filter(Case.case_id == case_id).one_or_none()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )

    rule_record = (
        db.query(RuleResultRecord)
        .filter(RuleResultRecord.case_id == case_id)
        .order_by(RuleResultRecord.evaluated_timestamp.desc())
        .first()
    )

    if not rule_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rules evaluation for case '{case_id}' not found or pending",
        )

    category_scores = json.loads(rule_record.category_scores_json) if rule_record.category_scores_json else {}
    results = json.loads(rule_record.results_json) if rule_record.results_json else []

    return RulesEvaluationSummary(
        rules_engine_version=rule_record.rules_engine_version,
        evaluated_timestamp=rule_record.evaluated_timestamp.isoformat(),
        total_rules_evaluated=rule_record.total_rules_evaluated,
        matched_rules_count=rule_record.matched_rules_count,
        total_score=rule_record.total_score,
        verdict=rule_record.rules_verdict,
        category_scores=category_scores,
        results=results,
    )


class MLFeatureResponse(BaseModel):
    token: str
    weight: float
    direction: str


class MLResultResponse(BaseModel):
    case_id: str
    model_version: str
    preprocessing_version: str
    prediction_timestamp: str
    prediction: str
    phishing_probability: float
    confidence: str
    model_status: str
    top_features: List[MLFeatureResponse] = []
    error_message: Optional[str] = None


@router.get(
    "/{case_id}/ml",
    response_model=MLResultResponse,
    summary="Get ML engine prediction results",
    description="Returns statistical ML phishing/fraud likelihood prediction, confidence, and feature contributions.",
)
def get_case_ml(
    case_id: str,
    db: Session = Depends(get_db),
):
    case = db.query(Case).filter(Case.case_id == case_id).one_or_none()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )

    ml_record = (
        db.query(MLResultRecord)
        .filter(MLResultRecord.case_id == case_id)
        .order_by(MLResultRecord.prediction_timestamp.desc())
        .first()
    )

    if not ml_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"ML prediction for case '{case_id}' not found or pending",
        )

    features = json.loads(ml_record.features_json) if ml_record.features_json else []

    return MLResultResponse(
        case_id=ml_record.case_id,
        model_version=ml_record.model_version,
        preprocessing_version=ml_record.preprocessing_version,
        prediction_timestamp=ml_record.prediction_timestamp.isoformat(),
        prediction=ml_record.prediction,
        phishing_probability=ml_record.phishing_probability,
        confidence=ml_record.confidence,
        model_status=ml_record.model_status,
        top_features=features,
        error_message=ml_record.error_message,
    )


class IOCResultResponseItem(BaseModel):
    ioc_id: str
    ioc_type: str
    original_value: str
    normalized_value: str
    source_context: str
    matched: bool
    status: str
    confidence: int
    source: str
    reason: str
    feed_version: str
    feed_sha256: Optional[str] = None
    lookup_timestamp: str
    error_message: Optional[str] = None


class IOCSummaryCountsResponse(BaseModel):
    total_iocs: int
    matched_iocs: int
    malicious_iocs: int
    suspicious_iocs: int
    not_found_iocs: int


class IOCSummaryResponse(BaseModel):
    case_id: str
    feed_versions: List[str] = []
    feed_sha256s: List[str] = []
    summary: IOCSummaryCountsResponse
    results: List[IOCResultResponseItem] = []


@router.get(
    "/{case_id}/iocs",
    response_model=IOCSummaryResponse,
    summary="Get IOC threat intelligence evaluation results",
    description="Returns indicator-level findings against configured threat intelligence feeds, with provenance tracking.",
)
def get_case_iocs(
    case_id: str,
    db: Session = Depends(get_db),
):
    case = db.query(Case).filter(Case.case_id == case_id).one_or_none()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )

    ioc_records = (
        db.query(IOCResultRecord)
        .filter(IOCResultRecord.case_id == case_id)
        .order_by(IOCResultRecord.id.asc())
        .all()
    )

    if not ioc_records:
        if case.status != "complete":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"IOC evaluation for case '{case_id}' not found or pending",
            )
        # Complete case with 0 IOCs extracted
        return IOCSummaryResponse(
            case_id=case_id,
            feed_versions=[],
            feed_sha256s=[],
            summary=IOCSummaryCountsResponse(
                total_iocs=0,
                matched_iocs=0,
                malicious_iocs=0,
                suspicious_iocs=0,
                not_found_iocs=0,
            ),
            results=[],
        )

    feed_versions = sorted(list({r.feed_version for r in ioc_records if r.feed_version}))
    feed_sha256s = sorted(list({r.feed_sha256 for r in ioc_records if r.feed_sha256}))

    matched_count = sum(1 for r in ioc_records if r.matched)
    malicious_count = sum(1 for r in ioc_records if r.status == "known_malicious")
    suspicious_count = sum(1 for r in ioc_records if r.status == "known_suspicious")
    not_found_count = sum(1 for r in ioc_records if r.status == "not_found")

    results = [
        IOCResultResponseItem(
            ioc_id=r.ioc_id,
            ioc_type=r.ioc_type,
            original_value=r.original_value,
            normalized_value=r.normalized_value,
            source_context=r.source_context,
            matched=r.matched,
            status=r.status,
            confidence=r.confidence,
            source=r.source,
            reason=r.reason,
            feed_version=r.feed_version,
            feed_sha256=r.feed_sha256,
            lookup_timestamp=r.lookup_timestamp.isoformat(),
            error_message=r.error_message,
        )
        for r in ioc_records
    ]

    return IOCSummaryResponse(
        case_id=case_id,
        feed_versions=feed_versions,
        feed_sha256s=feed_sha256s,
        summary=IOCSummaryCountsResponse(
            total_iocs=len(ioc_records),
            matched_iocs=matched_count,
            malicious_iocs=malicious_count,
            suspicious_iocs=suspicious_count,
            not_found_iocs=not_found_count,
        ),
        results=results,
    )


# ---------------------------------------------------------
# Stage 6: Geo / Origin Forensics Schemas & Endpoint
# ---------------------------------------------------------

class CandidateIPResponseItem(BaseModel):
    ip: str
    ip_version: int
    classification: str
    hop_index: int
    raw_header_snippet: str
    reverse_dns_hint: Optional[str] = None
    is_origin_candidate: bool = False


class GeoIPResponseData(BaseModel):
    ip: str
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    accuracy_radius_km: Optional[int] = None
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    database_version: Optional[str] = None
    database_sha256: Optional[str] = None


class NetworkIntelResponseData(BaseModel):
    ip: str
    is_tor_exit: Optional[bool] = None
    is_vpn: Optional[bool] = None
    is_proxy: Optional[bool] = None
    is_datacenter_hosting: Optional[bool] = None
    provider_name: Optional[str] = None
    source: Optional[str] = None
    feed_version: Optional[str] = None
    feed_sha256: Optional[str] = None


class GeoOriginResponse(BaseModel):
    case_id: str
    analysis_version: str
    analysis_timestamp: str
    selected_origin_ip: Optional[str] = None
    selection_method: str
    confidence: str
    status: str
    candidate_ips: List[CandidateIPResponseItem] = []
    geo_data: Optional[GeoIPResponseData] = None
    network_intel: Optional[NetworkIntelResponseData] = None
    limitations: List[str] = []
    disclaimer: str
    error_message: Optional[str] = None


@router.get(
    "/{case_id}/geo",
    response_model=GeoOriginResponse,
    summary="Get Geo / Origin forensic analysis results",
    description="Returns candidate IPs extracted from Received headers, origin selection heuristic results, approximate geolocation, ASN, and network intelligence flags.",
)
def get_case_geo(
    case_id: str,
    db: Session = Depends(get_db),
):
    case = db.query(Case).filter(Case.case_id == case_id).one_or_none()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )

    geo_rec = (
        db.query(GeoOriginResultRecord)
        .filter(GeoOriginResultRecord.case_id == case_id)
        .one_or_none()
    )

    if not geo_rec:
        if case.status != "complete":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Geo / Origin analysis for case '{case_id}' not found or pending",
            )
        # Empty fallback for completed cases
        return GeoOriginResponse(
            case_id=case_id,
            analysis_version="1.0.0",
            analysis_timestamp=datetime.now().isoformat(),
            selected_origin_ip=None,
            selection_method="earliest_plausible_public_ip",
            confidence="UNKNOWN",
            status="NO_CANDIDATE",
            candidate_ips=[],
            geo_data=None,
            network_intel=None,
            limitations=["No Received headers were present in this email."],
            disclaimer=(
                "Forensic Disclaimer: Geolocation and network origin data indicate the approximate "
                "originating routing point or exit infrastructure of the transmission. They do NOT "
                "definitively identify the physical location, identity, or nation-state of the attacker."
            ),
        )

    candidate_ips = []
    if geo_rec.candidate_ips_json:
        try:
            candidate_ips = json.loads(geo_rec.candidate_ips_json)
        except Exception:
            candidate_ips = []

    geo_data = None
    if geo_rec.geo_data_json:
        try:
            geo_data = json.loads(geo_rec.geo_data_json)
        except Exception:
            geo_data = None

    network_intel = None
    if geo_rec.network_intel_json:
        try:
            network_intel = json.loads(geo_rec.network_intel_json)
        except Exception:
            network_intel = None

    limitations = []
    if geo_rec.limitations_json:
        try:
            limitations = json.loads(geo_rec.limitations_json)
        except Exception:
            limitations = []

    return GeoOriginResponse(
        case_id=geo_rec.case_id,
        analysis_version=geo_rec.analysis_version,
        analysis_timestamp=geo_rec.analysis_timestamp.isoformat(),
        selected_origin_ip=geo_rec.selected_origin_ip,
        selection_method=geo_rec.selection_method,
        confidence=geo_rec.confidence,
        status=geo_rec.status,
        candidate_ips=candidate_ips,
        geo_data=geo_data,
        network_intel=network_intel,
        limitations=limitations,
        disclaimer=geo_rec.disclaimer,
        error_message=geo_rec.error_message,
    )


# ---------------------------------------------------------
# Stage 7: Correlation Engine Schemas & Endpoint
# ---------------------------------------------------------

class EngineSignalResponseData(BaseModel):
    engine_name: str
    availability: str
    raw_value: Optional[Any] = None
    normalized_value: float
    base_weight: float
    effective_weight: float
    contribution: float
    summary_text: str


class TopEvidenceResponseItem(BaseModel):
    rank: int
    engine: str
    evidence_type: str
    impact: str
    description: str


class CorrelationConflictResponseItem(BaseModel):
    conflict_type: str
    engines_involved: List[str]
    description: str
    reconciliation: str


class CorrelationResponse(BaseModel):
    case_id: str
    correlation_engine_version: str
    policy_version: str
    evaluated_timestamp: str

    final_score: float
    final_assessment: str
    correlation_confidence: str
    evidence_coverage_percent: float

    engine_breakdown: Dict[str, EngineSignalResponseData] = {}
    top_evidence: List[TopEvidenceResponseItem] = []
    evidence_graph: Dict[str, Any] = {}
    conflicts: List[CorrelationConflictResponseItem] = []
    limitations: List[str] = []

    explanation: str
    upstream_versions: Dict[str, Any] = {}
    disclaimer: str


@router.get(
    "/{case_id}/correlation",
    response_model=CorrelationResponse,
    summary="Get correlated final forensic assessment",
    description="Synthesizes Rules, ML, IOC, and Geo/Origin evidence into an explainable forensic risk assessment.",
)
def get_case_correlation(
    case_id: str,
    db: Session = Depends(get_db),
):
    case = db.query(Case).filter(Case.case_id == case_id).one_or_none()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )

    corr_rec = (
        db.query(CorrelationResultRecord)
        .filter(CorrelationResultRecord.case_id == case_id)
        .one_or_none()
    )

    if not corr_rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Correlation assessment for case '{case_id}' not found or pending",
        )

    engine_breakdown = {}
    if corr_rec.engine_breakdown_json:
        try:
            raw_eb = json.loads(corr_rec.engine_breakdown_json)
            for k, v in raw_eb.items():
                engine_breakdown[k] = EngineSignalResponseData(**v)
        except Exception:
            engine_breakdown = {}

    top_evidence = []
    if corr_rec.top_evidence_json:
        try:
            raw_te = json.loads(corr_rec.top_evidence_json)
            top_evidence = [TopEvidenceResponseItem(**item) for item in raw_te]
        except Exception:
            top_evidence = []

    evidence_graph = {}
    if corr_rec.evidence_graph_json:
        try:
            evidence_graph = json.loads(corr_rec.evidence_graph_json)
        except Exception:
            evidence_graph = {}

    conflicts = []
    if corr_rec.conflicts_json:
        try:
            raw_c = json.loads(corr_rec.conflicts_json)
            conflicts = [CorrelationConflictResponseItem(**c) for c in raw_c]
        except Exception:
            conflicts = []

    limitations = []
    if corr_rec.limitations_json:
        try:
            limitations = json.loads(corr_rec.limitations_json)
        except Exception:
            limitations = []

    upstream_versions = {}
    if corr_rec.upstream_versions_json:
        try:
            upstream_versions = json.loads(corr_rec.upstream_versions_json)
        except Exception:
            upstream_versions = {}

    return CorrelationResponse(
        case_id=corr_rec.case_id,
        correlation_engine_version=corr_rec.correlation_version,
        policy_version=corr_rec.policy_version,
        evaluated_timestamp=corr_rec.evaluated_timestamp.isoformat(),
        final_score=corr_rec.final_score,
        final_assessment=corr_rec.final_assessment,
        correlation_confidence=corr_rec.correlation_confidence,
        evidence_coverage_percent=corr_rec.evidence_coverage_percent,
        engine_breakdown=engine_breakdown,
        top_evidence=top_evidence,
        evidence_graph=evidence_graph,
        conflicts=conflicts,
        limitations=limitations,
        explanation=corr_rec.explanation,
        upstream_versions=upstream_versions,
        disclaimer=corr_rec.disclaimer,
    )



# =====================================================================
# Stage 8: Forensic Audit Trail & Provenance Endpoints
# =====================================================================

from app.db.models import (
    CaseEventRecord,
    AnalysisRunRecord,
    ProvenanceSnapshotRecord,
    EvidenceManifestRecord,
)
from app.audit.models import (
    TimelineResponse,
    TimelineEventItem,
    AuditVerificationResponse,
    AnalysisRunsResponse,
    AnalysisRunItem,
    ProvenanceResponse,
    EvidenceManifestResponse,
    EvidenceArtifactItem,
)
from app.audit.service import (
    verify_case_audit_chain,
    compute_composite_manifest_sha256,
)


@router.get(
    "/{case_id}/timeline",
    response_model=TimelineResponse,
    summary="Get case forensic event timeline",
    description="Returns an append-only, chronologically ordered sequence of lifecycle and analysis events for the case.",
)
def get_case_timeline(
    case_id: str,
    db: Session = Depends(get_db),
):
    case = db.query(Case).filter(Case.case_id == case_id).one_or_none()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )

    events = (
        db.query(CaseEventRecord)
        .filter(CaseEventRecord.case_id == case_id)
        .order_by(CaseEventRecord.event_sequence.asc())
        .all()
    )

    items = []
    for ev in events:
        try:
            meta = json.loads(ev.metadata_json) if ev.metadata_json else {}
        except Exception:
            meta = {}

        items.append(
            TimelineEventItem(
                event_id=ev.id,
                case_id=ev.case_id,
                event_sequence=ev.event_sequence,
                event_type=ev.event_type,
                event_timestamp=ev.event_timestamp.isoformat(),
                actor_type=ev.actor_type,
                actor_id=ev.actor_id,
                message=ev.message,
                metadata=meta,
                previous_event_hash=ev.previous_event_hash,
                event_hash=ev.event_hash,
            )
        )

    return TimelineResponse(
        case_id=case_id,
        total_events=len(items),
        events=items,
    )


@router.get(
    "/{case_id}/audit/verify",
    response_model=AuditVerificationResponse,
    summary="Verify case audit hash-chain integrity",
    description="Validates cryptographic hash chaining and sequence continuity across all recorded case events to detect tampering.",
)
def verify_audit_trail(
    case_id: str,
    db: Session = Depends(get_db),
):
    case = db.query(Case).filter(Case.case_id == case_id).one_or_none()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )

    return verify_case_audit_chain(case_id=case_id, db=db)


@router.get(
    "/{case_id}/analysis-runs",
    response_model=AnalysisRunsResponse,
    summary="Get case analytical engine runs",
    description="Returns detailed execution history, input/output fingerprints, and versions for all engine runs associated with the case.",
)
def get_case_analysis_runs(
    case_id: str,
    db: Session = Depends(get_db),
):
    case = db.query(Case).filter(Case.case_id == case_id).one_or_none()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )

    runs = (
        db.query(AnalysisRunRecord)
        .filter(AnalysisRunRecord.case_id == case_id)
        .order_by(AnalysisRunRecord.started_timestamp.asc())
        .all()
    )

    items = []
    for r in runs:
        duration = None
        if r.completed_timestamp and r.started_timestamp:
            duration = round((r.completed_timestamp - r.started_timestamp).total_seconds(), 3)

        items.append(
            AnalysisRunItem(
                run_id=r.run_id,
                engine_name=r.engine_name,
                status=r.status,
                started_timestamp=r.started_timestamp.isoformat(),
                completed_timestamp=r.completed_timestamp.isoformat() if r.completed_timestamp else None,
                duration_seconds=duration,
                error_message=r.error_message,
                engine_version=r.engine_version,
                model_version=r.model_version,
                feed_version=r.feed_version,
                input_fingerprint=r.input_fingerprint,
                output_fingerprint=r.output_fingerprint,
            )
        )

    return AnalysisRunsResponse(
        case_id=case_id,
        total_runs=len(items),
        runs=items,
    )


@router.get(
    "/{case_id}/provenance",
    response_model=ProvenanceResponse,
    summary="Get case analytical provenance snapshot",
    description="Returns the exact software, engine, model, feed versions and cryptographic digests utilized during case evaluation.",
)
def get_case_provenance(
    case_id: str,
    db: Session = Depends(get_db),
):
    case = db.query(Case).filter(Case.case_id == case_id).one_or_none()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )

    snap = (
        db.query(ProvenanceSnapshotRecord)
        .filter(ProvenanceSnapshotRecord.case_id == case_id)
        .order_by(ProvenanceSnapshotRecord.created_timestamp.desc())
        .first()
    )

    if not snap:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Provenance snapshot not yet generated for case '{case_id}'",
        )

    return ProvenanceResponse(
        case_id=snap.case_id,
        created_timestamp=snap.created_timestamp.isoformat(),
        parser_version=snap.parser_version,
        rules_engine_version=snap.rules_engine_version,
        ml_model_version=snap.ml_model_version,
        ml_preprocessing_version=snap.ml_preprocessing_version,
        ioc_engine_version=snap.ioc_engine_version,
        ioc_feed_version=snap.ioc_feed_version,
        ioc_feed_sha256=snap.ioc_feed_sha256,
        geo_analysis_version=snap.geo_analysis_version,
        geo_database_version=snap.geo_database_version,
        geo_database_sha256=snap.geo_database_sha256,
        network_feed_version=snap.network_feed_version,
        network_feed_sha256=snap.network_feed_sha256,
        correlation_engine_version=snap.correlation_engine_version,
        correlation_policy_version=snap.correlation_policy_version,
        raw_evidence_sha256=snap.raw_evidence_sha256,
        attachment_manifest_sha256=snap.attachment_manifest_sha256,
    )


@router.get(
    "/{case_id}/evidence-manifest",
    response_model=EvidenceManifestResponse,
    summary="Get case evidence and artifact manifest",
    description="Returns the comprehensive cryptographic catalog of primary evidence and derived analytical artifacts with individual and composite SHA-256 digests.",
)
def get_evidence_manifest(
    case_id: str,
    db: Session = Depends(get_db),
):
    case = db.query(Case).filter(Case.case_id == case_id).one_or_none()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )

    manifest_entries = (
        db.query(EvidenceManifestRecord)
        .filter(EvidenceManifestRecord.case_id == case_id)
        .order_by(EvidenceManifestRecord.id.asc())
        .all()
    )

    if not manifest_entries:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence manifest not yet generated for case '{case_id}'",
        )

    composite_sha = compute_composite_manifest_sha256(manifest_entries)

    artifacts = [
        EvidenceArtifactItem(
            artifact_id=m.id,
            artifact_type=m.artifact_type,
            artifact_name=m.artifact_name,
            relative_path=m.relative_path,
            size_bytes=m.size_bytes,
            sha256=m.sha256,
            created_timestamp=m.created_timestamp.isoformat(),
            source=m.source,
            immutable=m.immutable,
        )
        for m in manifest_entries
    ]

    return EvidenceManifestResponse(
        case_id=case_id,
        raw_evidence_sha256=case.sha256,
        manifest_sha256=composite_sha,
        total_artifacts=len(artifacts),
        artifacts=artifacts,
    )
