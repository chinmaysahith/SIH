"""Stage 9 Forensic Reporting Service.

Orchestrates report assembly, deterministic content fingerprinting,
HTML rendering, PDF compilation, and generation history tracking.
"""

import copy
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.orm import Session

from app.audit.hashing import canonical_json, compute_fingerprint, compute_sha256
from app.audit.service import compute_composite_manifest_sha256, verify_case_audit_chain
from app.db.models import (
    AnalysisRunRecord,
    Case,
    CaseEventRecord,
    CorrelationResultRecord,
    EvidenceManifestRecord,
    GeoOriginResultRecord,
    IOCResultRecord,
    MLResultRecord,
    ParsedData,
    ProvenanceSnapshotRecord,
    ReportGenerationRecord,
    RuleResultRecord,
)
from app.reporting.builders import (
    build_analysis_runs,
    build_attachment_findings,
    build_audit_timeline,
    build_case_info,
    build_correlation_report,
    build_email_overview,
    build_evidence_integrity,
    build_evidence_manifest,
    build_executive_summary,
    build_geo_findings,
    build_header_analysis,
    build_ioc_findings,
    build_ml_findings,
    build_provenance,
    build_rules_findings,
)
from app.reporting.models import (
    ForensicReport,
    ReportHistoryItem,
    ReportHistoryResponse,
    ReportMetadata,
)
from app.reporting.pdf_generator import generate_pdf_report

logger = logging.getLogger("email_forensics.reporting")

TEMPLATE_DIR = Path(__file__).parent / "templates"
jinja_env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
)


def compute_report_sha256(report_data: Union[ForensicReport, Dict[str, Any]]) -> str:
    """Computes a deterministic content SHA-256 fingerprint for a forensic report.

    Strips runtime-volatile metadata (generated_timestamp, generation_duration_ms, report_id, report_sha256)
    so two independent report generations of the same persisted case yield the identical fingerprint.
    """
    if hasattr(report_data, "model_dump"):
        raw_dict = report_data.model_dump()
    else:
        raw_dict = copy.deepcopy(report_data)

    if "metadata" in raw_dict and isinstance(raw_dict["metadata"], dict):
        raw_dict["metadata"].pop("generated_timestamp", None)
        raw_dict["metadata"].pop("generation_duration_ms", None)
        raw_dict["metadata"].pop("report_id", None)
        raw_dict["metadata"].pop("report_sha256", None)

    return compute_fingerprint(raw_dict)


def build_forensic_report(case_id: str, db: Session) -> ForensicReport:
    """Assembles a comprehensive, structured ForensicReport from persisted platform data."""
    t_start = time.perf_counter()

    case = db.query(Case).filter(Case.case_id == case_id).one_or_none()
    if not case:
        raise ValueError(f"Case '{case_id}' not found")

    parsed_rec = db.query(ParsedData).filter(ParsedData.case_id == case_id).one_or_none()
    rule_rec = db.query(RuleResultRecord).filter(RuleResultRecord.case_id == case_id).one_or_none()
    ml_rec = db.query(MLResultRecord).filter(MLResultRecord.case_id == case_id).one_or_none()
    ioc_recs = db.query(IOCResultRecord).filter(IOCResultRecord.case_id == case_id).order_by(IOCResultRecord.id.asc()).all()
    geo_rec = db.query(GeoOriginResultRecord).filter(GeoOriginResultRecord.case_id == case_id).one_or_none()
    corr_rec = db.query(CorrelationResultRecord).filter(CorrelationResultRecord.case_id == case_id).one_or_none()
    events = db.query(CaseEventRecord).filter(CaseEventRecord.case_id == case_id).order_by(CaseEventRecord.event_sequence.asc()).all()

    chain_valid = True
    if events:
        try:
            chain_res = verify_case_audit_chain(case_id, db)
            chain_valid = chain_res.valid
        except Exception as v_err:
            logger.warning("Audit verification failed during report build: %s", v_err)
            chain_valid = False

    runs = db.query(AnalysisRunRecord).filter(AnalysisRunRecord.case_id == case_id).order_by(AnalysisRunRecord.started_timestamp.asc()).all()
    snap = db.query(ProvenanceSnapshotRecord).filter(ProvenanceSnapshotRecord.case_id == case_id).order_by(ProvenanceSnapshotRecord.created_timestamp.desc()).first()
    manifest_entries = db.query(EvidenceManifestRecord).filter(EvidenceManifestRecord.case_id == case_id).order_by(EvidenceManifestRecord.id.asc()).all()

    composite_manifest_sha = compute_composite_manifest_sha256(manifest_entries) if manifest_entries else ""

    # Build individual sections
    case_info = build_case_info(case, parsed_rec)
    evidence_integrity = build_evidence_integrity(case)
    email_overview = build_email_overview(parsed_rec)
    header_analysis = build_header_analysis(parsed_rec)
    rules_findings = build_rules_findings(rule_rec)
    ml_findings = build_ml_findings(ml_rec)
    ioc_findings = build_ioc_findings(ioc_recs)
    attachment_findings = build_attachment_findings(parsed_rec)
    geo_findings = build_geo_findings(geo_rec)
    correlation_rep = build_correlation_report(corr_rec)
    executive_summary = build_executive_summary(correlation_rep, case.status)
    audit_timeline = build_audit_timeline(events, chain_valid)
    analysis_runs = build_analysis_runs(runs)
    provenance = build_provenance(snap)
    evidence_manifest = build_evidence_manifest(manifest_entries, composite_manifest_sha)

    # Initial dummy metadata to calculate deterministic content hash
    dummy_meta = ReportMetadata(
        report_id="PROVISIONAL",
        case_id=case_id,
        report_version="1.0.0",
        generated_timestamp="1970-01-01T00:00:00Z",
        generation_duration_ms=0,
        report_sha256="",
    )

    provisional_report = ForensicReport(
        metadata=dummy_meta,
        executive_summary=executive_summary,
        case_info=case_info,
        evidence_integrity=evidence_integrity,
        email_overview=email_overview,
        header_analysis=header_analysis,
        rules_findings=rules_findings,
        ml_findings=ml_findings,
        ioc_findings=ioc_findings,
        attachment_findings=attachment_findings,
        geo_findings=geo_findings,
        correlation=correlation_rep,
        audit_timeline=audit_timeline,
        analysis_runs=analysis_runs,
        provenance=provenance,
        evidence_manifest=evidence_manifest,
    )

    report_sha256 = compute_report_sha256(provisional_report)

    t_end = time.perf_counter()
    duration_ms = int((t_end - t_start) * 1000)
    now_iso = datetime.now(timezone.utc).isoformat()
    report_id = f"rep-{uuid.uuid4().hex[:12]}"

    final_meta = ReportMetadata(
        report_id=report_id,
        case_id=case_id,
        report_version="1.0.0",
        generated_timestamp=now_iso,
        generation_duration_ms=duration_ms,
        report_sha256=report_sha256,
    )

    provisional_report.metadata = final_meta
    return provisional_report


def render_html_report(report: ForensicReport) -> str:
    """Renders self-contained printable HTML report from ForensicReport model using Jinja2 with autoescaping."""
    template = jinja_env.get_template("report_template.html")
    return template.render(report=report)


def generate_report(
    case_id: str,
    format_type: str,
    db: Session,
) -> Tuple[Any, ReportGenerationRecord]:
    """Generates a forensic report in the requested format, records generation in DB, and returns payload."""
    fmt = format_type.upper()
    if fmt not in ["JSON", "HTML", "PDF"]:
        raise ValueError(f"Unsupported report format: '{format_type}'. Supported: JSON, HTML, PDF")

    report = build_forensic_report(case_id, db)

    content: Any = None
    if fmt == "JSON":
        content = report
    elif fmt == "HTML":
        content = render_html_report(report)
    elif fmt == "PDF":
        content = generate_pdf_report(report)

    # Record generation history
    gen_rec = ReportGenerationRecord(
        report_id=report.metadata.report_id,
        case_id=case_id,
        report_version=report.metadata.report_version,
        generated_timestamp=datetime.now(timezone.utc),
        report_sha256=report.metadata.report_sha256,
        format=fmt,
        generation_status="SUCCESS",
        error_message=None,
    )
    db.add(gen_rec)
    db.commit()

    logger.info(
        "REPORT GENERATED: case_id=%s, format=%s, report_id=%s, sha256=%s",
        case_id,
        fmt,
        report.metadata.report_id,
        report.metadata.report_sha256[:12],
    )

    return content, gen_rec


def get_report_history(case_id: str, db: Session) -> ReportHistoryResponse:
    """Returns all historical report generations for a case ordered by generated_timestamp desc."""
    records = (
        db.query(ReportGenerationRecord)
        .filter(ReportGenerationRecord.case_id == case_id)
        .order_by(ReportGenerationRecord.generated_timestamp.desc())
        .all()
    )

    items = [
        ReportHistoryItem(
            report_id=r.report_id,
            format=r.format,
            version=r.report_version,
            generated_timestamp=r.generated_timestamp.isoformat(),
            report_sha256=r.report_sha256,
            status=r.generation_status,
            error_message=r.error_message,
        )
        for r in records
    ]

    return ReportHistoryResponse(
        case_id=case_id,
        total_reports=len(items),
        reports=items,
    )
