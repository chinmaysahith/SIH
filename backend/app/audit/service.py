"""Stage 8 Forensic Audit Trail & Lifecycle Service.

Provides append-only hash-chained event logging, chain verification,
engine run lifecycle tracking, provenance snapshots, and evidence manifests.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.audit.hashing import (
    canonical_json,
    compute_event_hash,
    compute_fingerprint,
    compute_sha256,
    normalize_timestamp_str,
)
from app.audit.models import (
    ActorType,
    AuditEventType,
    AuditChainVerificationError,
    AuditVerificationResponse,
    EngineName,
    RunStatus,
    ArtifactType,
)
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
    RuleResultRecord,
)

logger = logging.getLogger("email_forensics.audit")


def record_event(
    case_id: str,
    event_type: AuditEventType | str,
    message: str,
    db: Session,
    actor_type: ActorType | str = ActorType.SYSTEM,
    actor_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    flush: bool = True,
) -> CaseEventRecord:
    """Appends a new tamper-evident, hash-chained event to the case audit log.

    Atomically computes next sequence number and links previous event hash.
    """
    event_type_val = event_type.value if hasattr(event_type, "value") else str(event_type)
    actor_type_val = actor_type.value if hasattr(actor_type, "value") else str(actor_type)
    metadata_clean = metadata or {}

    # 1. Fetch latest event for this case to determine sequence & previous hash
    last_event = (
        db.query(CaseEventRecord)
        .filter(CaseEventRecord.case_id == case_id)
        .order_by(CaseEventRecord.event_sequence.desc())
        .first()
    )

    if last_event:
        event_sequence = last_event.event_sequence + 1
        previous_event_hash = last_event.event_hash
    else:
        event_sequence = 1
        previous_event_hash = None

    event_time = datetime.now(timezone.utc)
    event_time_iso = normalize_timestamp_str(event_time)

    # 2. Compute tamper-evident hash
    event_hash = compute_event_hash(
        case_id=case_id,
        event_sequence=event_sequence,
        event_type=event_type_val,
        event_timestamp_iso=event_time_iso,
        actor_type=actor_type_val,
        actor_id=actor_id,
        message=message,
        metadata=metadata_clean,
        previous_event_hash=previous_event_hash,
    )

    # 3. Create record
    rec = CaseEventRecord(
        case_id=case_id,
        event_sequence=event_sequence,
        event_type=event_type_val,
        event_timestamp=event_time,
        actor_type=actor_type_val,
        actor_id=actor_id,
        message=message,
        metadata_json=canonical_json(metadata_clean),
        previous_event_hash=previous_event_hash,
        event_hash=event_hash,
    )

    db.add(rec)
    if flush:
        db.flush()

    logger.debug(
        "AUDIT EVENT: case_id=%s, seq=%d, type=%s, hash=%s",
        case_id,
        event_sequence,
        event_type_val,
        event_hash[:12],
    )
    return rec


def verify_case_audit_chain(case_id: str, db: Session) -> AuditVerificationResponse:
    """Performs full cryptographic verification over the append-only event log for a case.

    Checks:
    1. Monotonically increasing continuous sequence numbers starting from 1.
    2. No missing, out-of-order, or duplicate sequence numbers.
    3. Hash linkage: previous_event_hash matches previous event's event_hash.
    4. Data integrity: recomputed event_hash strictly matches stored event_hash.
    """
    events = (
        db.query(CaseEventRecord)
        .filter(CaseEventRecord.case_id == case_id)
        .order_by(CaseEventRecord.event_sequence.asc())
        .all()
    )

    errors: List[AuditChainVerificationError] = []
    now_iso = datetime.now(timezone.utc).isoformat()

    if not events:
        return AuditVerificationResponse(
            case_id=case_id,
            valid=True,
            event_count=0,
            first_event_hash=None,
            last_event_hash=None,
            errors=[],
            verification_timestamp=now_iso,
        )

    expected_seq = 1
    prev_hash = None

    for ev in events:
        # Sequence continuity
        if ev.event_sequence != expected_seq:
            errors.append(
                AuditChainVerificationError(
                    event_id=ev.id,
                    event_sequence=ev.event_sequence,
                    error_type="sequence_anomaly",
                    message=f"Sequence anomaly: expected {expected_seq}, observed {ev.event_sequence}",
                )
            )

        # Hash linkage verification
        if ev.previous_event_hash != prev_hash:
            errors.append(
                AuditChainVerificationError(
                    event_id=ev.id,
                    event_sequence=ev.event_sequence,
                    error_type="previous_hash_mismatch",
                    message=f"Previous hash mismatch at sequence {ev.event_sequence}: expected {prev_hash}, observed {ev.previous_event_hash}",
                )
            )

        # Recompute event hash over content
        try:
            meta_dict = json.loads(ev.metadata_json) if ev.metadata_json else {}
        except Exception:
            meta_dict = {}

        # Handle timezone formatting cleanly
        ev_ts_iso = normalize_timestamp_str(ev.event_timestamp)
        recomputed_hash = compute_event_hash(
            case_id=ev.case_id,
            event_sequence=ev.event_sequence,
            event_type=ev.event_type,
            event_timestamp_iso=ev_ts_iso,
            actor_type=ev.actor_type,
            actor_id=ev.actor_id,
            message=ev.message,
            metadata=meta_dict,
            previous_event_hash=ev.previous_event_hash,
        )

        if recomputed_hash != ev.event_hash:
            errors.append(
                AuditChainVerificationError(
                    event_id=ev.id,
                    event_sequence=ev.event_sequence,
                    error_type="event_hash_mismatch",
                    message=f"Cryptographic digest mismatch at sequence {ev.event_sequence}: stored {ev.event_hash}, recomputed {recomputed_hash}",
                )
            )

        prev_hash = ev.event_hash
        expected_seq += 1

    return AuditVerificationResponse(
        case_id=case_id,
        valid=len(errors) == 0,
        event_count=len(events),
        first_event_hash=events[0].event_hash,
        last_event_hash=events[-1].event_hash,
        errors=errors,
        verification_timestamp=now_iso,
    )


def start_analysis_run(
    case_id: str,
    engine_name: EngineName | str,
    input_payload: Any,
    db: Session,
    engine_version: Optional[str] = None,
    model_version: Optional[str] = None,
    feed_version: Optional[str] = None,
) -> AnalysisRunRecord:
    """Initializes an explicit AnalysisRunRecord for an analytical engine execution."""
    engine_val = engine_name.value if hasattr(engine_name, "value") else str(engine_name)
    input_fp = compute_fingerprint(input_payload)
    
    # Generate distinct run_id
    run_seq = db.query(AnalysisRunRecord).filter(
        AnalysisRunRecord.case_id == case_id,
        AnalysisRunRecord.engine_name == engine_val,
    ).count() + 1
    run_id = f"RUN-{case_id}-{engine_val}-{run_seq}"

    run_rec = AnalysisRunRecord(
        case_id=case_id,
        run_id=run_id,
        engine_name=engine_val,
        status=RunStatus.STARTED.value,
        started_timestamp=datetime.now(timezone.utc),
        completed_timestamp=None,
        error_message=None,
        engine_version=engine_version,
        model_version=model_version,
        feed_version=feed_version,
        input_fingerprint=input_fp,
        output_fingerprint=None,
    )

    db.add(run_rec)
    db.flush()
    return run_rec


def finish_analysis_run(
    run_rec: AnalysisRunRecord,
    status: RunStatus | str,
    db: Session,
    output_payload: Optional[Any] = None,
    error_message: Optional[str] = None,
) -> AnalysisRunRecord:
    """Completes an AnalysisRunRecord with completion timestamp, status, and output fingerprint."""
    status_val = status.value if hasattr(status, "value") else str(status)
    run_rec.status = status_val
    run_rec.completed_timestamp = datetime.now(timezone.utc)
    run_rec.error_message = error_message
    if output_payload is not None:
        run_rec.output_fingerprint = compute_fingerprint(output_payload)

    db.flush()
    return run_rec


def record_evidence_manifest(
    case_id: str,
    db: Session,
) -> List[EvidenceManifestRecord]:
    """Scans and records all primary evidence and derived analytical artifacts for a case.

    Idempotently clears prior manifest entries for this case and writes fresh records.
    """
    db.flush()
    case = db.query(Case).filter(Case.case_id == case_id).one_or_none()
    if not case:
        return []

    # Clean old manifest rows for this case
    db.query(EvidenceManifestRecord).filter(EvidenceManifestRecord.case_id == case_id).delete()
    db.flush()

    manifest_entries: List[EvidenceManifestRecord] = []
    now = datetime.now(timezone.utc)

    # 1. Primary Evidence: Raw Email
    raw_entry = EvidenceManifestRecord(
        case_id=case_id,
        artifact_type=ArtifactType.RAW_EMAIL.value,
        artifact_name=case.original_filename,
        relative_path=case.stored_path,
        size_bytes=case.file_size,
        sha256=case.sha256,
        created_timestamp=case.upload_timestamp,
        source="quarantine",
        immutable=True,
    )
    manifest_entries.append(raw_entry)
    db.add(raw_entry)

    # 2. Extracted Attachments from ParsedData
    parsed_rec = db.query(ParsedData).filter(ParsedData.case_id == case_id).one_or_none()
    if parsed_rec and parsed_rec.attachments_json:
        try:
            att_list = json.loads(parsed_rec.attachments_json)
            for idx, att in enumerate(att_list):
                att_sha = att.get("sha256", "")
                att_name = att.get("filename") or f"attachment_{idx+1}"
                att_size = att.get("size_bytes", 0)
                att_path = att.get("stored_path")
                att_entry = EvidenceManifestRecord(
                    case_id=case_id,
                    artifact_type=ArtifactType.ATTACHMENT.value,
                    artifact_name=att_name,
                    relative_path=att_path,
                    size_bytes=att_size,
                    sha256=att_sha,
                    created_timestamp=parsed_rec.parsed_timestamp,
                    source="parser",
                    immutable=True,
                )
                manifest_entries.append(att_entry)
                db.add(att_entry)
        except Exception as exc:
            logger.warning("Failed to parse attachments_json for manifest: %s", exc)

    # 3. Derived Analytical Artifacts:
    # ParsedData
    if parsed_rec:
        p_fp = compute_fingerprint(parsed_rec.headers_json or "")
        p_entry = EvidenceManifestRecord(
            case_id=case_id,
            artifact_type=ArtifactType.PARSED_RESULT.value,
            artifact_name=f"parsed_data_v{parsed_rec.parser_version}.json",
            relative_path=None,
            size_bytes=len(parsed_rec.headers_json or ""),
            sha256=p_fp,
            created_timestamp=parsed_rec.parsed_timestamp,
            source="parser",
            immutable=False,
        )
        manifest_entries.append(p_entry)
        db.add(p_entry)

    # RuleResultRecord
    rule_rec = db.query(RuleResultRecord).filter(RuleResultRecord.case_id == case_id).one_or_none()
    if rule_rec:
        r_fp = compute_fingerprint(rule_rec.results_json or "")
        r_entry = EvidenceManifestRecord(
            case_id=case_id,
            artifact_type=ArtifactType.RULE_RESULT.value,
            artifact_name=f"rules_results_v{rule_rec.rules_engine_version}.json",
            relative_path=None,
            size_bytes=len(rule_rec.results_json or ""),
            sha256=r_fp,
            created_timestamp=rule_rec.evaluated_timestamp,
            source="rules",
            immutable=False,
        )
        manifest_entries.append(r_entry)
        db.add(r_entry)

    # MLResultRecord
    ml_rec = db.query(MLResultRecord).filter(MLResultRecord.case_id == case_id).one_or_none()
    if ml_rec:
        m_fp = compute_fingerprint({"pred": ml_rec.prediction, "prob": ml_rec.phishing_probability})
        m_entry = EvidenceManifestRecord(
            case_id=case_id,
            artifact_type=ArtifactType.ML_RESULT.value,
            artifact_name=f"ml_results_v{ml_rec.model_version}.json",
            relative_path=None,
            size_bytes=len(ml_rec.features_json or ""),
            sha256=m_fp,
            created_timestamp=ml_rec.prediction_timestamp,
            source="ml",
            immutable=False,
        )
        manifest_entries.append(m_entry)
        db.add(m_entry)

    # CorrelationResultRecord
    corr_rec = db.query(CorrelationResultRecord).filter(CorrelationResultRecord.case_id == case_id).one_or_none()
    if corr_rec:
        c_fp = compute_fingerprint({"score": corr_rec.final_score, "assessment": corr_rec.final_assessment})
        c_entry = EvidenceManifestRecord(
            case_id=case_id,
            artifact_type=ArtifactType.CORRELATION_RESULT.value,
            artifact_name=f"correlation_v{corr_rec.correlation_version}.json",
            relative_path=None,
            size_bytes=len(corr_rec.engine_breakdown_json or ""),
            sha256=c_fp,
            created_timestamp=corr_rec.evaluated_timestamp,
            source="correlation",
            immutable=False,
        )
        manifest_entries.append(c_entry)
        db.add(c_entry)

    db.flush()
    return manifest_entries


def compute_composite_manifest_sha256(manifest_entries: List[EvidenceManifestRecord]) -> str:
    """Computes a deterministic composite SHA-256 fingerprint representing the entire evidence manifest."""
    sorted_items = sorted(
        [
            {
                "artifact_type": m.artifact_type,
                "artifact_name": m.artifact_name,
                "size_bytes": m.size_bytes,
                "sha256": m.sha256,
            }
            for m in manifest_entries
        ],
        key=lambda x: (x["artifact_type"], x["artifact_name"]),
    )
    return compute_fingerprint(sorted_items)


def create_provenance_snapshot(
    case_id: str,
    db: Session,
) -> ProvenanceSnapshotRecord:
    """Captures and stores an immutable record of all software and feed versions used for a case."""
    db.flush()
    case = db.query(Case).filter(Case.case_id == case_id).one_or_none()
    parsed_rec = db.query(ParsedData).filter(ParsedData.case_id == case_id).one_or_none()
    rule_rec = db.query(RuleResultRecord).filter(RuleResultRecord.case_id == case_id).one_or_none()
    ml_rec = db.query(MLResultRecord).filter(MLResultRecord.case_id == case_id).one_or_none()
    ioc_rec = db.query(IOCResultRecord).filter(IOCResultRecord.case_id == case_id).first()
    geo_rec = db.query(GeoOriginResultRecord).filter(GeoOriginResultRecord.case_id == case_id).one_or_none()
    corr_rec = db.query(CorrelationResultRecord).filter(CorrelationResultRecord.case_id == case_id).one_or_none()

    # Calculate attachment manifest SHA if attachments exist
    attachment_manifest_sha = None
    if parsed_rec and parsed_rec.attachments_json:
        try:
            atts = json.loads(parsed_rec.attachments_json)
            if atts:
                norm_atts = sorted(
                    [{"filename": a.get("filename"), "sha256": a.get("sha256"), "size": a.get("size_bytes")} for a in atts],
                    key=lambda x: x.get("filename") or "",
                )
                attachment_manifest_sha = compute_fingerprint(norm_atts)
        except Exception:
            pass

    snap = ProvenanceSnapshotRecord(
        case_id=case_id,
        created_timestamp=datetime.now(timezone.utc),
        parser_version=parsed_rec.parser_version if parsed_rec else None,
        rules_engine_version=rule_rec.rules_engine_version if rule_rec else None,
        ml_model_version=ml_rec.model_version if ml_rec else None,
        ml_preprocessing_version=ml_rec.preprocessing_version if ml_rec else None,
        ioc_engine_version="1.0.0" if ioc_rec else None,
        ioc_feed_version=ioc_rec.feed_version if ioc_rec else None,
        ioc_feed_sha256=ioc_rec.feed_sha256 if ioc_rec else None,
        geo_analysis_version=geo_rec.analysis_version if geo_rec else None,
        geo_database_version=geo_rec.geo_database_version if geo_rec else None,
        geo_database_sha256=geo_rec.geo_database_sha256 if geo_rec else None,
        network_feed_version=geo_rec.network_feed_version if geo_rec else None,
        network_feed_sha256=geo_rec.network_feed_sha256 if geo_rec else None,
        correlation_engine_version=corr_rec.correlation_version if corr_rec else None,
        correlation_policy_version=corr_rec.policy_version if corr_rec else None,
        raw_evidence_sha256=case.sha256 if case else "UNKNOWN",
        attachment_manifest_sha256=attachment_manifest_sha,
    )

    db.add(snap)
    db.flush()
    return snap
