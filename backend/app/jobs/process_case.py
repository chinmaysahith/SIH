import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from rq import get_current_job

from app.config import (
    PARSER_VERSION,
    IOC_ENGINE_VERSION,
    GEO_ANALYSIS_VERSION,
    CORRELATION_ENGINE_VERSION,
    CORRELATION_POLICY_VERSION,
)
from app.db.database import SessionLocal
from app.db.models import (
    Case,
    ParsedData,
    RuleResultRecord,
    MLResultRecord,
    IOCResultRecord,
    GeoOriginResultRecord,
    CorrelationResultRecord,
)
from app.parser.eml_parser import parse_email
from app.rules import evaluate_rules
from app.ml import ML_MODEL_VERSION, predict_email
from app.ioc import evaluate_iocs
from app.geo import evaluate_geo_origin
from app.correlation import evaluate_correlation

# Stage 8 Audit Trail & Forensic Lifecycle
from app.audit import (
    AuditEventType,
    EngineName,
    RunStatus,
    record_event,
    start_analysis_run,
    finish_analysis_run,
    record_evidence_manifest,
    create_provenance_snapshot,
)

logger = logging.getLogger("email_forensics.worker")


def calculate_sha256(file_path: Path) -> str:
    """Computes the SHA-256 hash of a file on disk."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def process_case(case_id: str, force_rerun: bool = False) -> dict:
    """Stage 2 through Stage 8 worker job:
    1. Confirms case exists.
    2. Idempotency check: returns existing analysis if complete unless force_rerun is True.
    3. Confirms evidence file exists on disk.
    4. PRE-CHECK: Verifies quarantined file SHA-256 matches case record.
    5. Records PROCESSING_STARTED event (or ANALYSIS_RERUN if rerunning).
    6. Explicitly handles .msg vs .eml.
    7. Executes Stage 2 Parser with audit event and analysis run tracking.
    8. Executes Stage 3 Rules Engine with audit event and analysis run tracking.
    9. Executes Stage 4 ML Engine with audit event and analysis run tracking.
    10. Executes Stage 5 IOC Engine with audit event and analysis run tracking.
    11. Executes Stage 6 Geo / Origin Forensics with audit event and analysis run tracking.
    12. Executes Stage 7 Correlation Engine with audit event and analysis run tracking.
    13. Records Evidence Manifest and Provenance Snapshot.
    14. Updates case status to 'complete'.
    15. POST-CHECK: Asserts quarantined file SHA-256 remains 100% unchanged.
        If corrupted, records EVIDENCE_INTEGRITY_FAILURE and sets status to 'failed'.
    """
    job = get_current_job()
    job_id: Optional[str] = job.id if job else None

    logger.info(
        "JOB STARTED: case_id=%s, job_id=%s, timestamp=%s",
        case_id,
        job_id,
        datetime.now(timezone.utc).isoformat(),
    )

    with SessionLocal() as db:
        case = db.query(Case).filter(Case.case_id == case_id).one_or_none()

        # 1. Confirm case exists in database
        if not case:
            err_msg = f"Case {case_id} not found in database"
            logger.error("JOB FAILED: case_id=%s, error=%s", case_id, err_msg)
            return {"case_id": case_id, "status": "failed", "error": err_msg}

        # 2. Idempotency check
        existing_parsed = db.query(ParsedData).filter(ParsedData.case_id == case_id).one_or_none()
        existing_rules = db.query(RuleResultRecord).filter(RuleResultRecord.case_id == case_id).one_or_none()
        existing_ml = db.query(MLResultRecord).filter(MLResultRecord.case_id == case_id).one_or_none()
        existing_ioc = db.query(IOCResultRecord).filter(IOCResultRecord.case_id == case_id).first()
        existing_geo = db.query(GeoOriginResultRecord).filter(GeoOriginResultRecord.case_id == case_id).one_or_none()
        existing_corr = db.query(CorrelationResultRecord).filter(CorrelationResultRecord.case_id == case_id).one_or_none()

        is_already_complete = (
            case.status == "complete"
            and existing_parsed
            and existing_rules
            and existing_ml
            and existing_ioc
            and existing_geo
            and existing_corr
        )

        if is_already_complete and not force_rerun:
            logger.info("JOB SKIPPED (IDEMPOTENT): case_id=%s is already evaluated and correlated", case_id)
            return {
                "case_id": case_id,
                "status": "complete",
                "rules_verdict": existing_rules.rules_verdict,
                "total_score": existing_rules.total_score,
                "ml_prediction": existing_ml.prediction,
                "phishing_probability": existing_ml.phishing_probability,
                "origin_ip": existing_geo.selected_origin_ip,
                "origin_confidence": existing_geo.confidence,
                "final_score": existing_corr.final_score,
                "final_assessment": existing_corr.final_assessment,
                "correlation_confidence": existing_corr.correlation_confidence,
                "idempotent": True,
            }

        # 3. Confirm quarantined file exists on disk
        stored_path = Path(case.stored_path)
        if not stored_path.exists() or not stored_path.is_file():
            err_msg = f"Quarantined evidence file not found at {case.stored_path}"
            case.status = "failed"
            case.error_message = err_msg
            case.processing_completed_at = datetime.now(timezone.utc)
            record_event(
                case_id=case_id,
                event_type=AuditEventType.CASE_ANALYSIS_FAILED,
                message=err_msg,
                db=db,
                metadata={"error": err_msg},
            )
            db.commit()
            logger.error("JOB FAILED: case_id=%s, error=%s", case_id, err_msg)
            return {"case_id": case_id, "status": "failed", "error": err_msg}

        # 4. CRITICAL FORENSIC PRE-CHECK: Verify evidence SHA-256 before parsing
        pre_hash = calculate_sha256(stored_path)
        if pre_hash != case.sha256:
            err_msg = (
                f"FORENSIC INTEGRITY VIOLATION: Disk hash ({pre_hash}) does not match "
                f"registered case hash ({case.sha256})"
            )
            case.status = "failed"
            case.error_message = err_msg
            case.processing_completed_at = datetime.now(timezone.utc)
            record_event(
                case_id=case_id,
                event_type=AuditEventType.EVIDENCE_INTEGRITY_FAILURE,
                message=err_msg,
                db=db,
                metadata={"expected_sha256": case.sha256, "computed_sha256": pre_hash},
            )
            db.commit()
            logger.critical("INTEGRITY ERROR: case_id=%s, error=%s", case_id, err_msg)
            return {"case_id": case_id, "status": "failed", "error": err_msg}

        # 5. Transition status: queued -> processing
        is_rerun = is_already_complete and force_rerun
        case.status = "processing"
        case.processing_started_at = datetime.now(timezone.utc)
        if job_id and not case.job_id:
            case.job_id = job_id

        if is_rerun:
            record_event(
                case_id=case_id,
                event_type=AuditEventType.ANALYSIS_RERUN,
                message="Case analysis rerun triggered by analyst/system",
                db=db,
                metadata={"job_id": job_id},
            )
        else:
            record_event(
                case_id=case_id,
                event_type=AuditEventType.PROCESSING_STARTED,
                message="Background forensic analysis processing started",
                db=db,
                metadata={"job_id": job_id, "pre_hash": pre_hash},
            )
        db.commit()

        # 6. Check format: .msg vs .eml
        if case.file_extension == ".msg":
            err_msg = "Outlook MSG binary format is not supported by Stage 2 EML parser"
            parsed_record = ParsedData(
                case_id=case_id,
                parser_version=PARSER_VERSION,
                parsed_timestamp=datetime.now(timezone.utc),
                parser_status="unsupported_format",
                error_message=err_msg,
            )
            db.merge(parsed_record)
            case.status = "failed"
            case.error_message = err_msg
            case.processing_completed_at = datetime.now(timezone.utc)
            record_event(
                case_id=case_id,
                event_type=AuditEventType.PARSER_FAILED,
                message=err_msg,
                db=db,
                metadata={"error": err_msg, "file_extension": case.file_extension},
            )
            record_event(
                case_id=case_id,
                event_type=AuditEventType.CASE_ANALYSIS_FAILED,
                message=f"Analysis aborted: {err_msg}",
                db=db,
                metadata={"error": err_msg},
            )
            db.commit()
            logger.warning("UNSUPPORTED FORMAT: case_id=%s is .msg file", case_id)
            return {"case_id": case_id, "status": "failed", "error": err_msg}

        # 7. STAGE 2: Parse raw bytes
        record_event(
            case_id=case_id,
            event_type=AuditEventType.PARSER_STARTED,
            message=f"Initiating MIME parsing using parser v{PARSER_VERSION}",
            db=db,
            metadata={"parser_version": PARSER_VERSION, "input_sha256": pre_hash},
        )
        run_parser = start_analysis_run(
            case_id=case_id,
            engine_name=EngineName.PARSER,
            input_payload={"raw_sha256": pre_hash, "file_size": case.file_size},
            db=db,
            engine_version=PARSER_VERSION,
        )

        try:
            with open(stored_path, "rb") as f:
                raw_bytes = f.read()

            parsed_email = parse_email(raw_bytes, case_id=case_id)

            parsed_record = ParsedData(
                case_id=case_id,
                parser_version=parsed_email.parser_version,
                parsed_timestamp=parsed_email.parsed_timestamp,
                headers_json=json.dumps(parsed_email.headers, default=str),
                received_headers_json=json.dumps(parsed_email.received_headers),
                sender_json=json.dumps(parsed_email.sender.model_dump() if parsed_email.sender else None),
                recipients_json=json.dumps({k: [r.model_dump() for r in v] for k, v in parsed_email.recipients.items()}),
                subject=parsed_email.subject,
                body_text=parsed_email.body_text,
                body_html=parsed_email.body_html,
                urls_json=json.dumps(parsed_email.urls),
                attachments_json=json.dumps([a.model_dump() for a in parsed_email.attachments]),
                parser_status=parsed_email.parser_status,
                error_message=parsed_email.error_message,
            )

            # Upsert parsed_record
            existing = db.query(ParsedData).filter(ParsedData.case_id == case_id).one_or_none()
            if existing:
                db.delete(existing)
                db.flush()
            db.add(parsed_record)
            db.flush()

            finish_analysis_run(
                run_rec=run_parser,
                status=RunStatus.COMPLETED,
                db=db,
                output_payload={"urls_count": len(parsed_email.urls), "attachments_count": len(parsed_email.attachments), "status": parsed_email.parser_status},
            )
            record_event(
                case_id=case_id,
                event_type=AuditEventType.PARSER_COMPLETED,
                message=f"Parser v{PARSER_VERSION} completed successfully ({len(parsed_email.urls)} URLs, {len(parsed_email.attachments)} attachments extracted)",
                db=db,
                metadata={"urls_count": len(parsed_email.urls), "attachments_count": len(parsed_email.attachments)},
            )
        except Exception as exc:
            err_msg = f"Unexpected parser failure: {str(exc)}"
            finish_analysis_run(run_rec=run_parser, status=RunStatus.FAILED, db=db, error_message=err_msg)
            record_event(case_id=case_id, event_type=AuditEventType.PARSER_FAILED, message=err_msg, db=db, metadata={"error": err_msg})
            case.status = "failed"
            case.error_message = err_msg
            case.processing_completed_at = datetime.now(timezone.utc)
            record_event(case_id=case_id, event_type=AuditEventType.CASE_ANALYSIS_FAILED, message=err_msg, db=db, metadata={"error": err_msg})
            db.commit()
            logger.exception("Parser exception for case %s", case_id)
            return {"case_id": case_id, "status": "failed", "error": err_msg}

        # 8. STAGE 3: Evaluate Rules Engine if parser succeeded
        rules_summary = None
        if parsed_email.parser_status == "success":
            record_event(
                case_id=case_id,
                event_type=AuditEventType.RULES_STARTED,
                message="Evaluating deterministic RFC and security rules",
                db=db,
            )
            run_rules = start_analysis_run(
                case_id=case_id,
                engine_name=EngineName.RULES,
                input_payload={"headers": parsed_email.headers, "urls": parsed_email.urls, "attachments": [a.model_dump() for a in parsed_email.attachments]},
                db=db,
                engine_version="1.0.0",
            )
            try:
                rules_summary = evaluate_rules(parsed_email)
                rule_record = RuleResultRecord(
                    case_id=case_id,
                    rules_engine_version=rules_summary.rules_engine_version,
                    evaluated_timestamp=datetime.now(timezone.utc),
                    total_score=rules_summary.total_score,
                    rules_verdict=rules_summary.verdict.value,
                    matched_rules_count=rules_summary.matched_rules_count,
                    total_rules_evaluated=rules_summary.total_rules_evaluated,
                    category_scores_json=json.dumps(rules_summary.category_scores),
                    results_json=json.dumps([r.model_dump() for r in rules_summary.results]),
                )
                existing_r = db.query(RuleResultRecord).filter(
                    RuleResultRecord.case_id == case_id,
                    RuleResultRecord.rules_engine_version == rules_summary.rules_engine_version
                ).one_or_none()
                if existing_r:
                    db.delete(existing_r)
                    db.flush()
                db.add(rule_record)
                db.flush()

                finish_analysis_run(
                    run_rec=run_rules,
                    status=RunStatus.COMPLETED,
                    db=db,
                    output_payload={"verdict": rules_summary.verdict.value, "score": rules_summary.total_score, "matched_rules": rules_summary.matched_rules_count},
                )
                record_event(
                    case_id=case_id,
                    event_type=AuditEventType.RULES_COMPLETED,
                    message=f"Rules Engine completed: score {rules_summary.total_score}, verdict {rules_summary.verdict.value} ({rules_summary.matched_rules_count} rules matched)",
                    db=db,
                    metadata={"total_score": rules_summary.total_score, "verdict": rules_summary.verdict.value, "matched_rules": rules_summary.matched_rules_count},
                )
            except Exception as r_exc:
                err_msg = f"Rules engine failure: {r_exc}"
                finish_analysis_run(run_rec=run_rules, status=RunStatus.FAILED, db=db, error_message=err_msg)
                record_event(case_id=case_id, event_type=AuditEventType.RULES_FAILED, message=err_msg, db=db, metadata={"error": str(r_exc)})
                logger.exception("Rules engine failure for case %s: %s", case_id, r_exc)

        # 9. STAGE 4: Evaluate ML Engine independently if parser succeeded
        ml_result = None
        if parsed_email.parser_status == "success":
            record_event(
                case_id=case_id,
                event_type=AuditEventType.ML_STARTED,
                message="Evaluating statistical text phishing classifier",
                db=db,
            )
            run_ml = start_analysis_run(
                case_id=case_id,
                engine_name=EngineName.ML,
                input_payload={"subject": parsed_email.subject, "body_len": len(parsed_email.body_text or "")},
                db=db,
                model_version=ML_MODEL_VERSION,
            )
            try:
                ml_result = predict_email(parsed_email)
                ml_record = MLResultRecord(
                    case_id=case_id,
                    model_version=ml_result.model_version,
                    preprocessing_version=ml_result.preprocessing_version,
                    prediction_timestamp=ml_result.prediction_timestamp,
                    prediction=ml_result.prediction.value,
                    phishing_probability=ml_result.phishing_probability,
                    confidence=ml_result.confidence.value,
                    model_status=ml_result.model_status.value,
                    features_json=json.dumps([f.model_dump() for f in ml_result.top_features]),
                    error_message=ml_result.error_message,
                )
                # Delete any existing ML records for this case to maintain single active result invariant
                db.query(MLResultRecord).filter(MLResultRecord.case_id == case_id).delete()
                db.flush()
                db.add(ml_record)
                db.flush()

                finish_analysis_run(
                    run_rec=run_ml,
                    status=RunStatus.COMPLETED,
                    db=db,
                    output_payload={"pred": ml_result.prediction.value, "prob": ml_result.phishing_probability, "status": ml_result.model_status.value},
                )
                record_event(
                    case_id=case_id,
                    event_type=AuditEventType.ML_COMPLETED,
                    message=f"ML Engine completed: prediction {ml_result.prediction.value} (probability {ml_result.phishing_probability:.2f}, {ml_result.confidence.value} conf)",
                    db=db,
                    metadata={"prediction": ml_result.prediction.value, "probability": ml_result.phishing_probability, "model_status": ml_result.model_status.value},
                )
            except Exception as m_exc:
                err_msg = f"ML engine failure: {m_exc}"
                finish_analysis_run(run_rec=run_ml, status=RunStatus.FAILED, db=db, error_message=err_msg)
                record_event(case_id=case_id, event_type=AuditEventType.ML_FAILED, message=err_msg, db=db, metadata={"error": str(m_exc)})
                logger.exception("ML engine failure for case %s: %s", case_id, m_exc)

        # 10. STAGE 5: Evaluate IOC Analysis Engine independently if parser succeeded
        ioc_summary = None
        if parsed_email.parser_status == "success":
            record_event(
                case_id=case_id,
                event_type=AuditEventType.IOC_STARTED,
                message="Matching extracted indicators against threat intelligence feeds",
                db=db,
            )
            run_ioc = start_analysis_run(
                case_id=case_id,
                engine_name=EngineName.IOC,
                input_payload={"urls": parsed_email.urls, "sender": (parsed_email.sender.address if parsed_email.sender else None)},
                db=db,
                engine_version=IOC_ENGINE_VERSION,
            )
            try:
                ioc_summary = evaluate_iocs(parsed_email)
                db.query(IOCResultRecord).filter(IOCResultRecord.case_id == case_id).delete()
                db.flush()

                for r in ioc_summary.results:
                    db.add(
                        IOCResultRecord(
                            case_id=case_id,
                            ioc_id=r.ioc_id,
                            ioc_type=r.ioc_type.value,
                            original_value=r.original_value,
                            normalized_value=r.normalized_value,
                            source_context=r.source_context,
                            matched=r.matched,
                            status=r.status.value,
                            confidence=r.confidence,
                            source=r.source,
                            reason=r.reason,
                            feed_version=r.feed_version,
                            feed_sha256=r.feed_sha256,
                            lookup_timestamp=r.lookup_timestamp,
                            error_message=r.error_message,
                        )
                    )
                db.flush()

                finish_analysis_run(
                    run_rec=run_ioc,
                    status=RunStatus.COMPLETED,
                    db=db,
                    output_payload={"total_iocs": ioc_summary.summary.total_iocs, "malicious_iocs": ioc_summary.summary.malicious_iocs},
                )
                record_event(
                    case_id=case_id,
                    event_type=AuditEventType.IOC_COMPLETED,
                    message=f"IOC Engine completed: {ioc_summary.summary.total_iocs} indicators checked, {ioc_summary.summary.malicious_iocs} malicious matches",
                    db=db,
                    metadata={"total_iocs": ioc_summary.summary.total_iocs, "malicious_iocs": ioc_summary.summary.malicious_iocs, "suspicious_iocs": ioc_summary.summary.suspicious_iocs},
                )
            except Exception as ioc_exc:
                err_msg = f"IOC engine failure: {ioc_exc}"
                finish_analysis_run(run_rec=run_ioc, status=RunStatus.FAILED, db=db, error_message=err_msg)
                record_event(case_id=case_id, event_type=AuditEventType.IOC_FAILED, message=err_msg, db=db, metadata={"error": str(ioc_exc)})
                logger.exception("IOC engine failure for case %s: %s", case_id, ioc_exc)

        # 11. STAGE 6: Evaluate Geo / Origin Forensics Engine independently if parser succeeded
        geo_result = None
        if parsed_email.parser_status == "success":
            record_event(
                case_id=case_id,
                event_type=AuditEventType.GEO_STARTED,
                message="Evaluating Received header relay hops and origin network infrastructure",
                db=db,
            )
            run_geo = start_analysis_run(
                case_id=case_id,
                engine_name=EngineName.GEO,
                input_payload={"received_hops_count": len(parsed_email.received_headers)},
                db=db,
                engine_version=GEO_ANALYSIS_VERSION,
            )
            try:
                geo_result = evaluate_geo_origin(parsed_email)
                existing_geo_rec = db.query(GeoOriginResultRecord).filter(
                    GeoOriginResultRecord.case_id == case_id
                ).one_or_none()
                if existing_geo_rec:
                    db.delete(existing_geo_rec)
                    db.flush()

                db.add(
                    GeoOriginResultRecord(
                        case_id=case_id,
                        analysis_version=geo_result.analysis_version,
                        analysis_timestamp=datetime.fromisoformat(geo_result.analysis_timestamp),
                        selected_origin_ip=geo_result.selected_origin_ip,
                        selection_method=geo_result.selection_method,
                        confidence=geo_result.confidence.value,
                        status=geo_result.status,
                        candidate_ips_json=json.dumps([c.model_dump() for c in geo_result.candidate_ips]),
                        geo_data_json=json.dumps(geo_result.geo_data.model_dump()) if geo_result.geo_data else None,
                        network_intel_json=json.dumps(geo_result.network_intel.model_dump()) if geo_result.network_intel else None,
                        limitations_json=json.dumps(geo_result.limitations),
                        geo_database_version=geo_result.geo_data.database_version if geo_result.geo_data else None,
                        geo_database_sha256=geo_result.geo_data.database_sha256 if geo_result.geo_data else None,
                        network_feed_version=geo_result.network_intel.feed_version if geo_result.network_intel else None,
                        network_feed_sha256=geo_result.network_intel.feed_sha256 if geo_result.network_intel else None,
                        disclaimer=geo_result.disclaimer,
                        error_message=geo_result.error_message,
                    )
                )
                db.flush()

                finish_analysis_run(
                    run_rec=run_geo,
                    status=RunStatus.COMPLETED,
                    db=db,
                    output_payload={"origin_ip": geo_result.selected_origin_ip, "confidence": geo_result.confidence.value},
                )
                record_event(
                    case_id=case_id,
                    event_type=AuditEventType.GEO_COMPLETED,
                    message=f"Geo / Origin Forensics completed: selected origin {geo_result.selected_origin_ip or 'None'} ({geo_result.confidence.value} conf)",
                    db=db,
                    metadata={"selected_origin_ip": geo_result.selected_origin_ip, "confidence": geo_result.confidence.value},
                )
            except Exception as geo_exc:
                err_msg = f"Geo / Origin engine failure: {geo_exc}"
                finish_analysis_run(run_rec=run_geo, status=RunStatus.FAILED, db=db, error_message=err_msg)
                record_event(case_id=case_id, event_type=AuditEventType.GEO_FAILED, message=err_msg, db=db, metadata={"error": str(geo_exc)})
                logger.exception("Geo / Origin Forensics engine failure for case %s: %s", case_id, geo_exc)

        # 12. STAGE 7: Evaluate Correlation Engine over all persisted upstream engine results
        corr_result = None
        if parsed_email.parser_status == "success":
            record_event(
                case_id=case_id,
                event_type=AuditEventType.CORRELATION_STARTED,
                message="Synthesizing multi-signal assessment with dynamic weight renormalization",
                db=db,
            )
            run_corr = start_analysis_run(
                case_id=case_id,
                engine_name=EngineName.CORRELATION,
                input_payload={"rules_score": rules_summary.total_score if rules_summary else None, "ml_prob": ml_result.phishing_probability if ml_result else None},
                db=db,
                engine_version=CORRELATION_ENGINE_VERSION,
            )
            try:
                db.flush()
                corr_result = evaluate_correlation(case_id, db)
                existing_corr_rec = db.query(CorrelationResultRecord).filter(
                    CorrelationResultRecord.case_id == case_id
                ).one_or_none()
                if existing_corr_rec:
                    db.delete(existing_corr_rec)
                    db.flush()

                db.add(
                    CorrelationResultRecord(
                        case_id=case_id,
                        correlation_version=corr_result.correlation_engine_version,
                        policy_version=corr_result.policy_version,
                        evaluated_timestamp=datetime.fromisoformat(corr_result.evaluated_timestamp),
                        final_score=corr_result.final_score,
                        final_assessment=corr_result.final_assessment.value,
                        correlation_confidence=corr_result.correlation_confidence.value,
                        evidence_coverage_percent=corr_result.evidence_coverage.coverage_percent,
                        engine_breakdown_json=json.dumps({k: v.model_dump() for k, v in corr_result.engine_breakdown.items()}),
                        top_evidence_json=json.dumps([e.model_dump() for e in corr_result.top_evidence]),
                        evidence_graph_json=json.dumps(corr_result.evidence_graph.model_dump()),
                        conflicts_json=json.dumps([c.model_dump() for c in corr_result.conflicts]),
                        limitations_json=json.dumps(corr_result.limitations),
                        explanation=corr_result.explanation,
                        upstream_versions_json=json.dumps(corr_result.upstream_versions.model_dump()),
                        disclaimer=corr_result.disclaimer,
                    )
                )
                db.flush()

                finish_analysis_run(
                    run_rec=run_corr,
                    status=RunStatus.COMPLETED,
                    db=db,
                    output_payload={"assessment": corr_result.final_assessment.value, "score": corr_result.final_score, "conf": corr_result.correlation_confidence.value},
                )
                record_event(
                    case_id=case_id,
                    event_type=AuditEventType.CORRELATION_COMPLETED,
                    message=f"Correlation Engine completed: {corr_result.final_assessment.value} (Score {corr_result.final_score:.1f}, {corr_result.correlation_confidence.value} conf)",
                    db=db,
                    metadata={"assessment": corr_result.final_assessment.value, "score": corr_result.final_score, "confidence": corr_result.correlation_confidence.value},
                )
            except Exception as corr_exc:
                err_msg = f"Correlation engine failure: {corr_exc}"
                finish_analysis_run(run_rec=run_corr, status=RunStatus.FAILED, db=db, error_message=err_msg)
                record_event(case_id=case_id, event_type=AuditEventType.CORRELATION_FAILED, message=err_msg, db=db, metadata={"error": str(corr_exc)})
                logger.exception("Correlation engine failure for case %s: %s", case_id, corr_exc)

        # 13. STAGE 8: Create Evidence Manifest and Provenance Snapshot
        manifest_entries = record_evidence_manifest(case_id, db)
        create_provenance_snapshot(case_id, db)

        # 14. Update case status to complete
        case.status = "complete"
        case.processing_completed_at = datetime.now(timezone.utc)
        case.error_message = parsed_email.error_message
        record_event(
            case_id=case_id,
            event_type=AuditEventType.CASE_ANALYSIS_COMPLETED,
            message=f"Case analysis completed with final assessment: {corr_result.final_assessment.value if corr_result else 'N/A'}",
            db=db,
            metadata={"final_assessment": corr_result.final_assessment.value if corr_result else None, "final_score": corr_result.final_score if corr_result else None},
        )
        db.commit()
        db.refresh(case)

        # 15. CRITICAL FORENSIC POST-CHECK: Re-verify evidence was NOT mutated by any engine
        post_hash = calculate_sha256(stored_path)
        if post_hash != pre_hash:
            logger.critical("FATAL: Evidence corrupted during processing! case_id=%s", case_id)
            case.status = "failed"
            case.error_message = "Quarantined evidence file was mutated during processing!"
            record_event(
                case_id=case_id,
                event_type=AuditEventType.EVIDENCE_INTEGRITY_FAILURE,
                message="Quarantined evidence file was mutated during processing!",
                db=db,
                metadata={"expected_sha256": pre_hash, "computed_sha256": post_hash},
            )
            db.commit()
            raise IOError("Forensic violation: Quarantine file was modified during processing!")

        record_event(
            case_id=case_id,
            event_type=AuditEventType.EVIDENCE_INTEGRITY_VERIFIED,
            message=f"Post-processing evidence integrity verified (SHA-256: {post_hash}, 0 bytes altered)",
            db=db,
            metadata={"sha256": post_hash, "bytes_altered": 0},
        )
        db.commit()

        logger.info(
            "STAGE 2-8 SUCCESS: case_id=%s, assessment=%s (Score: %s, Conf: %s), status=complete",
            case_id,
            corr_result.final_assessment.value if corr_result else "N/A",
            corr_result.final_score if corr_result else "N/A",
            corr_result.correlation_confidence.value if corr_result else "N/A",
        )

        return {
            "case_id": case.case_id,
            "status": "complete",
            "parser_version": PARSER_VERSION,
            "urls_count": len(parsed_email.urls),
            "attachments_count": len(parsed_email.attachments),
            "total_score": rules_summary.total_score if rules_summary else None,
            "rules_verdict": rules_summary.verdict.value if rules_summary else None,
            "ml_prediction": ml_result.prediction.value if ml_result else None,
            "phishing_probability": ml_result.phishing_probability if ml_result else None,
            "ml_confidence": ml_result.confidence.value if ml_result else None,
            "ml_status": ml_result.model_status.value if ml_result else None,
            "ioc_total": ioc_summary.summary.total_iocs if ioc_summary else None,
            "ioc_matched": ioc_summary.summary.matched_iocs if ioc_summary else None,
            "ioc_malicious": ioc_summary.summary.malicious_iocs if ioc_summary else None,
            "origin_ip": geo_result.selected_origin_ip if geo_result else None,
            "origin_confidence": geo_result.confidence.value if geo_result else None,
            "origin_country": geo_result.geo_data.country_code if (geo_result and geo_result.geo_data) else None,
            "final_score": corr_result.final_score if corr_result else None,
            "final_assessment": corr_result.final_assessment.value if corr_result else None,
            "correlation_confidence": corr_result.correlation_confidence.value if corr_result else None,
            "evidence_coverage": corr_result.evidence_coverage.coverage_percent if corr_result else None,
        }
