"""Builder functions to assemble structured ForensicReport sections from DB records."""

import hashlib
import json
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

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
from app.reporting.models import (
    AnalysisRunItem,
    AnalysisRunsReport,
    AttachmentFindingsReport,
    AttachmentReportItem,
    AuditTimelineItem,
    AuditTimelineReport,
    CaseInfo,
    ConflictItem,
    CorrelationReport,
    EmailOverview,
    EngineSignalBreakdownItem,
    EvidenceIntegrityReport,
    EvidenceManifestReport,
    ExecutiveSummary,
    GeoFindingsReport,
    HeaderAnalysisReport,
    HeaderHopItem,
    IOCFindingsReport,
    IOCReportItem,
    ManifestArtifactItem,
    MatchedRuleItem,
    MLFeatureItem,
    MLFindingsReport,
    ProvenanceReport,
    RulesFindingsReport,
    TopEvidenceItem,
)


def is_doc_or_reserved_ip(ip_str: Optional[str]) -> bool:
    if not ip_str:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        # RFC 5737 Test-Net ranges and documentation ranges
        doc_nets = [
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        ]
        return any(ip_obj in net for net in doc_nets) or ip_obj.is_private or ip_obj.is_loopback
    except Exception:
        return False


def build_case_info(case: Case, parsed_rec: Optional[ParsedData]) -> CaseInfo:
    subject = None
    message_id = None
    sender = None
    recipients: List[str] = []
    email_date = None

    if parsed_rec:
        subject = parsed_rec.subject
        if parsed_rec.headers_json:
            try:
                headers = json.loads(parsed_rec.headers_json)
                message_id = headers.get("message-id") or headers.get("Message-ID")
                email_date = headers.get("date") or headers.get("Date")
            except Exception:
                pass

        if parsed_rec.sender_json:
            try:
                s_dict = json.loads(parsed_rec.sender_json)
                disp = s_dict.get("display_name")
                addr = s_dict.get("email") or s_dict.get("address")
                sender = f"{disp} <{addr}>" if disp and addr else (addr or disp or None)
            except Exception:
                pass

        if parsed_rec.recipients_json:
            try:
                r_list = json.loads(parsed_rec.recipients_json)
                for r in r_list:
                    if isinstance(r, dict):
                        addr = r.get("email") or r.get("address")
                        if addr:
                            recipients.append(addr)
                    elif isinstance(r, str):
                        recipients.append(r)
            except Exception:
                pass

    upload_ts = case.upload_timestamp.isoformat() if hasattr(case.upload_timestamp, "isoformat") else str(case.upload_timestamp)

    return CaseInfo(
        case_id=case.case_id,
        original_filename=case.original_filename,
        upload_timestamp=upload_ts,
        file_size_bytes=case.file_size,
        evidence_sha256=case.sha256,
        case_status=case.status,
        message_id=message_id,
        subject=subject,
        sender=sender,
        recipients=recipients,
        email_date=email_date,
    )


def build_evidence_integrity(case: Case) -> EvidenceIntegrityReport:
    p = Path(case.stored_path)
    if not p.exists():
        return EvidenceIntegrityReport(
            original_sha256=case.sha256,
            current_sha256="MISSING_ON_DISK",
            integrity_status="FILE_MISSING",
            bytes_altered=-1,
            message="CRITICAL: Quarantined evidence file is missing from storage!",
        )

    try:
        raw_bytes = p.read_bytes()
        current_sha = hashlib.sha256(raw_bytes).hexdigest()
        if current_sha == case.sha256:
            return EvidenceIntegrityReport(
                original_sha256=case.sha256,
                current_sha256=current_sha,
                integrity_status="VERIFIED",
                bytes_altered=0,
                message="Evidence byte-for-byte intact (0 bytes modified).",
            )
        else:
            diff_bytes = abs(len(raw_bytes) - case.file_size)
            return EvidenceIntegrityReport(
                original_sha256=case.sha256,
                current_sha256=current_sha,
                integrity_status="COMPROMISED",
                bytes_altered=diff_bytes,
                message="CRITICAL: Evidence integrity verification failed! Disk hash does not match original SHA-256.",
            )
    except Exception as exc:
        return EvidenceIntegrityReport(
            original_sha256=case.sha256,
            current_sha256="READ_ERROR",
            integrity_status="COMPROMISED",
            bytes_altered=-1,
            message=f"CRITICAL: Failed to read quarantined evidence file: {exc}",
        )


def build_email_overview(parsed_rec: Optional[ParsedData]) -> Optional[EmailOverview]:
    if not parsed_rec:
        return None

    sender_from = "Not available"
    if parsed_rec.sender_json:
        try:
            s_dict = json.loads(parsed_rec.sender_json)
            disp = s_dict.get("display_name")
            addr = s_dict.get("email") or s_dict.get("address")
            sender_from = f"{disp} <{addr}>" if disp and addr else (addr or disp or "Not available")
        except Exception:
            pass

    to_list = []
    cc_list = []
    reply_to = None
    date_str = None
    msg_id = None
    return_path = None
    content_type = None

    if parsed_rec.headers_json:
        try:
            hdrs = json.loads(parsed_rec.headers_json)
            reply_to = hdrs.get("reply-to") or hdrs.get("Reply-To")
            date_str = hdrs.get("date") or hdrs.get("Date")
            msg_id = hdrs.get("message-id") or hdrs.get("Message-ID")
            return_path = hdrs.get("return-path") or hdrs.get("Return-Path")
            content_type = hdrs.get("content-type") or hdrs.get("Content-Type")
        except Exception:
            pass

    if parsed_rec.recipients_json:
        try:
            r_list = json.loads(parsed_rec.recipients_json)
            for r in r_list:
                if isinstance(r, dict):
                    addr = r.get("email") or r.get("address")
                    r_type = r.get("recipient_type", "to")
                    if addr:
                        if r_type == "cc":
                            cc_list.append(addr)
                        else:
                            to_list.append(addr)
                elif isinstance(r, str):
                    to_list.append(r)
        except Exception:
            pass

    urls_count = 0
    if parsed_rec.urls_json:
        try:
            urls_count = len(json.loads(parsed_rec.urls_json))
        except Exception:
            pass

    atts_count = 0
    if parsed_rec.attachments_json:
        try:
            atts_count = len(json.loads(parsed_rec.attachments_json))
        except Exception:
            pass

    body_snippet = None
    if parsed_rec.body_text:
        body_snippet = parsed_rec.body_text[:500]
        if len(parsed_rec.body_text) > 500:
            body_snippet += "..."

    return EmailOverview(
        sender_from=sender_from,
        to=to_list,
        cc=cc_list,
        reply_to=reply_to,
        subject=parsed_rec.subject or "(No Subject)",
        date=date_str,
        message_id=msg_id,
        return_path=return_path,
        content_type=content_type,
        body_plain_snippet=body_snippet,
        urls_count=urls_count,
        attachments_count=atts_count,
    )


def build_header_analysis(parsed_rec: Optional[ParsedData]) -> Optional[HeaderAnalysisReport]:
    if not parsed_rec or not parsed_rec.received_headers_json:
        return None

    try:
        hops_data = json.loads(parsed_rec.received_headers_json)
        hops: List[HeaderHopItem] = []
        for idx, h in enumerate(hops_data):
            hops.append(
                HeaderHopItem(
                    hop_index=idx,
                    by_host=h.get("by"),
                    from_host=h.get("from"),
                    ip=h.get("ip"),
                    timestamp=h.get("date") or h.get("timestamp"),
                    protocol=h.get("with") or h.get("protocol"),
                    raw_snippet=h.get("raw") or str(h),
                )
            )
        return HeaderAnalysisReport(
            received_chain=hops,
            total_hops=len(hops),
            notes="Received headers ordered from earliest hop to destination.",
        )
    except Exception:
        return None


def build_rules_findings(rule_rec: Optional[RuleResultRecord]) -> Optional[RulesFindingsReport]:
    if not rule_rec:
        return None

    matched_list: List[MatchedRuleItem] = []
    category_scores: Dict[str, int] = {}
    total_evaluated = 0

    if rule_rec.results_json:
        try:
            res_data = json.loads(rule_rec.results_json)
            if isinstance(res_data, dict):
                matched_raw = res_data.get("matched_rules", [])
                total_evaluated = res_data.get("total_rules_evaluated", 0)
                for mr in matched_raw:
                    matched_list.append(
                        MatchedRuleItem(
                            rule_id=mr.get("rule_id", "UNKNOWN"),
                            rule_name=mr.get("rule_name", mr.get("rule_id", "UNKNOWN")),
                            category=mr.get("category", "General"),
                            points=mr.get("points", 0),
                            severity=mr.get("severity", "MEDIUM"),
                            description=mr.get("description", ""),
                            evidence=mr.get("evidence", {}),
                        )
                    )
            elif isinstance(res_data, list):
                for mr in res_data:
                    matched_list.append(
                        MatchedRuleItem(
                            rule_id=mr.get("rule_id", "UNKNOWN"),
                            rule_name=mr.get("rule_name", mr.get("rule_id", "UNKNOWN")),
                            category=mr.get("category", "General"),
                            points=mr.get("points", 0),
                            severity=mr.get("severity", "MEDIUM"),
                            description=mr.get("description", ""),
                            evidence=mr.get("evidence", {}),
                        )
                    )
        except Exception:
            pass

    if rule_rec.category_scores_json:
        try:
            category_scores = json.loads(rule_rec.category_scores_json)
        except Exception:
            pass

    return RulesFindingsReport(
        rules_engine_version=rule_rec.rules_engine_version,
        total_score=int(rule_rec.total_score),
        verdict=getattr(rule_rec, "rules_verdict", None) or getattr(rule_rec, "verdict", "BENIGN"),
        category_scores=category_scores,
        matched_rules=matched_list,
        total_rules_evaluated=total_evaluated or len(matched_list),
        status="COMPLETED",
    )


def build_ml_findings(ml_rec: Optional[MLResultRecord]) -> Optional[MLFindingsReport]:
    if not ml_rec:
        return None

    features: List[MLFeatureItem] = []
    if ml_rec.features_json:
        try:
            feats = json.loads(ml_rec.features_json)
            for f in feats:
                features.append(
                    MLFeatureItem(
                        token=f.get("token", ""),
                        weight=float(f.get("weight", 0.0)),
                        direction=f.get("direction", "neutral"),
                    )
                )
        except Exception:
            pass

    return MLFindingsReport(
        model_version=ml_rec.model_version,
        preprocessing_version=ml_rec.preprocessing_version,
        prediction=ml_rec.prediction,
        phishing_probability=round(float(ml_rec.phishing_probability), 4),
        confidence=ml_rec.confidence,
        model_status=ml_rec.model_status,
        top_features=features,
        error_message=ml_rec.error_message,
    )


def build_ioc_findings(ioc_records: List[IOCResultRecord]) -> Optional[IOCFindingsReport]:
    if not ioc_records:
        return None

    items: List[IOCReportItem] = []
    malicious_count = 0
    suspicious_count = 0
    not_found_count = 0
    feeds = set()

    for rec in ioc_records:
        status_norm = (rec.status or "not_found").upper()
        if "MALICIOUS" in status_norm:
            malicious_count += 1
        elif "SUSPICIOUS" in status_norm:
            suspicious_count += 1
        elif "NOT_FOUND" in status_norm:
            not_found_count += 1

        if rec.feed_version:
            feeds.add(f"v{rec.feed_version} ({rec.feed_sha256[:12]}...)" if rec.feed_sha256 else f"v{rec.feed_version}")

        items.append(
            IOCReportItem(
                ioc_type=rec.ioc_type,
                value=rec.original_value,
                status=status_norm,
                matched=rec.matched,
                source=rec.source,
                confidence=rec.confidence,
                reason=rec.reason,
                feed_version=rec.feed_version,
                feed_sha256=rec.feed_sha256,
            )
        )

    return IOCFindingsReport(
        total_iocs=len(items),
        malicious_iocs=malicious_count,
        suspicious_iocs=suspicious_count,
        not_found_iocs=not_found_count,
        indicators=items,
        feed_provenance=sorted(list(feeds)),
    )


def build_attachment_findings(parsed_rec: Optional[ParsedData]) -> Optional[AttachmentFindingsReport]:
    if not parsed_rec or not parsed_rec.attachments_json:
        return AttachmentFindingsReport(total_attachments=0, attachments=[])

    try:
        att_list = json.loads(parsed_rec.attachments_json)
        items: List[AttachmentReportItem] = []
        for a in att_list:
            items.append(
                AttachmentReportItem(
                    filename=a.get("filename", "unnamed"),
                    size_bytes=int(a.get("size_bytes", 0)),
                    sha256=a.get("sha256", "UNKNOWN"),
                    content_type=a.get("content_type", "application/octet-stream"),
                )
            )
        return AttachmentFindingsReport(total_attachments=len(items), attachments=items)
    except Exception:
        return AttachmentFindingsReport(total_attachments=0, attachments=[])


def build_geo_findings(geo_rec: Optional[GeoOriginResultRecord]) -> Optional[GeoFindingsReport]:
    if not geo_rec:
        return None

    geo_data = {}
    if geo_rec.geo_data_json:
        try:
            geo_data = json.loads(geo_rec.geo_data_json)
        except Exception:
            pass

    net_intel = {}
    if geo_rec.network_intel_json:
        try:
            net_intel = json.loads(geo_rec.network_intel_json)
        except Exception:
            pass

    candidate_count = 0
    if geo_rec.candidate_ips_json:
        try:
            candidate_count = len(json.loads(geo_rec.candidate_ips_json))
        except Exception:
            pass

    limitations: List[str] = []
    if geo_rec.limitations_json:
        try:
            limitations = json.loads(geo_rec.limitations_json)
        except Exception:
            pass

    is_doc = is_doc_or_reserved_ip(geo_rec.selected_origin_ip)

    return GeoFindingsReport(
        analysis_version=geo_rec.analysis_version,
        selected_origin_ip=geo_rec.selected_origin_ip,
        selection_method=geo_rec.selection_method,
        confidence=geo_rec.confidence,
        status=geo_rec.status,
        country=geo_data.get("country_name") or geo_data.get("country_code"),
        city=geo_data.get("city"),
        asn=geo_data.get("asn"),
        asn_org=geo_data.get("asn_org"),
        is_tor=net_intel.get("is_tor_exit"),
        is_vpn=net_intel.get("is_vpn"),
        is_proxy=net_intel.get("is_proxy"),
        is_hosting=net_intel.get("is_datacenter_hosting"),
        is_documentation_range=is_doc,
        candidate_ips_count=candidate_count,
        limitations=limitations,
        disclaimer=geo_rec.disclaimer,
    )


def build_correlation_report(corr_rec: Optional[CorrelationResultRecord]) -> Optional[CorrelationReport]:
    if not corr_rec:
        return None

    engine_bd: Dict[str, EngineSignalBreakdownItem] = {}
    if corr_rec.engine_breakdown_json:
        try:
            raw_bd = json.loads(corr_rec.engine_breakdown_json)
            for eng, item in raw_bd.items():
                engine_bd[eng] = EngineSignalBreakdownItem(
                    engine_name=item.get("engine_name", eng),
                    availability=item.get("availability", "AVAILABLE"),
                    normalized_value=float(item.get("normalized_value", 0.0)),
                    effective_weight=float(item.get("effective_weight", 0.0)),
                    contribution=float(item.get("contribution", 0.0)),
                    summary_text=item.get("summary_text", ""),
                )
        except Exception:
            pass

    top_ev: List[TopEvidenceItem] = []
    if corr_rec.top_evidence_json:
        try:
            raw_ev = json.loads(corr_rec.top_evidence_json)
            for e in raw_ev:
                top_ev.append(
                    TopEvidenceItem(
                        rank=int(e.get("rank", 0)),
                        engine=e.get("engine", ""),
                        evidence_type=e.get("evidence_type", ""),
                        impact=e.get("impact", "medium"),
                        description=e.get("description", ""),
                    )
                )
        except Exception:
            pass

    conflicts: List[ConflictItem] = []
    if corr_rec.conflicts_json:
        try:
            raw_c = json.loads(corr_rec.conflicts_json)
            for c in raw_c:
                conflicts.append(
                    ConflictItem(
                        conflict_type=c.get("conflict_type", ""),
                        engines_involved=c.get("engines_involved", []),
                        description=c.get("description", ""),
                        reconciliation=c.get("reconciliation", ""),
                    )
                )
        except Exception:
            pass

    limitations: List[str] = []
    if corr_rec.limitations_json:
        try:
            limitations = json.loads(corr_rec.limitations_json)
        except Exception:
            pass

    graph_entities: List[Dict[str, Any]] = []
    if corr_rec.evidence_graph_json:
        try:
            raw_g = json.loads(corr_rec.evidence_graph_json)
            if isinstance(raw_g, dict) and "entities" in raw_g:
                graph_entities = raw_g["entities"]
            elif isinstance(raw_g, list):
                graph_entities = raw_g
        except Exception:
            pass

    return CorrelationReport(
        correlation_version=corr_rec.correlation_version,
        policy_version=corr_rec.policy_version,
        final_score=round(float(corr_rec.final_score), 1),
        final_assessment=corr_rec.final_assessment,
        correlation_confidence=corr_rec.correlation_confidence,
        evidence_coverage_percent=round(float(corr_rec.evidence_coverage_percent), 1),
        engine_breakdown=engine_bd,
        top_evidence=top_ev,
        conflicts=conflicts,
        limitations=limitations,
        evidence_graph_entities=graph_entities,
        explanation=corr_rec.explanation,
    )


def build_audit_timeline(events: List[CaseEventRecord], is_valid_chain: bool) -> Optional[AuditTimelineReport]:
    if not events:
        return None

    items: List[AuditTimelineItem] = []
    for ev in events:
        ts_str = ev.event_timestamp.isoformat() if hasattr(ev.event_timestamp, "isoformat") else str(ev.event_timestamp)
        items.append(
            AuditTimelineItem(
                event_sequence=ev.event_sequence,
                event_type=ev.event_type,
                timestamp=ts_str,
                actor=f"{ev.actor_type}" + (f":{ev.actor_id}" if ev.actor_id else ""),
                message=ev.message,
                event_hash=ev.event_hash,
            )
        )

    return AuditTimelineReport(
        audit_chain_valid=is_valid_chain,
        total_events=len(items),
        events=items,
    )


def build_analysis_runs(runs: List[AnalysisRunRecord]) -> Optional[AnalysisRunsReport]:
    if not runs:
        return None

    items: List[AnalysisRunItem] = []
    for r in runs:
        ts_str = r.started_timestamp.isoformat() if hasattr(r.started_timestamp, "isoformat") else str(r.started_timestamp)
        duration_ms = None
        if r.completed_timestamp and r.started_timestamp:
            try:
                duration_ms = int((r.completed_timestamp - r.started_timestamp).total_seconds() * 1000)
            except Exception:
                pass

        items.append(
            AnalysisRunItem(
                run_id=r.run_id,
                engine_name=r.engine_name,
                status=r.status,
                version=r.engine_version or "1.0.0",
                started_timestamp=ts_str,
                duration_ms=duration_ms,
                input_fingerprint=r.input_fingerprint,
                output_fingerprint=r.output_fingerprint,
            )
        )

    return AnalysisRunsReport(total_runs=len(items), runs=items)


def build_provenance(snap: Optional[ProvenanceSnapshotRecord]) -> Optional[ProvenanceReport]:
    if not snap:
        return None

    return ProvenanceReport(
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


def build_evidence_manifest(
    entries: List[EvidenceManifestRecord],
    composite_sha: str,
) -> Optional[EvidenceManifestReport]:
    if not entries:
        return None

    items: List[ManifestArtifactItem] = []
    for e in entries:
        items.append(
            ManifestArtifactItem(
                artifact_type=e.artifact_type,
                artifact_name=e.artifact_name,
                size_bytes=e.size_bytes,
                sha256=e.sha256,
                source=e.source,
                immutable=e.immutable,
            )
        )

    return EvidenceManifestReport(
        manifest_sha256=composite_sha,
        total_artifacts=len(items),
        artifacts=items,
    )


def build_executive_summary(
    corr_rep: Optional[CorrelationReport],
    case_status: str,
) -> ExecutiveSummary:
    if corr_rep:
        return ExecutiveSummary(
            final_assessment=corr_rep.final_assessment,
            risk_score=corr_rep.final_score,
            confidence=corr_rep.correlation_confidence,
            evidence_coverage_percent=corr_rep.evidence_coverage_percent,
            concise_summary=corr_rep.explanation,
        )

    # Fallback if correlation not yet completed or inconclusive
    return ExecutiveSummary(
        final_assessment="INCONCLUSIVE" if case_status == "complete" else "PENDING",
        risk_score=0.0,
        confidence="LOW",
        evidence_coverage_percent=0.0,
        concise_summary=f"Case analysis is in status '{case_status}'. Forensic correlation has not completed.",
    )
