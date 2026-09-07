"""Comprehensive Test Suite for Stage 9 — Forensic Reporting.

Covers:
1. Report Construction & Metadata Fidelity
2. Presentation Integrity (No Recomputation / Faithfulness to Upstream)
3. Rules, ML, IOC, Geo, and Correlation Faithfulness
4. Evidence Integrity & Immutability Verification (0 Bytes Altered)
5. Audit Trail & Provenance Verification
6. Security, Sanitization & Anti-XSS Protections
7. Deterministic Report Content Hashing & History
8. Multi-Format APIs (JSON, HTML, PDF)
"""

import hashlib
import io
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.audit.hashing import canonical_json, compute_fingerprint
from app.config import QUARANTINE_DIR
from app.db.database import SessionLocal, init_db
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
from app.main import app
from app.reporting import (
    ForensicReport,
    build_forensic_report,
    compute_report_sha256,
    generate_report,
    get_report_history,
    render_html_report,
)
from app.reporting.pdf_generator import generate_pdf_report

client = TestClient(app)


def clean_case(case_id: str, db):
    """Cleans all case-related records from DB across all stages."""
    for model in [
        ReportGenerationRecord,
        EvidenceManifestRecord,
        ProvenanceSnapshotRecord,
        AnalysisRunRecord,
        CaseEventRecord,
        CorrelationResultRecord,
        GeoOriginResultRecord,
        IOCResultRecord,
        MLResultRecord,
        RuleResultRecord,
        ParsedData,
        Case,
    ]:
        db.query(model).filter(model.case_id == case_id).delete()
    db.commit()


@pytest.fixture(autouse=True)
def setup_db():
    init_db()
    yield


def seed_fully_analyzed_case(case_id: str) -> str:
    """Helper to seed a comprehensive case with records for all engines (Stages 1-8)."""
    raw_content = b"From: attacker@evil.test\r\nTo: victim@corp.test\r\nSubject: Urgent Wire\r\n\r\nHello CFO."
    raw_sha = hashlib.sha256(raw_content).hexdigest()

    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    stored_path = QUARANTINE_DIR / f"{case_id}.eml"
    stored_path.write_bytes(raw_content)

    with SessionLocal() as db:
        clean_case(case_id, db)

        # 1. Case
        case = Case(
            case_id=case_id,
            original_filename="urgent_wire.eml",
            stored_path=str(stored_path),
            sha256=raw_sha,
            file_size=len(raw_content),
            file_extension=".eml",
            status="complete",
        )
        db.add(case)

        # 2. ParsedData
        parsed = ParsedData(
            case_id=case_id,
            parser_version="1.0.0",
            headers_json=json.dumps({"from": "attacker@evil.test", "to": "victim@corp.test", "subject": "Urgent Wire", "message-id": "<msg-01@evil.test>"}),
            received_headers_json=json.dumps([
                {"by": "mail.corp.test", "from": "relay.evil.test", "ip": "198.51.100.50", "timestamp": "Sat, 06 Sep 2026 12:00:00 +0000", "raw": "Received: from relay..."}
            ]),
            sender_json=json.dumps({"display_name": "Attacker", "email": "attacker@evil.test"}),
            recipients_json=json.dumps([{"email": "victim@corp.test", "recipient_type": "to"}]),
            subject="Urgent Wire",
            body_text="Hello CFO, please transfer funds.",
            body_html="<p>Hello CFO, please transfer funds.</p>",
            urls_json=json.dumps([{"url": "http://198.51.100.50/pay", "domain": "198.51.100.50"}]),
            attachments_json=json.dumps([
                {"filename": "invoice.pdf", "size_bytes": 1024, "sha256": "att-sha256-invoice", "content_type": "application/pdf"}
            ]),
            parser_status="success",
        )
        db.add(parsed)

        # 3. Rules
        rule_rec = RuleResultRecord(
            case_id=case_id,
            rules_engine_version="1.0.0",
            total_score=65.0,
            rules_verdict="SUSPICIOUS",
            category_scores_json=json.dumps({"Header Anomaly": 20, "Content Risk": 45}),
            results_json=json.dumps({
                "total_rules_evaluated": 20,
                "matched_rules": [
                    {
                        "rule_id": "RULE-CONTENT-001",
                        "rule_name": "Urgent Language",
                        "category": "Content Risk",
                        "points": 25,
                        "severity": "HIGH",
                        "description": "Urgent wire request language detected",
                        "evidence": {"keyword": "Urgent Wire"},
                    }
                ],
            }),
        )
        db.add(rule_rec)

        # 4. ML
        ml_rec = MLResultRecord(
            case_id=case_id,
            model_version="phishing_v1",
            preprocessing_version="prep_v1",
            prediction="PHISHING",
            phishing_probability=0.8850,
            confidence="HIGH",
            model_status="ready",
            features_json=json.dumps([{"token": "wire", "weight": 0.45, "direction": "phishing"}]),
        )
        db.add(ml_rec)

        # 5. IOCs
        ioc_rec1 = IOCResultRecord(
            case_id=case_id,
            ioc_id="ioc-01",
            ioc_type="IP",
            original_value="198.51.100.50",
            normalized_value="198.51.100.50",
            source_context="Received header",
            matched=True,
            status="known_malicious",
            confidence=95,
            source="test-feed",
            reason="Malicious C2 infrastructure",
            feed_version="2026.09.1",
            feed_sha256="feed-sha-01",
        )
        ioc_rec2 = IOCResultRecord(
            case_id=case_id,
            ioc_id="ioc-02",
            ioc_type="DOMAIN",
            original_value="corp.test",
            normalized_value="corp.test",
            source_context="Recipient domain",
            matched=False,
            status="not_found",
            confidence=0,
            source="test-feed",
            reason="Indicator not present in local threat intelligence feed",
            feed_version="2026.09.1",
            feed_sha256="feed-sha-01",
        )
        db.add_all([ioc_rec1, ioc_rec2])

        # 6. Geo
        geo_rec = GeoOriginResultRecord(
            case_id=case_id,
            analysis_version="1.0.0",
            selected_origin_ip="198.51.100.50",
            selection_method="earliest_plausible_public_ip",
            confidence="HIGH",
            status="SUCCESS",
            candidate_ips_json=json.dumps([{"ip": "198.51.100.50"}]),
            geo_data_json=json.dumps({"country_name": "Netherlands", "country_code": "NL", "city": "Amsterdam", "asn": 60781, "asn_org": "LEASENEWEB"}),
            network_intel_json=json.dumps({"is_tor_exit": False, "is_vpn": True, "is_proxy": False, "is_datacenter_hosting": True}),
            limitations_json=json.dumps(["Local GeoIP dataset utilized"]),
            disclaimer="Geo/origin analysis estimates plausible network origin based on headers.",
        )
        db.add(geo_rec)

        # 7. Correlation
        corr_rec = CorrelationResultRecord(
            case_id=case_id,
            correlation_version="1.0.0",
            policy_version="1.0.0",
            final_score=82.5,
            final_assessment="HIGH_RISK",
            correlation_confidence="HIGH",
            evidence_coverage_percent=100.0,
            engine_breakdown_json=json.dumps({
                "rules": {"engine_name": "rules", "availability": "AVAILABLE", "normalized_value": 65.0, "effective_weight": 35.0, "contribution": 22.75, "summary_text": "Rules matched"},
                "ml": {"engine_name": "ml", "availability": "AVAILABLE", "normalized_value": 88.5, "effective_weight": 30.0, "contribution": 26.55, "summary_text": "ML Phishing"},
                "ioc": {"engine_name": "ioc", "availability": "AVAILABLE", "normalized_value": 95.0, "effective_weight": 25.0, "contribution": 23.75, "summary_text": "Malicious IOC"},
                "geo": {"engine_name": "geo", "availability": "AVAILABLE", "normalized_value": 94.5, "effective_weight": 10.0, "contribution": 9.45, "summary_text": "Datacenter VPN"},
            }),
            top_evidence_json=json.dumps([
                {"rank": 1, "engine": "ioc", "evidence_type": "KNOWN_MALICIOUS", "impact": "high", "description": "Known malicious IP observed in relay"},
                {"rank": 2, "engine": "ml", "evidence_type": "PHISHING_PREDICTION", "impact": "high", "description": "ML classifier indicates phishing"},
            ]),
            conflicts_json=json.dumps([]),
            limitations_json=json.dumps(["Offline local threat intelligence"]),
            evidence_graph_json=json.dumps({"entities": [{"id": "198.51.100.50", "type": "ip", "observed_by": ["rules", "ioc", "geo"]}]}),
            explanation="Multiple independent engines indicate severe phishing and fraudulent wire instructions.",
            disclaimer="The correlation score is an explainable multi-signal risk rating.",
        )
        db.add(corr_rec)

        # 8. Audit Events
        ev1 = CaseEventRecord(
            case_id=case_id,
            event_sequence=1,
            event_type="CASE_CREATED",
            actor_type="SYSTEM",
            message="Case created",
            event_hash="hash-ev-1",
        )
        ev2 = CaseEventRecord(
            case_id=case_id,
            event_sequence=2,
            event_type="EVIDENCE_STORED",
            actor_type="SYSTEM",
            message="Evidence stored",
            previous_event_hash="hash-ev-1",
            event_hash="hash-ev-2",
        )
        db.add_all([ev1, ev2])

        # 9. Analysis Runs
        t_start = datetime.now(timezone.utc)
        from datetime import timedelta
        t_end = t_start + timedelta(milliseconds=25)
        run1 = AnalysisRunRecord(
            run_id=f"run-{case_id}-01",
            case_id=case_id,
            engine_name="parser",
            status="COMPLETED",
            engine_version="1.0.0",
            started_timestamp=t_start,
            completed_timestamp=t_end,
            input_fingerprint="fp-in-1",
            output_fingerprint="fp-out-1",
        )
        db.add(run1)

        # 10. Provenance
        prov = ProvenanceSnapshotRecord(
            case_id=case_id,
            parser_version="1.0.0",
            rules_engine_version="1.0.0",
            ml_model_version="phishing_v1",
            ioc_engine_version="1.0.0",
            ioc_feed_version="2026.09.1",
            geo_analysis_version="1.0.0",
            geo_database_version="2026.09.1",
            correlation_engine_version="1.0.0",
            correlation_policy_version="1.0.0",
            raw_evidence_sha256=raw_sha,
        )
        db.add(prov)

        # 11. Evidence Manifest
        man = EvidenceManifestRecord(
            case_id=case_id,
            artifact_type="RAW_EMAIL",
            artifact_name="urgent_wire.eml",
            relative_path=str(stored_path),
            size_bytes=len(raw_content),
            sha256=raw_sha,
            source="quarantine",
            immutable=True,
        )
        db.add(man)
        db.commit()

    return raw_sha


# =====================================================================
# 1. Report Construction & Metadata Fidelity Tests
# =====================================================================

def test_1_report_generated_from_persisted_case():
    case_id = "test-rep-01"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    assert rep.case_info.case_id == case_id
    assert rep.metadata.case_id == case_id
    assert rep.metadata.report_version == "1.0.0"
    assert rep.metadata.report_sha256 is not None
    assert len(rep.metadata.report_sha256) == 64


def test_2_correct_case_metadata():
    case_id = "test-rep-02"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    assert rep.case_info.original_filename == "urgent_wire.eml"
    assert rep.case_info.subject == "Urgent Wire"
    assert "victim@corp.test" in rep.case_info.recipients
    assert "attacker@evil.test" in rep.case_info.sender


def test_3_correct_final_assessment():
    case_id = "test-rep-03"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    assert rep.executive_summary.final_assessment == "HIGH_RISK"
    assert rep.correlation.final_assessment == "HIGH_RISK"


def test_4_correct_correlation_score():
    case_id = "test-rep-04"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    assert rep.executive_summary.risk_score == 82.5
    assert rep.correlation.final_score == 82.5


def test_5_correct_confidence():
    case_id = "test-rep-05"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    assert rep.executive_summary.confidence == "HIGH"
    assert rep.correlation.correlation_confidence == "HIGH"


def test_6_correct_evidence_coverage():
    case_id = "test-rep-06"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    assert rep.executive_summary.evidence_coverage_percent == 100.0


# =====================================================================
# 2. Upstream Intelligence Faithfulness (Rules, ML, IOC, Geo)
# =====================================================================

def test_7_rules_findings_represented_correctly():
    case_id = "test-rep-07"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    assert rep.rules_findings.total_score == 65
    assert rep.rules_findings.verdict == "SUSPICIOUS"
    assert len(rep.rules_findings.matched_rules) == 1
    assert rep.rules_findings.matched_rules[0].rule_id == "RULE-CONTENT-001"
    assert rep.rules_findings.matched_rules[0].points == 25


def test_8_rules_score_not_recomputed():
    case_id = "test-rep-08"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        # Deliberately modify stored rule record score to confirm report strictly reflects DB
        r = db.query(RuleResultRecord).filter(RuleResultRecord.case_id == case_id).one()
        r.total_score = 42.0
        db.commit()

        rep = build_forensic_report(case_id, db)
    assert rep.rules_findings.total_score == 42


def test_9_ml_probability_represented_correctly():
    case_id = "test-rep-09"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    assert rep.ml_findings.prediction == "PHISHING"
    assert rep.ml_findings.phishing_probability == 0.8850
    assert rep.ml_findings.confidence == "HIGH"
    assert len(rep.ml_findings.top_features) == 1
    assert rep.ml_findings.top_features[0].token == "wire"


def test_10_ml_unavailable_handled_correctly():
    case_id = "test-rep-10"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        # Delete ML record to simulate unavailable ML engine
        db.query(MLResultRecord).filter(MLResultRecord.case_id == case_id).delete()
        db.commit()

        rep = build_forensic_report(case_id, db)
    assert rep.ml_findings is None


def test_11_ml_probability_not_described_as_fraud_probability():
    case_id = "test-rep-11"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    # The note must explicitly differentiate phishing probability from overall fraud probability
    assert "phishing-classifier" in rep.ml_findings.interpretation_note.lower()
    assert "not overall fraud probability" in rep.ml_findings.interpretation_note.lower()


def test_12_malicious_ioc_represented():
    case_id = "test-rep-12"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    assert rep.ioc_findings.malicious_iocs == 1
    malicious_item = [i for i in rep.ioc_findings.indicators if i.value == "198.51.100.50"][0]
    assert malicious_item.status == "KNOWN_MALICIOUS"
    assert malicious_item.matched is True


def test_13_not_found_ioc_remains_not_found():
    case_id = "test-rep-13"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    not_found_item = [i for i in rep.ioc_findings.indicators if i.value == "corp.test"][0]
    assert not_found_item.status == "NOT_FOUND"
    assert not_found_item.matched is False


def test_14_ioc_source_and_feed_provenance_preserved():
    case_id = "test-rep-14"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    assert any("2026.09.1" in f for f in rep.ioc_findings.feed_provenance)


def test_15_origin_information_represented():
    case_id = "test-rep-15"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    assert rep.geo_findings.selected_origin_ip == "198.51.100.50"
    assert rep.geo_findings.country == "Netherlands"
    assert rep.geo_findings.city == "Amsterdam"
    assert rep.geo_findings.asn == 60781
    assert rep.geo_findings.is_vpn is True


def test_16_geo_disclaimer_present():
    case_id = "test-rep-16"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    assert "Geo/origin analysis estimates plausible network origin" in rep.geo_findings.disclaimer


def test_17_documentation_test_ip_visibly_identified():
    case_id = "test-rep-17"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    # 198.51.100.50 is in TEST-NET-2 (RFC 5737)
    assert rep.geo_findings.is_documentation_range is True


# =====================================================================
# 3. Evidence Integrity & Invariant Tests
# =====================================================================

def test_18_raw_sha_preserved():
    case_id = "test-rep-18"
    raw_sha = seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    assert rep.case_info.evidence_sha256 == raw_sha
    assert rep.evidence_integrity.original_sha256 == raw_sha


def test_19_attachment_sha_preserved():
    case_id = "test-rep-19"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    assert rep.attachment_findings.total_attachments == 1
    assert rep.attachment_findings.attachments[0].sha256 == "att-sha256-invoice"


def test_20_evidence_manifest_represented():
    case_id = "test-rep-20"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    assert rep.evidence_manifest is not None
    assert rep.evidence_manifest.total_artifacts == 1
    assert rep.evidence_manifest.artifacts[0].artifact_type == "RAW_EMAIL"


def test_21_evidence_integrity_status_verified():
    case_id = "test-rep-21"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    assert rep.evidence_integrity.integrity_status == "VERIFIED"
    assert rep.evidence_integrity.bytes_altered == 0


def test_22_corrupted_evidence_detected_in_report():
    case_id = "test-rep-22"
    seed_fully_analyzed_case(case_id)

    # Tamper with file on disk
    p = QUARANTINE_DIR / f"{case_id}.eml"
    p.write_bytes(b"TAMPERED EVIDENCE BYTES")

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    assert rep.evidence_integrity.integrity_status == "COMPROMISED"
    assert rep.evidence_integrity.bytes_altered > 0
    assert "failed" in rep.evidence_integrity.message.lower()


# =====================================================================
# 4. Correlation & Evidence Graph
# =====================================================================

def test_23_engine_breakdown_preserved():
    case_id = "test-rep-23"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    assert "rules" in rep.correlation.engine_breakdown
    assert rep.correlation.engine_breakdown["rules"].contribution == 22.75
    assert rep.correlation.engine_breakdown["ml"].effective_weight == 30.0


def test_24_top_evidence_preserved_in_rank_order():
    case_id = "test-rep-24"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    assert len(rep.correlation.top_evidence) == 2
    assert rep.correlation.top_evidence[0].rank == 1
    assert rep.correlation.top_evidence[0].impact == "high"


def test_25_evidence_graph_represented():
    case_id = "test-rep-25"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    assert len(rep.correlation.evidence_graph_entities) == 1
    assert rep.correlation.evidence_graph_entities[0]["id"] == "198.51.100.50"


def test_26_conflicts_and_limitations_preserved():
    case_id = "test-rep-26"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    assert "Offline local threat intelligence" in rep.correlation.limitations


# =====================================================================
# 5. Audit Timeline & Provenance
# =====================================================================

def test_27_audit_timeline_included():
    case_id = "test-rep-27"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    assert rep.audit_timeline.total_events == 2
    assert rep.audit_timeline.events[0].event_sequence == 1
    assert rep.audit_timeline.events[0].event_type == "CASE_CREATED"


def test_28_analysis_runs_included():
    case_id = "test-rep-28"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    assert rep.analysis_runs.total_runs == 1
    assert rep.analysis_runs.runs[0].engine_name == "parser"
    assert rep.analysis_runs.runs[0].duration_ms == 25


def test_29_provenance_included():
    case_id = "test-rep-29"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    assert rep.provenance.parser_version == "1.0.0"
    assert rep.provenance.rules_engine_version == "1.0.0"
    assert rep.provenance.ml_model_version == "phishing_v1"
    assert rep.provenance.ioc_feed_version == "2026.09.1"
    assert rep.provenance.correlation_policy_version == "1.0.0"


def test_30_forensic_disclaimer_verbatim_present():
    case_id = "test-rep-30"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep = build_forensic_report(case_id, db)
    assert "This report presents analytical findings" in rep.forensic_disclaimer
    assert "not a mathematically calibrated probability of fraud" in rep.forensic_disclaimer


# =====================================================================
# 6. Security, XSS Sanitization & HTML Escaping
# =====================================================================

def test_31_html_xss_escaping_in_subject():
    case_id = "test-xss-01"
    seed_fully_analyzed_case(case_id)

    # Inject malicious XSS script into subject
    with SessionLocal() as db:
        p = db.query(ParsedData).filter(ParsedData.case_id == case_id).one()
        p.subject = "<script>alert('XSS_ATTACK_SUBJECT')</script>"
        db.commit()

        rep = build_forensic_report(case_id, db)
        html_out = render_html_report(rep)

    assert "<script>alert('XSS_ATTACK_SUBJECT')</script>" not in html_out
    assert "&lt;script&gt;alert(&#39;XSS_ATTACK_SUBJECT&#39;)&lt;/script&gt;" in html_out


def test_32_html_xss_escaping_in_body():
    case_id = "test-xss-02"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        p = db.query(ParsedData).filter(ParsedData.case_id == case_id).one()
        p.body_text = "<img src=x onerror=alert('XSS_BODY')>"
        db.commit()

        rep = build_forensic_report(case_id, db)
        html_out = render_html_report(rep)

    assert "<img src=x onerror=alert('XSS_BODY')>" not in html_out
    assert "&lt;img src=x onerror=alert(&#39;XSS_BODY&#39;)&gt;" in html_out


def test_33_html_xss_escaping_in_attachment_filename():
    case_id = "test-xss-03"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        p = db.query(ParsedData).filter(ParsedData.case_id == case_id).one()
        p.attachments_json = json.dumps([
            {"filename": "<svg onload=alert('XSS_ATT')>", "size_bytes": 100, "sha256": "abc", "content_type": "text/html"}
        ])
        db.commit()

        rep = build_forensic_report(case_id, db)
        html_out = render_html_report(rep)

    assert "<svg onload=alert('XSS_ATT')>" not in html_out
    assert "&lt;svg onload=alert(&#39;XSS_ATT&#39;)&gt;" in html_out


# =====================================================================
# 7. Deterministic Hashing & Generation History
# =====================================================================

def test_34_deterministic_report_content_hash():
    case_id = "test-hash-01"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        rep1 = build_forensic_report(case_id, db)
        rep2 = build_forensic_report(case_id, db)

    # Despite different generated_timestamp and report_id, the content SHA-256 must be identical!
    assert rep1.metadata.report_sha256 == rep2.metadata.report_sha256
    assert len(rep1.metadata.report_sha256) == 64


def test_35_report_generation_history_recorded():
    case_id = "test-hist-01"
    seed_fully_analyzed_case(case_id)

    with SessionLocal() as db:
        # Generate JSON and HTML reports
        generate_report(case_id, "JSON", db)
        generate_report(case_id, "HTML", db)

        history = get_report_history(case_id, db)
        assert history.total_reports >= 2
        formats = [r.format for r in history.reports]
        assert "JSON" in formats
        assert "HTML" in formats


# =====================================================================
# 8. Multi-Format REST APIs (JSON, HTML, PDF)
# =====================================================================

def test_36_api_get_report_json():
    case_id = "test-api-01"
    seed_fully_analyzed_case(case_id)

    resp = client.get(f"/api/cases/{case_id}/report")
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_info"]["case_id"] == case_id
    assert data["executive_summary"]["final_assessment"] == "HIGH_RISK"
    assert data["metadata"]["report_sha256"] is not None


def test_37_api_get_report_html():
    case_id = "test-api-02"
    seed_fully_analyzed_case(case_id)

    resp = client.get(f"/api/cases/{case_id}/report/html")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "<!DOCTYPE html>" in resp.text
    assert case_id in resp.text
    assert "FORENSIC ANALYSIS REPORT" in resp.text.upper()


def test_38_api_get_report_pdf():
    case_id = "test-api-03"
    seed_fully_analyzed_case(case_id)

    resp = client.get(f"/api/cases/{case_id}/report/pdf")
    assert resp.status_code == 200
    assert "application/pdf" in resp.headers["content-type"]
    assert resp.content.startswith(b"%PDF")
    assert len(resp.content) > 1000


def test_39_api_get_report_history():
    case_id = "test-api-04"
    seed_fully_analyzed_case(case_id)

    # Generate one report via API
    client.get(f"/api/cases/{case_id}/report")

    resp = client.get(f"/api/cases/{case_id}/reports")
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == case_id
    assert data["total_reports"] >= 1


def test_40_api_report_404_not_found():
    resp = client.get("/api/cases/non-existent-case-uuid/report")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_41_evidence_bytes_unmodified_invariant():
    case_id = "test-inv-01"
    raw_sha = seed_fully_analyzed_case(case_id)
    p = QUARANTINE_DIR / f"{case_id}.eml"
    before_bytes = p.read_bytes()

    # Generate reports in all 3 formats
    with SessionLocal() as db:
        generate_report(case_id, "JSON", db)
        generate_report(case_id, "HTML", db)
        generate_report(case_id, "PDF", db)

    after_bytes = p.read_bytes()
    assert before_bytes == after_bytes
    assert hashlib.sha256(after_bytes).hexdigest() == raw_sha
