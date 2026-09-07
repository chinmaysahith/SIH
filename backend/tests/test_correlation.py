"""
Comprehensive test suite for Stage 7 — Correlation Engine.
Tests cover:
1. Normalization of all upstream engine outputs (Rules, ML, IOC, Geo)
2. Dynamic weight renormalization under partial engine availability
3. Double counting mitigation and Evidence Graph construction
4. Asymmetric severe IOC overrides
5. Cross-engine conflict detection and confidence reduction
6. Geo/Origin context gating and low-confidence suppression
7. Minimum coverage defensibility threshold (inconclusive assessments)
8. End-to-end worker processing and 100% byte-for-byte evidence immutability
9. REST API endpoints (/api/cases/{case_id}/correlation)
10. Controlled acceptance test cases (Case A, Case B, Case C)
"""

import hashlib
import json
import pytest
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from fastapi.testclient import TestClient

from app.config import QUARANTINE_DIR
from app.db.database import SessionLocal, init_db
from app.db.models import (
    Case,
    CorrelationResultRecord,
    GeoOriginResultRecord,
    IOCResultRecord,
    MLResultRecord,
    ParsedData,
    RuleResultRecord,
)
from app.correlation.models import (
    CorrelationConfidence,
    CorrelationResult,
    EngineSignal,
    EvidenceCoverage,
    FinalAssessment,
    SignalAvailability,
)
from app.correlation.policy import (
    DEFAULT_ENGINE_WEIGHTS,
    ENTITY_OVERLAP_DISCOUNT_FACTOR,
    MIN_COVERAGE_FOR_ASSESSMENT,
    SEVERE_IOC_CONFIDENCE_THRESHOLD,
    SEVERE_IOC_MIN_SCORE,
    THRESHOLD_BENIGN_MAX,
    THRESHOLD_SUSPICIOUS_MAX,
)
from app.correlation.normalizer import (
    normalize_geo_signal,
    normalize_ioc_signal,
    normalize_ml_signal,
    normalize_rules_signal,
)
from app.correlation.evidence_graph import build_evidence_graph
from app.correlation.engine import (
    CorrelationEngine,
    evaluate_correlation,
    get_correlation_engine,
)
from app.jobs.process_case import process_case
from app.main import app

client = TestClient(app)


def clean_case(case_id: str, db):
    """Helper to cleanly purge all related rows across stages for a case_id."""
    for model in [CorrelationResultRecord, GeoOriginResultRecord, IOCResultRecord, MLResultRecord, RuleResultRecord, ParsedData, Case]:
        db.query(model).filter(model.case_id == case_id).delete()
    db.commit()


@pytest.fixture(autouse=True)
def setup_test_db():
    """Ensures test database tables exist before each test."""
    init_db()
    yield


# =====================================================================
# 1. Normalization Tests (Rules, ML, IOC, Geo)
# =====================================================================

def test_1_rules_normalization_valid():
    rec = RuleResultRecord(
        case_id="case-1",
        rules_engine_version="1.0.0",
        total_score=82,
        rules_verdict="HIGH_RISK",
        matched_rules_count=5,
        total_rules_evaluated=20,
        results_json="[]",
        category_scores_json="{}",
    )
    sig = normalize_rules_signal(rec)
    assert sig.availability == SignalAvailability.AVAILABLE
    assert sig.normalized_value == 0.82
    assert sig.base_weight == 0.35
    assert sig.contribution == round(0.82 * 0.35 * 100, 2)


def test_2_rules_normalization_missing():
    sig = normalize_rules_signal(None)
    assert sig.availability == SignalAvailability.UNAVAILABLE
    assert sig.normalized_value == 0.0
    assert sig.contribution == 0.0


def test_3_rules_normalization_caps_at_100():
    rec = RuleResultRecord(
        case_id="case-1",
        rules_engine_version="1.0.0",
        total_score=150,
        rules_verdict="HIGH_RISK",
        matched_rules_count=10,
        total_rules_evaluated=20,
        results_json="[]",
        category_scores_json="{}",
    )
    sig = normalize_rules_signal(rec)
    assert sig.normalized_value == 1.0


def test_4_ml_normalization_ready():
    rec = MLResultRecord(
        case_id="case-1",
        model_version="1.0.0",
        preprocessing_version="1.0.0",
        prediction="PHISHING",
        phishing_probability=0.88,
        confidence="HIGH",
        model_status="ready",
    )
    sig = normalize_ml_signal(rec)
    assert sig.availability == SignalAvailability.AVAILABLE
    assert sig.normalized_value == 0.88
    assert sig.contribution == round(0.88 * 0.30 * 100, 2)


def test_5_ml_normalization_insufficient_text():
    rec = MLResultRecord(
        case_id="case-1",
        model_version="1.0.0",
        preprocessing_version="1.0.0",
        prediction="UNCERTAIN",
        phishing_probability=0.5,
        confidence="LOW",
        model_status="insufficient_text",
    )
    sig = normalize_ml_signal(rec)
    assert sig.availability == SignalAvailability.UNAVAILABLE
    assert sig.normalized_value == 0.0


def test_6_ml_normalization_missing():
    sig = normalize_ml_signal(None)
    assert sig.availability == SignalAvailability.UNAVAILABLE
    assert sig.normalized_value == 0.0


def test_7_ioc_normalization_empty():
    sig, has_conflict = normalize_ioc_signal([])
    assert sig.availability == SignalAvailability.AVAILABLE
    assert sig.normalized_value == 0.0
    assert not has_conflict


def test_8_ioc_normalization_malicious():
    recs = [
        IOCResultRecord(
            case_id="case-1",
            ioc_id="1",
            ioc_type="domain",
            original_value="malicious.test",
            normalized_value="malicious.test",
            source_context="url",
            status="known_malicious",
            confidence=95,
            source="test",
            reason="phishing",
            feed_version="1.0",
        )
    ]
    sig, has_conflict = normalize_ioc_signal(recs)
    assert sig.availability == SignalAvailability.AVAILABLE
    assert sig.normalized_value >= 0.85
    assert not has_conflict


def test_9_ioc_normalization_suspicious():
    recs = [
        IOCResultRecord(
            case_id="case-1",
            ioc_id="1",
            ioc_type="domain",
            original_value="suspicious.test",
            normalized_value="suspicious.test",
            source_context="url",
            status="known_suspicious",
            confidence=60,
            source="test",
            reason="redirector",
            feed_version="1.0",
        )
    ]
    sig, has_conflict = normalize_ioc_signal(recs)
    assert sig.availability == SignalAvailability.AVAILABLE
    assert 0.50 <= sig.normalized_value <= 0.70
    assert not has_conflict


def test_10_ioc_normalization_not_found():
    recs = [
        IOCResultRecord(
            case_id="case-1",
            ioc_id="1",
            ioc_type="domain",
            original_value="unknown.test",
            normalized_value="unknown.test",
            source_context="url",
            status="not_found",
            confidence=0,
            source="test",
            reason="not found",
            feed_version="1.0",
        )
    ]
    sig, has_conflict = normalize_ioc_signal(recs)
    assert sig.availability == SignalAvailability.AVAILABLE
    assert sig.normalized_value == 0.0
    assert "not_found != benign" in sig.summary_text.lower()


def test_11_ioc_normalization_benign():
    recs = [
        IOCResultRecord(
            case_id="case-1",
            ioc_id="1",
            ioc_type="domain",
            original_value="safe.test",
            normalized_value="safe.test",
            source_context="url",
            status="known_benign",
            confidence=90,
            source="test",
            reason="safe",
            feed_version="1.0",
        )
    ]
    sig, has_conflict = normalize_ioc_signal(recs)
    assert sig.availability == SignalAvailability.AVAILABLE
    assert sig.normalized_value <= 0.05


def test_12_ioc_normalization_conflict_detection():
    recs = [
        IOCResultRecord(
            case_id="case-1",
            ioc_id="1",
            ioc_type="domain",
            original_value="shared.test",
            normalized_value="shared.test",
            source_context="url",
            status="known_malicious",
            confidence=90,
            source="feed-a",
            reason="phish",
            feed_version="1.0",
        ),
        IOCResultRecord(
            case_id="case-1",
            ioc_id="2",
            ioc_type="domain",
            original_value="shared.test",
            normalized_value="shared.test",
            source_context="url",
            status="known_benign",
            confidence=90,
            source="feed-b",
            reason="benign",
            feed_version="1.0",
        ),
    ]
    sig, has_conflict = normalize_ioc_signal(recs)
    assert has_conflict is True


def test_13_geo_normalization_missing():
    sig = normalize_geo_signal(None)
    assert sig.availability == SignalAvailability.UNAVAILABLE
    assert sig.normalized_value == 0.0


def test_14_geo_normalization_tor_exit_high_conf():
    rec = GeoOriginResultRecord(
        case_id="case-1",
        analysis_version="1.0.0",
        selected_origin_ip="198.51.100.50",
        confidence="HIGH",
        network_intel_json=json.dumps({"is_tor_exit": True, "is_vpn": False, "is_proxy": False, "is_datacenter_hosting": True}),
        disclaimer="test",
    )
    sig = normalize_geo_signal(rec)
    assert sig.availability == SignalAvailability.AVAILABLE
    assert sig.normalized_value >= 0.35
    assert "Tor Exit" in sig.summary_text


def test_15_geo_normalization_unknown_origin_confidence():
    rec = GeoOriginResultRecord(
        case_id="case-1",
        analysis_version="1.0.0",
        selected_origin_ip="198.51.100.50",
        confidence="UNKNOWN",
        network_intel_json=json.dumps({"is_tor_exit": True}),
        disclaimer="test",
    )
    sig = normalize_geo_signal(rec)
    assert sig.normalized_value == 0.0


def test_16_geo_normalization_benign_consumer_ip():
    rec = GeoOriginResultRecord(
        case_id="case-1",
        analysis_version="1.0.0",
        selected_origin_ip="203.0.113.1",
        confidence="HIGH",
        network_intel_json=json.dumps({"is_tor_exit": False, "is_vpn": False, "is_proxy": False, "is_datacenter_hosting": False}),
        disclaimer="test",
    )
    sig = normalize_geo_signal(rec)
    assert sig.normalized_value == 0.0


# =====================================================================
# 2. Evidence Graph & Double Counting Prevention Tests
# =====================================================================

def test_17_evidence_graph_cross_engine_detection():
    rule_rec = RuleResultRecord(
        case_id="case-overlap",
        rules_engine_version="1.0.0",
        total_score=35,
        rules_verdict="SUSPICIOUS",
        matched_rules_count=1,
        total_rules_evaluated=20,
        results_json=json.dumps([
            {"rule_id": "RULE-URL-003", "fired": True, "title": "IP Host", "score": 15, "evidence": {"urls": ["http://203.0.113.10/login"]}}
        ]),
        category_scores_json="{}",
    )
    ioc_records = [
        IOCResultRecord(
            case_id="case-overlap",
            ioc_id="ioc-1",
            ioc_type="ip",
            original_value="203.0.113.10",
            normalized_value="203.0.113.10",
            source_context="url",
            status="known_malicious",
            confidence=90,
            source="test",
            reason="malware",
            feed_version="1.0",
        )
    ]
    geo_rec = GeoOriginResultRecord(
        case_id="case-overlap",
        analysis_version="1.0.0",
        selected_origin_ip="203.0.113.10",
        confidence="HIGH",
        network_intel_json=json.dumps({"is_datacenter_hosting": True}),
        disclaimer="test",
    )

    graph = build_evidence_graph(rule_rec, ioc_records, geo_rec)
    assert graph.cross_engine_entity_count >= 1
    ip_entity = next(e for e in graph.entities if e.value == "203.0.113.10")
    assert ip_entity.is_cross_engine is True
    engines = {obs.engine for obs in ip_entity.observations}
    assert engines == {"RULES", "IOC", "GEO"}


def test_18_evidence_graph_no_overlap():
    rule_rec = RuleResultRecord(
        case_id="case-no-overlap",
        rules_engine_version="1.0.0",
        total_score=10,
        rules_verdict="BENIGN",
        matched_rules_count=0,
        total_rules_evaluated=20,
        results_json="[]",
        category_scores_json="{}",
    )
    ioc_records = [
        IOCResultRecord(
            case_id="case-no-overlap",
            ioc_id="ioc-1",
            ioc_type="domain",
            original_value="different.domain.test",
            normalized_value="different.domain.test",
            source_context="body",
            status="known_benign",
            confidence=90,
            source="test",
            reason="safe",
            feed_version="1.0",
        )
    ]
    geo_rec = GeoOriginResultRecord(
        case_id="case-no-overlap",
        analysis_version="1.0.0",
        selected_origin_ip="198.51.100.1",
        confidence="HIGH",
        network_intel_json="{}",
        disclaimer="test",
    )
    graph = build_evidence_graph(rule_rec, ioc_records, geo_rec)
    assert graph.cross_engine_entity_count == 0


# =====================================================================
# 3. Dynamic Weight Renormalization & Coverage Tests
# =====================================================================

def test_19_dynamic_renormalization_missing_ml_and_geo():
    case_id = "test-renorm-01"
    with SessionLocal() as db:
        clean_case(case_id, db)
        db.add(Case(case_id=case_id, original_filename="test.eml", stored_path="p", sha256="h", file_size=10, file_extension=".eml", status="complete"))
        db.add(RuleResultRecord(case_id=case_id, rules_engine_version="1.0.0", total_score=80, rules_verdict="HIGH_RISK", matched_rules_count=4, total_rules_evaluated=20, results_json="[]", category_scores_json="{}"))
        db.add(IOCResultRecord(case_id=case_id, ioc_id="1", ioc_type="domain", original_value="test.test", normalized_value="test.test", source_context="url", status="not_found", confidence=0, source="s", reason="r", feed_version="1.0"))
        db.commit()

        res = evaluate_correlation(case_id, db)
        assert res.evidence_coverage.coverage_percent == 60.0  # Rules (35) + IOC (25) = 60%
        assert round(res.engine_breakdown["rules"].effective_weight, 2) == 0.58
        assert round(res.engine_breakdown["ioc"].effective_weight, 2) == 0.42
        assert res.engine_breakdown["ml"].availability == SignalAvailability.UNAVAILABLE
        assert res.engine_breakdown["geo"].availability == SignalAvailability.UNAVAILABLE


def test_20_coverage_below_threshold_inconclusive():
    case_id = "test-inconclusive-01"
    with SessionLocal() as db:
        clean_case(case_id, db)
        db.add(Case(case_id=case_id, original_filename="test.eml", stored_path="p", sha256="h", file_size=10, file_extension=".eml", status="complete"))
        # Only Geo available (10% coverage, below 40% threshold)
        db.add(GeoOriginResultRecord(case_id=case_id, analysis_version="1.0.0", selected_origin_ip="1.1.1.1", confidence="HIGH", disclaimer="d"))
        db.commit()

        res = evaluate_correlation(case_id, db)
        assert res.evidence_coverage.coverage_percent == 10.0
        assert res.final_assessment == FinalAssessment.INCONCLUSIVE
        assert any("below minimum defensibility" in lim.lower() for lim in res.limitations)


def test_21_zero_coverage_inconclusive():
    case_id = "test-inconclusive-zero"
    with SessionLocal() as db:
        clean_case(case_id, db)
        db.add(Case(case_id=case_id, original_filename="test.eml", stored_path="p", sha256="h", file_size=10, file_extension=".eml", status="complete"))
        db.commit()

        res = evaluate_correlation(case_id, db)
        assert res.evidence_coverage.coverage_percent == 0.0
        assert res.final_assessment == FinalAssessment.INCONCLUSIVE


# =====================================================================
# 4. Controlled Scenarios (Cases A, B, C)
# =====================================================================

def test_22_case_a_strong_agreement_high_risk():
    case_id = "test-case-a-agreement"
    with SessionLocal() as db:
        clean_case(case_id, db)
        db.add(Case(case_id=case_id, original_filename="test.eml", stored_path="p", sha256="h", file_size=10, file_extension=".eml", status="complete"))
        db.add(RuleResultRecord(case_id=case_id, rules_engine_version="1.0.0", total_score=85, rules_verdict="HIGH_RISK", matched_rules_count=5, total_rules_evaluated=20, results_json="[]", category_scores_json="{}"))
        db.add(MLResultRecord(case_id=case_id, model_version="1.0.0", preprocessing_version="1.0.0", prediction="PHISHING", phishing_probability=0.92, confidence="HIGH", model_status="ready"))
        db.add(IOCResultRecord(case_id=case_id, ioc_id="1", ioc_type="domain", original_value="phish.test", normalized_value="phish.test", source_context="url", status="known_malicious", confidence=95, source="feed", reason="phish", feed_version="1.0"))
        db.add(GeoOriginResultRecord(case_id=case_id, analysis_version="1.0.0", selected_origin_ip="198.51.100.50", confidence="HIGH", network_intel_json=json.dumps({"is_tor_exit": True}), disclaimer="d"))
        db.commit()

        res = evaluate_correlation(case_id, db)
        assert res.final_assessment == FinalAssessment.HIGH_RISK
        assert res.final_score >= 80.0
        assert res.correlation_confidence == CorrelationConfidence.HIGH
        assert not res.conflicts


def test_23_case_b_conflicting_signals():
    case_id = "test-case-b-conflict"
    with SessionLocal() as db:
        clean_case(case_id, db)
        db.add(Case(case_id=case_id, original_filename="test.eml", stored_path="p", sha256="h", file_size=10, file_extension=".eml", status="complete"))
        # Rules High, ML Legitimate, IOC Not Found
        db.add(RuleResultRecord(case_id=case_id, rules_engine_version="1.0.0", total_score=75, rules_verdict="HIGH_RISK", matched_rules_count=4, total_rules_evaluated=20, results_json="[]", category_scores_json="{}"))
        db.add(MLResultRecord(case_id=case_id, model_version="1.0.0", preprocessing_version="1.0.0", prediction="LEGITIMATE", phishing_probability=0.15, confidence="HIGH", model_status="ready"))
        db.add(IOCResultRecord(case_id=case_id, ioc_id="1", ioc_type="domain", original_value="test.test", normalized_value="test.test", source_context="url", status="not_found", confidence=0, source="feed", reason="not found", feed_version="1.0"))
        db.add(GeoOriginResultRecord(case_id=case_id, analysis_version="1.0.0", selected_origin_ip="1.1.1.1", confidence="HIGH", network_intel_json="{}", disclaimer="d"))
        db.commit()

        res = evaluate_correlation(case_id, db)
        assert len(res.conflicts) > 0
        assert res.conflicts[0].conflict_type == "RULES_ML_DISAGREEMENT"
        assert res.correlation_confidence in (CorrelationConfidence.MEDIUM, CorrelationConfidence.LOW)
        assert res.final_assessment in (FinalAssessment.SUSPICIOUS, FinalAssessment.HIGH_RISK)


def test_24_case_c_severe_ioc_asymmetric_override():
    case_id = "test-case-c-ioc-override"
    with SessionLocal() as db:
        clean_case(case_id, db)
        db.add(Case(case_id=case_id, original_filename="test.eml", stored_path="p", sha256="h", file_size=10, file_extension=".eml", status="complete"))
        # Rules Low (0), ML Low (0.05), but IOC Malicious (98% conf)
        db.add(RuleResultRecord(case_id=case_id, rules_engine_version="1.0.0", total_score=0, rules_verdict="BENIGN", matched_rules_count=0, total_rules_evaluated=20, results_json="[]", category_scores_json="{}"))
        db.add(MLResultRecord(case_id=case_id, model_version="1.0.0", preprocessing_version="1.0.0", prediction="LEGITIMATE", phishing_probability=0.05, confidence="HIGH", model_status="ready"))
        db.add(IOCResultRecord(case_id=case_id, ioc_id="1", ioc_type="domain", original_value="malicious-c2.test", normalized_value="malicious-c2.test", source_context="body", status="known_malicious", confidence=98, source="feed", reason="c2", feed_version="1.0"))
        db.commit()

        res = evaluate_correlation(case_id, db)
        assert res.final_assessment == FinalAssessment.HIGH_RISK
        assert res.final_score >= SEVERE_IOC_MIN_SCORE
        assert any("Asymmetric Override" in lim for lim in res.limitations)


def test_25_all_benign_assessment():
    case_id = "test-all-benign"
    with SessionLocal() as db:
        clean_case(case_id, db)
        db.add(Case(case_id=case_id, original_filename="test.eml", stored_path="p", sha256="h", file_size=10, file_extension=".eml", status="complete"))
        db.add(RuleResultRecord(case_id=case_id, rules_engine_version="1.0.0", total_score=5, rules_verdict="BENIGN", matched_rules_count=0, total_rules_evaluated=20, results_json="[]", category_scores_json="{}"))
        db.add(MLResultRecord(case_id=case_id, model_version="1.0.0", preprocessing_version="1.0.0", prediction="LEGITIMATE", phishing_probability=0.02, confidence="HIGH", model_status="ready"))
        db.add(IOCResultRecord(case_id=case_id, ioc_id="1", ioc_type="domain", original_value="safe.test", normalized_value="safe.test", source_context="url", status="known_benign", confidence=90, source="feed", reason="safe", feed_version="1.0"))
        db.add(GeoOriginResultRecord(case_id=case_id, analysis_version="1.0.0", selected_origin_ip="1.1.1.1", confidence="HIGH", network_intel_json="{}", disclaimer="d"))
        db.commit()

        res = evaluate_correlation(case_id, db)
        assert res.final_assessment == FinalAssessment.BENIGN
        assert res.final_score < THRESHOLD_BENIGN_MAX
        assert res.correlation_confidence == CorrelationConfidence.HIGH


def test_26_suspicious_borderline():
    case_id = "test-suspicious-border"
    with SessionLocal() as db:
        clean_case(case_id, db)
        db.add(Case(case_id=case_id, original_filename="test.eml", stored_path="p", sha256="h", file_size=10, file_extension=".eml", status="complete"))
        db.add(RuleResultRecord(case_id=case_id, rules_engine_version="1.0.0", total_score=45, rules_verdict="SUSPICIOUS", matched_rules_count=2, total_rules_evaluated=20, results_json="[]", category_scores_json="{}"))
        db.add(MLResultRecord(case_id=case_id, model_version="1.0.0", preprocessing_version="1.0.0", prediction="UNCERTAIN", phishing_probability=0.45, confidence="LOW", model_status="ready"))
        db.commit()

        res = evaluate_correlation(case_id, db)
        assert res.final_assessment == FinalAssessment.SUSPICIOUS
        assert THRESHOLD_BENIGN_MAX <= res.final_score <= THRESHOLD_SUSPICIOUS_MAX


# =====================================================================
# 5. Entity Overlap Deduction & Double Counting Tests
# =====================================================================

def test_27_entity_overlap_deduction_applied():
    case_id = "test-overlap-deduction"
    with SessionLocal() as db:
        clean_case(case_id, db)
        db.add(Case(case_id=case_id, original_filename="test.eml", stored_path="p", sha256="h", file_size=10, file_extension=".eml", status="complete"))
        
        # Rule references IP 203.0.113.5
        db.add(RuleResultRecord(
            case_id=case_id,
            rules_engine_version="1.0.0",
            total_score=60,
            rules_verdict="SUSPICIOUS",
            matched_rules_count=2,
            total_rules_evaluated=20,
            results_json=json.dumps([
                {"rule_id": "RULE-URL-003", "fired": True, "title": "IP Host", "score": 20, "evidence": {"urls": ["http://203.0.113.5/login"]}}
            ]),
            category_scores_json="{}"
        ))
        # IOC references same IP
        db.add(IOCResultRecord(
            case_id=case_id,
            ioc_id="1",
            ioc_type="ip",
            original_value="203.0.113.5",
            normalized_value="203.0.113.5",
            source_context="url",
            status="known_suspicious",
            confidence=60,
            source="feed",
            reason="vpn",
            feed_version="1.0"
        ))
        db.commit()

        res = evaluate_correlation(case_id, db)
        assert res.evidence_graph.cross_engine_entity_count >= 1
        assert any("Double-Counting Mitigation" in lim for lim in res.limitations)


# =====================================================================
# 6. Top Evidence Item Ranking Tests
# =====================================================================

def test_28_top_evidence_ranking_order():
    case_id = "test-top-evidence"
    with SessionLocal() as db:
        clean_case(case_id, db)
        db.add(Case(case_id=case_id, original_filename="test.eml", stored_path="p", sha256="h", file_size=10, file_extension=".eml", status="complete"))
        db.add(RuleResultRecord(case_id=case_id, rules_engine_version="1.0.0", total_score=80, rules_verdict="HIGH_RISK", matched_rules_count=3, total_rules_evaluated=20, results_json="[]", category_scores_json="{}"))
        db.add(MLResultRecord(case_id=case_id, model_version="1.0.0", preprocessing_version="1.0.0", prediction="PHISHING", phishing_probability=0.95, confidence="HIGH", model_status="ready"))
        db.add(IOCResultRecord(case_id=case_id, ioc_id="1", ioc_type="domain", original_value="c2.test", normalized_value="c2.test", source_context="body", status="known_malicious", confidence=99, source="feed", reason="c2", feed_version="1.0"))
        db.commit()

        res = evaluate_correlation(case_id, db)
        assert len(res.top_evidence) >= 2
        assert res.top_evidence[0].impact == "high"
        for idx, item in enumerate(res.top_evidence):
            assert item.rank == idx + 1


# =====================================================================
# 7. Confidence Lowering on Multiple Conflicts
# =====================================================================

def test_29_multiple_conflicts_drops_confidence_to_low():
    case_id = "test-multi-conflicts"
    with SessionLocal() as db:
        clean_case(case_id, db)
        db.add(Case(case_id=case_id, original_filename="test.eml", stored_path="p", sha256="h", file_size=10, file_extension=".eml", status="complete"))
        # Rules High (80), ML Low (0.10) => conflict 1
        db.add(RuleResultRecord(case_id=case_id, rules_engine_version="1.0.0", total_score=80, rules_verdict="HIGH_RISK", matched_rules_count=4, total_rules_evaluated=20, results_json="[]", category_scores_json="{}"))
        db.add(MLResultRecord(case_id=case_id, model_version="1.0.0", preprocessing_version="1.0.0", prediction="LEGITIMATE", phishing_probability=0.10, confidence="HIGH", model_status="ready"))
        # IOC conflict: both malicious and benign present => conflict 2
        db.add(IOCResultRecord(case_id=case_id, ioc_id="1", ioc_type="domain", original_value="d.test", normalized_value="d.test", source_context="u", status="known_malicious", confidence=90, source="f", reason="r", feed_version="1.0"))
        db.add(IOCResultRecord(case_id=case_id, ioc_id="2", ioc_type="domain", original_value="d.test", normalized_value="d.test", source_context="u", status="known_benign", confidence=90, source="f", reason="r", feed_version="1.0"))
        db.commit()

        res = evaluate_correlation(case_id, db)
        assert len(res.conflicts) >= 2
        assert res.correlation_confidence == CorrelationConfidence.LOW


# =====================================================================
# 8. Engine Singleton and Disclaimer Invariant
# =====================================================================

def test_30_engine_singleton_and_disclaimer():
    eng1 = get_correlation_engine()
    eng2 = get_correlation_engine()
    assert eng1 is eng2
    assert "NOT a mathematically calibrated probability" in eng1.disclaimer


# =====================================================================
# 9. API Endpoint Tests
# =====================================================================

def test_31_api_get_correlation_not_found():
    resp = client.get("/api/cases/nonexistent-case-id-404/correlation")
    assert resp.status_code == 404


def test_32_api_get_correlation_success():
    case_id = "test-case-api-corr-01"
    with SessionLocal() as db:
        clean_case(case_id, db)
        db.add(Case(case_id=case_id, original_filename="test.eml", stored_path="p", sha256="h", file_size=10, file_extension=".eml", status="complete"))
        db.add(
            CorrelationResultRecord(
                case_id=case_id,
                correlation_version="1.0.0",
                policy_version="1.0.0",
                evaluated_timestamp=datetime.now(timezone.utc),
                final_score=85.5,
                final_assessment="HIGH_RISK",
                correlation_confidence="HIGH",
                evidence_coverage_percent=100.0,
                engine_breakdown_json=json.dumps({
                    "rules": {"engine_name": "rules", "availability": "available", "normalized_value": 0.8, "base_weight": 0.35, "effective_weight": 0.35, "contribution": 28.0, "summary_text": "Rules score 80"}
                }),
                top_evidence_json=json.dumps([
                    {"rank": 1, "engine": "IOC", "evidence_type": "threat_intel_match", "impact": "high", "description": "Malicious domain"}
                ]),
                evidence_graph_json="{}",
                conflicts_json="[]",
                limitations_json="[]",
                explanation="Test explanation",
                upstream_versions_json="{}",
                disclaimer="Disclaimer",
            )
        )
        db.commit()

    resp = client.get(f"/api/cases/{case_id}/correlation")
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == case_id
    assert data["final_score"] == 85.5
    assert data["final_assessment"] == "HIGH_RISK"
    assert data["correlation_confidence"] == "HIGH"


def test_33_api_get_correlation_schema_validation():
    case_id = "test-case-schema-val"
    with SessionLocal() as db:
        clean_case(case_id, db)
        db.add(Case(case_id=case_id, original_filename="test.eml", stored_path="p", sha256="h", file_size=10, file_extension=".eml", status="complete"))
        db.add(
            CorrelationResultRecord(
                case_id=case_id,
                correlation_version="1.0.0",
                policy_version="1.0.0",
                evaluated_timestamp=datetime.now(timezone.utc),
                final_score=45.0,
                final_assessment="SUSPICIOUS",
                correlation_confidence="MEDIUM",
                evidence_coverage_percent=60.0,
                engine_breakdown_json=json.dumps({
                    "rules": {"engine_name": "rules", "availability": "available", "normalized_value": 0.45, "base_weight": 0.35, "effective_weight": 0.58, "contribution": 26.1, "summary_text": "Rules"}
                }),
                top_evidence_json="[]",
                evidence_graph_json=json.dumps({"entities": [], "cross_engine_entity_count": 0, "total_entity_count": 0, "entity_overlap_discount_applied": 0.0}),
                conflicts_json="[]",
                limitations_json=json.dumps(["Notice"]),
                explanation="Suspicious due to rules.",
                upstream_versions_json=json.dumps({"rules_version": "1.0.0"}),
                disclaimer="Disclaimer notice",
            )
        )
        db.commit()

    resp = client.get(f"/api/cases/{case_id}/correlation")
    assert resp.status_code == 200
    body = resp.json()
    assert "evidence_graph" in body
    assert "limitations" in body
    assert isinstance(body["limitations"], list)


# =====================================================================
# 10. End-to-End Worker, Idempotency & Evidence Immutability
# =====================================================================

def test_34_worker_end_to_end_correlation_pipeline():
    case_id = "test-case-worker-corr-e2e"

    with SessionLocal() as db:
        clean_case(case_id, db)

    msg = MIMEMultipart()
    msg["From"] = "security@malicious-phish-bank.test"
    msg["To"] = "target@company.test"
    msg["Subject"] = "Urgent: Your account is suspended"
    msg["Message-ID"] = f"<{case_id}@test.local>"
    msg["Received"] = "from relay.internal (10.0.0.1) by dest.internal; Fri, 05 Sep 2026 12:00:00 +0000"
    msg["Received"] = "from tor-node.test (198.51.100.50) by relay.internal; Fri, 05 Sep 2026 11:59:00 +0000"

    msg.attach(MIMEText("Please verify credentials immediately at http://malicious-phish-bank.test/login.", "plain"))
    raw_bytes = msg.as_bytes()
    expected_hash = hashlib.sha256(raw_bytes).hexdigest()

    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    stored_path = QUARANTINE_DIR / f"{case_id}.eml"
    with open(stored_path, "wb") as f:
        f.write(raw_bytes)

    with SessionLocal() as db:
        case = Case(
            case_id=case_id,
            original_filename="worker_corr_test.eml",
            stored_path=str(stored_path),
            sha256=expected_hash,
            file_size=len(raw_bytes),
            file_extension=".eml",
            status="queued",
        )
        db.merge(case)
        db.commit()

    # Run full worker job
    result = process_case(case_id)
    assert result["status"] == "complete"
    assert result["final_assessment"] == "HIGH_RISK"
    assert result["final_score"] is not None
    assert result["correlation_confidence"] is not None

    # FORENSIC INVARIANT: verify raw file on disk is byte-for-byte identical (0 bytes mutated)
    with open(stored_path, "rb") as f:
        post_bytes = f.read()
    assert post_bytes == raw_bytes
    assert hashlib.sha256(post_bytes).hexdigest() == expected_hash

    # Verify Correlation record persisted in database
    with SessionLocal() as db:
        rec = db.query(CorrelationResultRecord).filter(CorrelationResultRecord.case_id == case_id).one_or_none()
        assert rec is not None
        assert rec.final_assessment == "HIGH_RISK"
        assert rec.evidence_coverage_percent >= 90.0

    # Verify API returns correlation
    api_resp = client.get(f"/api/cases/{case_id}/correlation")
    assert api_resp.status_code == 200
    assert api_resp.json()["final_assessment"] == "HIGH_RISK"


def test_35_worker_correlation_idempotent():
    """Verify that re-running process_case does not duplicate records or alter evidence."""
    case_id = "test-case-worker-corr-e2e"
    stored_path = QUARANTINE_DIR / f"{case_id}.eml"
    with open(stored_path, "rb") as f:
        before_bytes = f.read()

    # Running process_case a second time should return complete immediately (idempotency)
    result = process_case(case_id)
    assert result["status"] == "complete"

    with open(stored_path, "rb") as f:
        after_bytes = f.read()
    assert before_bytes == after_bytes
    assert hashlib.sha256(after_bytes).hexdigest() == hashlib.sha256(before_bytes).hexdigest()

    # Ensure single correlation record
    with SessionLocal() as db:
        count = db.query(CorrelationResultRecord).filter(CorrelationResultRecord.case_id == case_id).count()
        assert count == 1
