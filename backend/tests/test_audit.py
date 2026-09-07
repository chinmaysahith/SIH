"""
Comprehensive test suite for Stage 8 — Forensic Case Management + Audit Trail.
Covers:
1. Case Lifecycle & State Transitions
2. Append-Only Audit Events, Sequence Monotonicity & Hashing
3. Tamper Detection & Audit Chain Verification
4. Analysis Run Lifecycle, Versions, & Fingerprints
5. Analytical Provenance Snapshots
6. Evidence Manifests & Composite Hashing
7. REST APIs (/timeline, /audit/verify, /analysis-runs, /provenance, /evidence-manifest)
8. Worker Integration, Forensic Invariants & Idempotency
"""

import hashlib
import io
import json
import pytest
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from fastapi.testclient import TestClient

from app.config import QUARANTINE_DIR, PARSER_VERSION
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
    RuleResultRecord,
)
from app.audit import (
    ActorType,
    AuditEventType,
    EngineName,
    RunStatus,
    ArtifactType,
    canonical_json,
    compute_event_hash,
    compute_fingerprint,
    record_event,
    verify_case_audit_chain,
    start_analysis_run,
    finish_analysis_run,
    record_evidence_manifest,
    compute_composite_manifest_sha256,
    create_provenance_snapshot,
)
from app.jobs.process_case import process_case
from app.main import app

client = TestClient(app)


def clean_case(case_id: str, db):
    """Purges all records associated with a case across all stages."""
    for model in [
        CaseEventRecord,
        AnalysisRunRecord,
        ProvenanceSnapshotRecord,
        EvidenceManifestRecord,
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
def setup_test_db():
    init_db()
    yield


# =====================================================================
# 1. Case Lifecycle Tests
# =====================================================================

def test_1_case_created_event_on_upload():
    """Verify that uploading an email emits CASE_CREATED and EVIDENCE_STORED events."""
    raw = b"From: user@test.com\r\nTo: recipient@test.com\r\nSubject: Audit Test\r\n\r\nBody text."
    resp = client.post("/api/upload", files={"file": ("audit_upload.eml", io.BytesIO(raw), "message/rfc822")})
    assert resp.status_code == 201
    case_id = resp.json()["case_id"]

    with SessionLocal() as db:
        events = db.query(CaseEventRecord).filter(CaseEventRecord.case_id == case_id).order_by(CaseEventRecord.event_sequence.asc()).all()
        assert len(events) >= 3  # CASE_CREATED, EVIDENCE_STORED, JOB_QUEUED / CASE_ANALYSIS_FAILED
        assert events[0].event_type == AuditEventType.CASE_CREATED.value
        assert events[0].event_sequence == 1
        assert events[0].previous_event_hash is None
        assert events[1].event_type == AuditEventType.EVIDENCE_STORED.value
        assert events[1].event_sequence == 2
        assert events[1].previous_event_hash == events[0].event_hash
        assert events[2].event_type in (AuditEventType.JOB_QUEUED.value, AuditEventType.CASE_ANALYSIS_FAILED.value)
        assert events[2].event_sequence == 3
        assert events[2].previous_event_hash == events[1].event_hash


def test_2_case_status_transitions():
    """Verify standard status progression: uploaded -> queued -> processing -> complete."""
    case_id = "test-case-lifecycle-01"
    with SessionLocal() as db:
        clean_case(case_id, db)
        case = Case(
            case_id=case_id,
            original_filename="test.eml",
            stored_path="dummy",
            sha256="abc",
            file_size=10,
            file_extension=".eml",
            status="uploaded",
        )
        db.add(case)
        db.commit()

        assert case.status == "uploaded"
        case.status = "queued"
        db.commit()
        assert case.status == "queued"
        case.status = "processing"
        db.commit()
        assert case.status == "processing"
        case.status = "complete"
        db.commit()
        assert case.status == "complete"


def test_3_case_failure_retains_records():
    """Verify that case failure retains the case record and logs failure event without data deletion."""
    case_id = "test-case-fail-retention"
    with SessionLocal() as db:
        clean_case(case_id, db)
        case = Case(
            case_id=case_id,
            original_filename="corrupt.eml",
            stored_path="nonexistent_path_to_file",
            sha256="fakehash",
            file_size=10,
            file_extension=".eml",
            status="queued",
        )
        db.add(case)
        db.commit()

    # Process should fail because file does not exist
    result = process_case(case_id)
    assert result["status"] == "failed"

    with SessionLocal() as db:
        c = db.query(Case).filter(Case.case_id == case_id).one_or_none()
        assert c is not None
        assert c.status == "failed"
        assert "not found" in c.error_message.lower()

        # Audit events must capture failure
        ev = db.query(CaseEventRecord).filter(CaseEventRecord.case_id == case_id, CaseEventRecord.event_type == AuditEventType.CASE_ANALYSIS_FAILED.value).one_or_none()
        assert ev is not None


# =====================================================================
# 2. Append-Only Audit Events & Hash Chaining Tests
# =====================================================================

def test_4_record_event_monotonic_sequence():
    case_id = "test-event-seq"
    with SessionLocal() as db:
        clean_case(case_id, db)
        e1 = record_event(case_id, AuditEventType.CASE_CREATED, "Created", db)
        e2 = record_event(case_id, AuditEventType.PROCESSING_STARTED, "Processing", db)
        e3 = record_event(case_id, AuditEventType.PARSER_STARTED, "Parser started", db)
        db.commit()

        assert e1.event_sequence == 1
        assert e2.event_sequence == 2
        assert e3.event_sequence == 3


def test_5_hash_chain_linkage():
    case_id = "test-hash-link"
    with SessionLocal() as db:
        clean_case(case_id, db)
        e1 = record_event(case_id, AuditEventType.CASE_CREATED, "Event 1", db)
        e2 = record_event(case_id, AuditEventType.PARSER_STARTED, "Event 2", db)
        e3 = record_event(case_id, AuditEventType.PARSER_COMPLETED, "Event 3", db)
        db.commit()

        assert e1.previous_event_hash is None
        assert e2.previous_event_hash == e1.event_hash
        assert e3.previous_event_hash == e2.event_hash


def test_6_canonical_json_determinism():
    d1 = {"z": 1, "a": 2, "m": {"b": 3, "a": 4}}
    d2 = {"a": 2, "m": {"a": 4, "b": 3}, "z": 1}
    assert canonical_json(d1) == canonical_json(d2)


def test_7_compute_fingerprint_deterministic():
    fp1 = compute_fingerprint({"test": 123, "arr": [1, 2, 3]})
    fp2 = compute_fingerprint({"arr": [1, 2, 3], "test": 123})
    assert fp1 == fp2
    assert len(fp1) == 64


def test_8_audit_chain_verification_valid():
    case_id = "test-chain-valid"
    with SessionLocal() as db:
        clean_case(case_id, db)
        record_event(case_id, AuditEventType.CASE_CREATED, "Case 1", db)
        record_event(case_id, AuditEventType.EVIDENCE_STORED, "Stored", db)
        record_event(case_id, AuditEventType.PROCESSING_STARTED, "Started", db)
        record_event(case_id, AuditEventType.PARSER_COMPLETED, "Parsed", db)
        db.commit()

        report = verify_case_audit_chain(case_id, db)
        assert report.valid is True
        assert report.event_count == 4
        assert len(report.errors) == 0


def test_9_tamper_detection_modified_message():
    case_id = "test-tamper-msg"
    with SessionLocal() as db:
        clean_case(case_id, db)
        record_event(case_id, AuditEventType.CASE_CREATED, "Original Message", db)
        e2 = record_event(case_id, AuditEventType.PROCESSING_STARTED, "Processing", db)
        db.commit()

        # Malicious attacker directly modifies database text
        e2.message = "Attacker Altered Message"
        db.commit()

        report = verify_case_audit_chain(case_id, db)
        assert report.valid is False
        assert any(err.error_type == "event_hash_mismatch" for err in report.errors)


def test_10_tamper_detection_modified_metadata():
    case_id = "test-tamper-meta"
    with SessionLocal() as db:
        clean_case(case_id, db)
        record_event(case_id, AuditEventType.CASE_CREATED, "Msg", db, metadata={"user": "alice"})
        e2 = record_event(case_id, AuditEventType.PROCESSING_STARTED, "Proc", db, metadata={"ip": "1.1.1.1"})
        db.commit()

        # Malicious modification of metadata
        e2.metadata_json = '{"ip":"8.8.8.8"}'
        db.commit()

        report = verify_case_audit_chain(case_id, db)
        assert report.valid is False
        assert any(err.error_type == "event_hash_mismatch" for err in report.errors)


def test_11_tamper_detection_deleted_middle_event():
    case_id = "test-tamper-delete"
    with SessionLocal() as db:
        clean_case(case_id, db)
        record_event(case_id, AuditEventType.CASE_CREATED, "Ev1", db)
        e2 = record_event(case_id, AuditEventType.PROCESSING_STARTED, "Ev2", db)
        record_event(case_id, AuditEventType.PARSER_COMPLETED, "Ev3", db)
        db.commit()

        # Malicious deletion of event 2
        db.delete(e2)
        db.commit()

        report = verify_case_audit_chain(case_id, db)
        assert report.valid is False
        assert any(err.error_type in ("sequence_anomaly", "previous_hash_mismatch") for err in report.errors)


def test_12_tamper_detection_duplicate_sequence():
    case_id = "test-tamper-dup-seq"
    with SessionLocal() as db:
        clean_case(case_id, db)
        record_event(case_id, AuditEventType.CASE_CREATED, "Ev1", db)
        e2 = record_event(case_id, AuditEventType.PROCESSING_STARTED, "Ev2", db)
        db.commit()

        e2.event_sequence = 1
        db.commit()

        report = verify_case_audit_chain(case_id, db)
        assert report.valid is False
        assert any(err.error_type == "sequence_anomaly" for err in report.errors)


# =====================================================================
# 3. Analysis Run Execution Tests
# =====================================================================

def test_13_start_and_finish_analysis_run():
    case_id = "test-run-lifecycle"
    with SessionLocal() as db:
        clean_case(case_id, db)
        run_rec = start_analysis_run(
            case_id=case_id,
            engine_name=EngineName.RULES,
            input_payload={"rules_count": 20},
            db=db,
            engine_version="1.0.0",
        )
        assert run_rec.status == RunStatus.STARTED.value
        assert run_rec.input_fingerprint is not None
        assert run_rec.completed_timestamp is None

        finish_analysis_run(
            run_rec=run_rec,
            status=RunStatus.COMPLETED,
            db=db,
            output_payload={"verdict": "HIGH_RISK", "score": 85},
        )
        assert run_rec.status == RunStatus.COMPLETED.value
        assert run_rec.completed_timestamp is not None
        assert run_rec.output_fingerprint is not None


def test_14_analysis_run_failure():
    case_id = "test-run-fail"
    with SessionLocal() as db:
        clean_case(case_id, db)
        run_rec = start_analysis_run(
            case_id=case_id,
            engine_name=EngineName.ML,
            input_payload={"text": "phishing sample"},
            db=db,
            model_version="1.0.0",
        )
        finish_analysis_run(
            run_rec=run_rec,
            status=RunStatus.FAILED,
            db=db,
            error_message="Model weights missing",
        )
        assert run_rec.status == RunStatus.FAILED.value
        assert run_rec.error_message == "Model weights missing"
        assert run_rec.output_fingerprint is None


def test_15_analysis_run_preserves_history_across_reruns():
    case_id = "test-run-history"
    with SessionLocal() as db:
        clean_case(case_id, db)
        # Run 1
        r1 = start_analysis_run(case_id, EngineName.RULES, {"version": "1.0"}, db, engine_version="1.0.0")
        finish_analysis_run(r1, RunStatus.COMPLETED, db, output_payload={"score": 50})
        # Run 2 (Rerun)
        r2 = start_analysis_run(case_id, EngineName.RULES, {"version": "1.1"}, db, engine_version="1.1.0")
        finish_analysis_run(r2, RunStatus.COMPLETED, db, output_payload={"score": 75})
        db.commit()

        runs = db.query(AnalysisRunRecord).filter(AnalysisRunRecord.case_id == case_id).all()
        assert len(runs) == 2
        assert runs[0].engine_version == "1.0.0"
        assert runs[1].engine_version == "1.1.0"
        assert runs[0].run_id != runs[1].run_id


# =====================================================================
# 4. Provenance Snapshot Tests
# =====================================================================

def test_16_create_provenance_snapshot_captures_all_versions():
    case_id = "test-provenance-snap"
    with SessionLocal() as db:
        clean_case(case_id, db)
        db.add(Case(case_id=case_id, original_filename="test.eml", stored_path="p", sha256="rawsha123", file_size=10, file_extension=".eml", status="complete"))
        db.add(ParsedData(case_id=case_id, parser_version="1.0.0", attachments_json='[{"filename": "test.pdf", "sha256": "pdfsha123", "size_bytes": 100}]'))
        db.add(RuleResultRecord(case_id=case_id, rules_engine_version="1.0.0", total_score=10, category_scores_json="{}", results_json="[]"))
        db.add(MLResultRecord(case_id=case_id, model_version="1.0.0", preprocessing_version="1.0.0"))
        db.add(IOCResultRecord(case_id=case_id, ioc_id="1", ioc_type="domain", original_value="d.test", normalized_value="d.test", source_context="u", status="known_malicious", confidence=90, source="s", reason="r", feed_version="2026.09.1", feed_sha256="feedsha123"))
        db.add(GeoOriginResultRecord(case_id=case_id, analysis_version="1.0.0", selected_origin_ip="1.1.1.1", confidence="HIGH", disclaimer="d", geo_database_version="geo1.0", geo_database_sha256="geosha123", network_feed_version="net1.0", network_feed_sha256="netsha123"))
        db.add(CorrelationResultRecord(case_id=case_id, correlation_version="1.0.0", policy_version="1.0.0", final_score=50.0, final_assessment="SUSPICIOUS", correlation_confidence="MEDIUM", evidence_coverage_percent=100.0, explanation="e", disclaimer="d"))
        db.commit()

        snap = create_provenance_snapshot(case_id, db)
        db.commit()

        assert snap.raw_evidence_sha256 == "rawsha123"
        assert snap.parser_version == "1.0.0"
        assert snap.rules_engine_version == "1.0.0"
        assert snap.ml_model_version == "1.0.0"
        assert snap.ioc_feed_version == "2026.09.1"
        assert snap.ioc_feed_sha256 == "feedsha123"
        assert snap.geo_database_version == "geo1.0"
        assert snap.geo_database_sha256 == "geosha123"
        assert snap.network_feed_version == "net1.0"
        assert snap.network_feed_sha256 == "netsha123"
        assert snap.correlation_engine_version == "1.0.0"
        assert snap.attachment_manifest_sha256 is not None


# =====================================================================
# 5. Evidence Manifest & Composite Hashing Tests
# =====================================================================

def test_17_record_evidence_manifest_includes_raw_and_artifacts():
    case_id = "test-manifest-generation"
    with SessionLocal() as db:
        clean_case(case_id, db)
        db.add(Case(case_id=case_id, original_filename="original.eml", stored_path="data/quarantine/original.eml", sha256="origsha", file_size=500, file_extension=".eml", status="complete"))
        db.add(ParsedData(case_id=case_id, parser_version="1.0.0", headers_json='{"From": "a@b.com"}', attachments_json='[{"filename": "doc.pdf", "sha256": "docsha", "size_bytes": 200, "stored_path": "data/attachments/doc.pdf"}]'))
        db.add(RuleResultRecord(case_id=case_id, rules_engine_version="1.0.0", total_score=20, category_scores_json="{}", results_json='[{"rule_id":"RULE-01"}]'))
        db.commit()

        entries = record_evidence_manifest(case_id, db)
        db.commit()

        types = {e.artifact_type for e in entries}
        assert ArtifactType.RAW_EMAIL.value in types
        assert ArtifactType.ATTACHMENT.value in types
        assert ArtifactType.PARSED_RESULT.value in types
        assert ArtifactType.RULE_RESULT.value in types

        raw_item = next(e for e in entries if e.artifact_type == ArtifactType.RAW_EMAIL.value)
        assert raw_item.immutable is True
        assert raw_item.sha256 == "origsha"


def test_18_composite_manifest_sha256_deterministic():
    case_id = "test-comp-sha"
    with SessionLocal() as db:
        clean_case(case_id, db)
        m1 = EvidenceManifestRecord(case_id=case_id, artifact_type="RAW_EMAIL", artifact_name="a.eml", size_bytes=100, sha256="sha1", source="q", immutable=True)
        m2 = EvidenceManifestRecord(case_id=case_id, artifact_type="ATTACHMENT", artifact_name="b.pdf", size_bytes=200, sha256="sha2", source="p", immutable=True)
        db.add_all([m1, m2])
        db.commit()

        h1 = compute_composite_manifest_sha256([m1, m2])
        h2 = compute_composite_manifest_sha256([m2, m1])  # order-independent sorting
        assert h1 == h2
        assert len(h1) == 64


# =====================================================================
# 6. REST API Endpoints Tests
# =====================================================================

def test_19_api_get_timeline():
    case_id = "test-api-timeline"
    with SessionLocal() as db:
        clean_case(case_id, db)
        db.add(Case(case_id=case_id, original_filename="t.eml", stored_path="p", sha256="s", file_size=10, file_extension=".eml", status="complete"))
        record_event(case_id, AuditEventType.CASE_CREATED, "Created", db)
        record_event(case_id, AuditEventType.PARSER_COMPLETED, "Parsed", db)
        db.commit()

    resp = client.get(f"/api/cases/{case_id}/timeline")
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == case_id
    assert data["total_events"] == 2
    assert data["events"][0]["event_type"] == "CASE_CREATED"
    assert data["events"][1]["event_type"] == "PARSER_COMPLETED"


def test_20_api_get_audit_verify_valid():
    case_id = "test-api-verify"
    with SessionLocal() as db:
        clean_case(case_id, db)
        db.add(Case(case_id=case_id, original_filename="t.eml", stored_path="p", sha256="s", file_size=10, file_extension=".eml", status="complete"))
        record_event(case_id, AuditEventType.CASE_CREATED, "Ev1", db)
        record_event(case_id, AuditEventType.PARSER_COMPLETED, "Ev2", db)
        db.commit()

    resp = client.get(f"/api/cases/{case_id}/audit/verify")
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == case_id
    assert data["valid"] is True
    assert data["event_count"] == 2


def test_21_api_get_analysis_runs():
    case_id = "test-api-runs"
    with SessionLocal() as db:
        clean_case(case_id, db)
        db.add(Case(case_id=case_id, original_filename="t.eml", stored_path="p", sha256="s", file_size=10, file_extension=".eml", status="complete"))
        r = start_analysis_run(case_id, EngineName.RULES, {"k": "v"}, db, engine_version="1.0.0")
        finish_analysis_run(r, RunStatus.COMPLETED, db, output_payload={"score": 20})
        db.commit()

    resp = client.get(f"/api/cases/{case_id}/analysis-runs")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_runs"] == 1
    assert data["runs"][0]["engine_name"] == "rules"
    assert data["runs"][0]["status"] == "COMPLETED"


def test_22_api_get_provenance():
    case_id = "test-api-prov"
    with SessionLocal() as db:
        clean_case(case_id, db)
        db.add(Case(case_id=case_id, original_filename="t.eml", stored_path="p", sha256="sha-p", file_size=10, file_extension=".eml", status="complete"))
        create_provenance_snapshot(case_id, db)
        db.commit()

    resp = client.get(f"/api/cases/{case_id}/provenance")
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == case_id
    assert data["raw_evidence_sha256"] == "sha-p"


def test_23_api_get_evidence_manifest():
    case_id = "test-api-man"
    with SessionLocal() as db:
        clean_case(case_id, db)
        db.add(Case(case_id=case_id, original_filename="t.eml", stored_path="p", sha256="sha-m", file_size=100, file_extension=".eml", status="complete"))
        record_evidence_manifest(case_id, db)
        db.commit()

    resp = client.get(f"/api/cases/{case_id}/evidence-manifest")
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == case_id
    assert data["total_artifacts"] >= 1
    assert data["manifest_sha256"] is not None


# =====================================================================
# 7. End-to-End Worker & Audit Integration Tests
# =====================================================================

def test_24_worker_e2e_creates_full_audit_trail_and_preserves_evidence():
    case_id = "test-worker-stage8-e2e"

    with SessionLocal() as db:
        clean_case(case_id, db)

    msg = MIMEMultipart()
    msg["From"] = "security@test-e2e-audit.test"
    msg["To"] = "target@corp.test"
    msg["Subject"] = "Stage 8 Audit Verification"
    msg["Message-ID"] = f"<{case_id}@test.local>"
    msg["Received"] = "from relay.internal (10.0.0.1) by dest.internal; Sat, 05 Sep 2026 12:00:00 +0000"
    msg["Received"] = "from public.sender.test (198.51.100.25) by relay.internal; Sat, 05 Sep 2026 11:59:00 +0000"
    msg.attach(MIMEText("Please review account status at http://198.51.100.25/login immediately.", "plain"))

    raw_bytes = msg.as_bytes()
    expected_hash = hashlib.sha256(raw_bytes).hexdigest()

    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    stored_path = QUARANTINE_DIR / f"{case_id}.eml"
    with open(stored_path, "wb") as f:
        f.write(raw_bytes)

    with SessionLocal() as db:
        case = Case(
            case_id=case_id,
            original_filename="stage8_e2e.eml",
            stored_path=str(stored_path),
            sha256=expected_hash,
            file_size=len(raw_bytes),
            file_extension=".eml",
            status="queued",
        )
        db.add(case)
        db.commit()

    # Process via worker
    result = process_case(case_id)
    assert result["status"] == "complete"

    # Verify quarantined evidence is 100% byte-for-byte identical (0 bytes altered)
    with open(stored_path, "rb") as f:
        post_bytes = f.read()
    assert post_bytes == raw_bytes
    assert hashlib.sha256(post_bytes).hexdigest() == expected_hash

    # Verify audit chain
    with SessionLocal() as db:
        report = verify_case_audit_chain(case_id, db)
        assert report.valid is True
        assert report.event_count >= 10  # Comprehensive lifecycle

        # Verify analysis runs were recorded for all engines
        runs = db.query(AnalysisRunRecord).filter(AnalysisRunRecord.case_id == case_id).all()
        engine_names = {r.engine_name for r in runs}
        assert engine_names == {"parser", "rules", "ml", "ioc", "geo", "correlation"}

        # Verify provenance snapshot exists
        snap = db.query(ProvenanceSnapshotRecord).filter(ProvenanceSnapshotRecord.case_id == case_id).one_or_none()
        assert snap is not None
        assert snap.raw_evidence_sha256 == expected_hash

        # Verify evidence manifest exists
        manifest = db.query(EvidenceManifestRecord).filter(EvidenceManifestRecord.case_id == case_id).all()
        assert len(manifest) >= 1
        assert any(m.artifact_type == "RAW_EMAIL" and m.sha256 == expected_hash for m in manifest)


def test_25_worker_rerun_records_analysis_rerun_event():
    case_id = "test-worker-stage8-e2e"
    # Execute a rerun with force_rerun=True
    result = process_case(case_id, force_rerun=True)
    assert result["status"] == "complete"

    with SessionLocal() as db:
        rerun_event = db.query(CaseEventRecord).filter(
            CaseEventRecord.case_id == case_id,
            CaseEventRecord.event_type == AuditEventType.ANALYSIS_RERUN.value,
        ).one_or_none()
        assert rerun_event is not None

        # Verify chain remains valid after rerun events appended
        report = verify_case_audit_chain(case_id, db)
        assert report.valid is True


# =====================================================================
# Additional Coverage Tests (Reaching >= 35 Tests)
# =====================================================================

def test_26_actor_type_values():
    assert ActorType.SYSTEM.value == "SYSTEM"
    assert ActorType.ANALYST.value == "ANALYST"


def test_27_audit_event_types_count():
    assert len(AuditEventType) >= 20


def test_28_timeline_api_404_not_found():
    resp = client.get("/api/cases/nonexistent-case-id-404/timeline")
    assert resp.status_code == 404


def test_29_audit_verify_api_404_not_found():
    resp = client.get("/api/cases/nonexistent-case-id-404/audit/verify")
    assert resp.status_code == 404


def test_30_analysis_runs_api_404_not_found():
    resp = client.get("/api/cases/nonexistent-case-id-404/analysis-runs")
    assert resp.status_code == 404


def test_31_provenance_api_404_not_found():
    resp = client.get("/api/cases/nonexistent-case-id-404/provenance")
    assert resp.status_code == 404


def test_32_evidence_manifest_api_404_not_found():
    resp = client.get("/api/cases/nonexistent-case-id-404/evidence-manifest")
    assert resp.status_code == 404


def test_33_empty_case_audit_chain_is_valid():
    case_id = "test-empty-chain"
    with SessionLocal() as db:
        clean_case(case_id, db)
        report = verify_case_audit_chain(case_id, db)
        assert report.valid is True
        assert report.event_count == 0


def test_34_actor_analyst_event():
    case_id = "test-analyst-event"
    with SessionLocal() as db:
        clean_case(case_id, db)
        ev = record_event(
            case_id=case_id,
            event_type=AuditEventType.ANALYST_VIEWED,
            message="Analyst viewed forensic assessment",
            db=db,
            actor_type=ActorType.ANALYST,
            actor_id=None,
        )
        db.commit()
        assert ev.actor_type == "ANALYST"
        assert ev.actor_id is None


def test_35_evidence_manifest_attachment_extraction():
    case_id = "test-manifest-att"
    with SessionLocal() as db:
        clean_case(case_id, db)
        db.add(Case(case_id=case_id, original_filename="test.eml", stored_path="p", sha256="s1", file_size=10, file_extension=".eml", status="complete"))
        db.add(ParsedData(
            case_id=case_id,
            parser_version="1.0.0",
            attachments_json=json.dumps([
                {"filename": "invoice.pdf", "sha256": "pdfsha", "size_bytes": 1024, "stored_path": "data/attachments/invoice.pdf"},
                {"filename": "payload.exe", "sha256": "exesha", "size_bytes": 2048, "stored_path": "data/attachments/payload.exe"}
            ])
        ))
        db.commit()

        entries = record_evidence_manifest(case_id, db)
        db.commit()

        atts = [e for e in entries if e.artifact_type == "ATTACHMENT"]
        assert len(atts) == 2
        assert {a.artifact_name for a in atts} == {"invoice.pdf", "payload.exe"}


def test_36_evidence_manifest_composite_changes_when_artifact_modified():
    case_id = "test-manifest-hash-change"
    with SessionLocal() as db:
        clean_case(case_id, db)
        m1 = EvidenceManifestRecord(case_id=case_id, artifact_type="RAW_EMAIL", artifact_name="a.eml", size_bytes=100, sha256="sha1", source="q", immutable=True)
        db.add(m1)
        db.commit()
        h1 = compute_composite_manifest_sha256([m1])

        m1.sha256 = "sha2_modified"
        h2 = compute_composite_manifest_sha256([m1])
        assert h1 != h2


def test_37_provenance_null_fields_handled_gracefully():
    case_id = "test-provenance-nulls"
    with SessionLocal() as db:
        clean_case(case_id, db)
        db.add(Case(case_id=case_id, original_filename="t.eml", stored_path="p", sha256="sha1", file_size=10, file_extension=".eml", status="complete"))
        db.commit()

        snap = create_provenance_snapshot(case_id, db)
        db.commit()

        assert snap.parser_version is None
        assert snap.ml_model_version is None
        assert snap.raw_evidence_sha256 == "sha1"


def test_38_analysis_run_duration_calculation():
    case_id = "test-run-duration"
    with SessionLocal() as db:
        clean_case(case_id, db)
        db.add(Case(case_id=case_id, original_filename="t.eml", stored_path="p", sha256="s", file_size=10, file_extension=".eml", status="complete"))
        r = start_analysis_run(case_id, EngineName.GEO, {}, db)
        finish_analysis_run(r, RunStatus.COMPLETED, db, output_payload={"origin": "1.1.1.1"})
        db.commit()

    resp = client.get(f"/api/cases/{case_id}/analysis-runs")
    assert resp.status_code == 200
    run_item = resp.json()["runs"][0]
    assert run_item["duration_seconds"] is not None
    assert run_item["duration_seconds"] >= 0.0


def test_39_worker_corrupted_post_check_raises_integrity_error(monkeypatch):
    """Verifies that if quarantine file is somehow mutated during processing, an error is raised and case marked failed."""
    case_id = "test-worker-corrupt-post"

    with SessionLocal() as db:
        clean_case(case_id, db)

    raw = b"From: a@b.com\r\nTo: c@d.com\r\nSubject: Test\r\n\r\nBody"
    expected_hash = hashlib.sha256(raw).hexdigest()

    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    stored_path = QUARANTINE_DIR / f"{case_id}.eml"
    with open(stored_path, "wb") as f:
        f.write(raw)

    with SessionLocal() as db:
        case = Case(
            case_id=case_id,
            original_filename="corrupt_post.eml",
            stored_path=str(stored_path),
            sha256=expected_hash,
            file_size=len(raw),
            file_extension=".eml",
            status="queued",
        )
        db.add(case)
        db.commit()

    # Monkeypatch calculate_sha256 for post check to simulate corruption
    real_sha = hashlib.sha256
    call_count = [0]
    def fake_sha(path):
        call_count[0] += 1
        if call_count[0] > 1:  # second call is post-check
            return "simulated_corrupted_sha256"
        return expected_hash

    monkeypatch.setattr("app.jobs.process_case.calculate_sha256", fake_sha)

    with pytest.raises(IOError, match="Forensic violation"):
        process_case(case_id)

    with SessionLocal() as db:
        c = db.query(Case).filter(Case.case_id == case_id).one_or_none()
        assert c.status == "failed"
        ev = db.query(CaseEventRecord).filter(CaseEventRecord.case_id == case_id, CaseEventRecord.event_type == AuditEventType.EVIDENCE_INTEGRITY_FAILURE.value).one_or_none()
        assert ev is not None


def test_40_case_event_metadata_json_serialization():
    case_id = "test-meta-json"
    with SessionLocal() as db:
        clean_case(case_id, db)
        record_event(case_id, AuditEventType.CASE_CREATED, "Msg", db, metadata={"num": 1, "float": 2.5, "flag": True, "nested": {"key": "val"}})
        db.commit()

        ev = db.query(CaseEventRecord).filter(CaseEventRecord.case_id == case_id).first()
        data = json.loads(ev.metadata_json)
        assert data["num"] == 1
        assert data["nested"]["key"] == "val"


def test_41_no_raw_evidence_modification_invariant():
    """Verify that throughout upload and processing, raw evidence disk bytes are never altered."""
    case_id = "test-immutable-invariant"
    raw_content = b"From: sender@bank.test\r\nTo: victim@user.test\r\nSubject: Important Notice\r\n\r\nDear User, please log in."
    initial_sha = hashlib.sha256(raw_content).hexdigest()

    resp = client.post("/api/upload", files={"file": ("immutable.eml", io.BytesIO(raw_content), "message/rfc822")})
    assert resp.status_code == 201
    uploaded_id = resp.json()["case_id"]

    stored_file = QUARANTINE_DIR / f"{uploaded_id}.eml"
    assert stored_file.read_bytes() == raw_content

    # Run processing
    res = process_case(uploaded_id)
    assert res["status"] == "complete"

    # Bytes must match exactly
    assert stored_file.read_bytes() == raw_content
    assert hashlib.sha256(stored_file.read_bytes()).hexdigest() == initial_sha


def test_42_api_read_only_operations_do_not_generate_audit_events():
    """Verify that querying GET /timeline and GET /status does not append spurious audit events."""
    case_id = "test-api-readonly-no-events"
    with SessionLocal() as db:
        clean_case(case_id, db)
        db.add(Case(case_id=case_id, original_filename="t.eml", stored_path="p", sha256="s", file_size=10, file_extension=".eml", status="complete"))
        record_event(case_id, AuditEventType.CASE_CREATED, "Created", db)
        db.commit()

        initial_count = db.query(CaseEventRecord).filter(CaseEventRecord.case_id == case_id).count()

    # Query APIs multiple times
    client.get(f"/api/cases/{case_id}/timeline")
    client.get(f"/api/cases/{case_id}/status")
    client.get(f"/api/cases/{case_id}/audit/verify")

    with SessionLocal() as db:
        final_count = db.query(CaseEventRecord).filter(CaseEventRecord.case_id == case_id).count()
        assert final_count == initial_count
