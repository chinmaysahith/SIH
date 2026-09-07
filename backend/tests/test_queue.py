import io
from pathlib import Path
import fakeredis
import pytest
from fastapi.testclient import TestClient
from rq import Queue, SimpleWorker

from app.config import QUARANTINE_DIR, QUEUE_NAME
from app.db.database import SessionLocal, init_db
from app.db.models import Case
from app.jobs.process_case import process_case
from app.main import app
import app.services.queue as queue_service

client = TestClient(app)

SAMPLE_EML_BYTES = (
    b"From: billing@finance-update.com\r\n"
    b"To: accountant@targetcorp.org\r\n"
    b"Subject: Overdue Invoice #9921\r\n"
    b"Date: Sat, 05 Sep 2026 12:00:00 +0000\r\n"
    b"\r\n"
    b"Please find the overdue invoice attached.\r\n"
)


@pytest.fixture(autouse=True)
def setup_test_env(monkeypatch):
    """Ensure DB initialized and mock Redis with in-memory fakeredis."""
    init_db()
    fake_redis = fakeredis.FakeRedis()
    monkeypatch.setattr(queue_service, "get_redis_connection", lambda url=None: fake_redis)
    return fake_redis


def test_1_upload_queues_job(monkeypatch, setup_test_env):
    """TEST 1: Uploading valid EML preserves evidence and enqueues an RQ job."""
    fake_redis = setup_test_env
    q = Queue(QUEUE_NAME, connection=fake_redis)

    response = client.post(
        "/api/upload",
        files={"file": ("invoice.eml", io.BytesIO(SAMPLE_EML_BYTES), "message/rfc822")},
    )

    assert response.status_code == 201
    data = response.json()
    case_id = data["case_id"]

    assert data["status"] == "queued"
    assert data["job_id"] is not None

    # Verify file preserved in quarantine
    stored_path = QUARANTINE_DIR / f"{case_id}.eml"
    assert stored_path.exists()
    assert stored_path.read_bytes() == SAMPLE_EML_BYTES

    # Verify job in queue
    job = q.fetch_job(data["job_id"])
    assert job is not None
    assert job.args == (case_id,)

    # Verify database state
    with SessionLocal() as db:
        case = db.query(Case).filter(Case.case_id == case_id).one()
        assert case.status == "queued"
        assert case.job_id == data["job_id"]


def test_2_worker_executes_job_lifecycle():
    """TEST 2: Worker executes placeholder job, transitioning queued -> processing -> complete."""
    # 1. Upload case to get queued state
    response = client.post(
        "/api/upload",
        files={"file": ("work_test.eml", io.BytesIO(SAMPLE_EML_BYTES), "message/rfc822")},
    )
    assert response.status_code == 201
    case_id = response.json()["case_id"]

    # 2. Run worker job function directly
    result = process_case(case_id)
    assert result["status"] == "complete"

    # 3. Verify database record updated
    with SessionLocal() as db:
        case = db.query(Case).filter(Case.case_id == case_id).one()
        assert case.status == "complete"
        assert case.processing_started_at is not None
        assert case.processing_completed_at is not None
        assert case.processing_completed_at >= case.processing_started_at
        assert case.error_message is None


def test_3_worker_unknown_case():
    """TEST 3: Worker execution on nonexistent case_id fails cleanly without crashing."""
    result = process_case("CASE-NONEXISTENT-999")
    assert result["status"] == "failed"
    assert "not found" in result["error"].lower()


def test_4_worker_missing_quarantine_file():
    """TEST 4: Case pointing to a missing quarantine file is marked failed with error recorded."""
    response = client.post(
        "/api/upload",
        files={"file": ("will_delete.eml", io.BytesIO(SAMPLE_EML_BYTES), "message/rfc822")},
    )
    assert response.status_code == 201
    case_id = response.json()["case_id"]

    # Deliberately remove the quarantined file to simulate evidence corruption/deletion
    stored_path = QUARANTINE_DIR / f"{case_id}.eml"
    if stored_path.exists():
        stored_path.unlink()

    # Execute worker job
    result = process_case(case_id)
    assert result["status"] == "failed"
    assert "not found" in result["error"].lower()

    # Verify DB reflects failure
    with SessionLocal() as db:
        case = db.query(Case).filter(Case.case_id == case_id).one()
        assert case.status == "failed"
        assert "not found" in case.error_message.lower()


def test_5_redis_unavailable_preserves_evidence(monkeypatch):
    """TEST 5: If Redis is unavailable, evidence is PRESERVED, hash matches, status is queue_failed."""
    # Force enqueue_case_analysis to fail (simulating Redis down)
    def broken_enqueue(case_id, connection=None):
        return False, None, "Simulated Redis connection failure"

    import app.routers.upload as upload_module
    monkeypatch.setattr(upload_module, "enqueue_case_analysis", broken_enqueue)

    response = client.post(
        "/api/upload",
        files={"file": ("redis_down.eml", io.BytesIO(SAMPLE_EML_BYTES), "message/rfc822")},
    )

    assert response.status_code == 201
    data = response.json()
    case_id = data["case_id"]

    # Status must reflect queue failure
    assert data["status"] == "queue_failed"
    assert data["job_id"] is None
    assert "Simulated Redis" in data["error_message"]

    # CRITICAL FORENSIC REQUIREMENT: Evidence MUST NOT be deleted
    stored_path = QUARANTINE_DIR / f"{case_id}.eml"
    assert stored_path.exists(), "FORENSIC INTEGRITY VIOLATION: Evidence was deleted on Redis failure!"
    assert stored_path.read_bytes() == SAMPLE_EML_BYTES

    # Verify DB record preserved
    with SessionLocal() as db:
        case = db.query(Case).filter(Case.case_id == case_id).one()
        assert case.status == "queue_failed"
        assert case.stored_path == str(stored_path.resolve())


def test_6_duplicate_upload_creates_separate_jobs():
    """TEST 6: Uploading identical bytes twice creates separate cases and separate jobs."""
    resp1 = client.post(
        "/api/upload",
        files={"file": ("dup1.eml", io.BytesIO(SAMPLE_EML_BYTES), "message/rfc822")},
    )
    resp2 = client.post(
        "/api/upload",
        files={"file": ("dup2.eml", io.BytesIO(SAMPLE_EML_BYTES), "message/rfc822")},
    )

    assert resp1.status_code == 201
    assert resp2.status_code == 201

    d1, d2 = resp1.json(), resp2.json()
    assert d1["case_id"] != d2["case_id"]
    assert d1["sha256"] == d2["sha256"]
    assert d1["job_id"] != d2["job_id"]


def test_7_case_status_endpoint():
    """TEST 7: GET /api/cases/{case_id}/status returns current case details."""
    response = client.post(
        "/api/upload",
        files={"file": ("status_test.eml", io.BytesIO(SAMPLE_EML_BYTES), "message/rfc822")},
    )
    case_id = response.json()["case_id"]

    # Query status endpoint
    status_resp = client.get(f"/api/cases/{case_id}/status")
    assert status_resp.status_code == 200
    st_data = status_resp.json()
    assert st_data["case_id"] == case_id
    assert st_data["status"] == "queued"

    # Nonexistent case returns 404
    bad_resp = client.get("/api/cases/CASE-DOES-NOT-EXIST/status")
    assert bad_resp.status_code == 404


def test_8_worker_idempotency():
    """TEST 8: Repeated execution of process_case does not alter completed state."""
    response = client.post(
        "/api/upload",
        files={"file": ("idempotent.eml", io.BytesIO(SAMPLE_EML_BYTES), "message/rfc822")},
    )
    case_id = response.json()["case_id"]

    # First execution
    res1 = process_case(case_id)
    assert res1["status"] == "complete"

    # Second execution (idempotency check)
    res2 = process_case(case_id)
    assert res2["status"] == "complete"
    assert res2.get("idempotent") is True
