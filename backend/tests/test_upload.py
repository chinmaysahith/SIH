import hashlib
import io
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.config import QUARANTINE_DIR
from app.db.database import SessionLocal, init_db
from app.db.models import Case
from app.main import app

client = TestClient(app)

SAMPLE_EML_CONTENT = (
    b"From: ceo@example.com\r\n"
    b"To: finance@victim.org\r\n"
    b"Subject: Urgent Wire Transfer\r\n"
    b"Date: Fri, 05 Sep 2026 10:00:00 +0000\r\n"
    b"Message-ID: <12345@example.com>\r\n"
    b"\r\n"
    b"Please execute the attached urgent transfer immediately.\r\n"
)


import fakeredis
import app.services.queue as queue_service


@pytest.fixture(autouse=True)
def ensure_db(monkeypatch):
    """Ensure database tables exist and mock Redis with fakeredis before each test."""
    init_db()
    fake_redis = fakeredis.FakeRedis()
    monkeypatch.setattr(queue_service, "get_redis_connection", lambda url=None: fake_redis)
    return fake_redis


def test_1_valid_eml_upload():
    """TEST 1: Valid EML upload creates case, hashes evidence, and preserves file."""
    response = client.post(
        "/api/upload",
        files={"file": ("urgent_invoice.eml", io.BytesIO(SAMPLE_EML_CONTENT), "message/rfc822")},
    )
    assert response.status_code == 201
    data = response.json()

    assert data["case_id"].startswith("CASE-")
    assert data["original_filename"] == "urgent_invoice.eml"
    assert data["status"] in ("uploaded", "queued")
    assert data["file_size"] == len(SAMPLE_EML_CONTENT)
    assert data["file_extension"] == ".eml"
    assert len(data["sha256"]) == 64

    # Verify file exists in quarantine
    stored_file = QUARANTINE_DIR / f"{data['case_id']}.eml"
    assert stored_file.exists(), f"Quarantined file {stored_file} does not exist"

    # Verify database record exists
    with SessionLocal() as db:
        case = db.query(Case).filter(Case.case_id == data["case_id"]).first()
        assert case is not None
        assert case.sha256 == data["sha256"]
        assert case.status in ("uploaded", "queued")


def test_2_hash_correctness():
    """TEST 2: SHA-256 returned by API matches independent hash of input bytes."""
    expected_hash = hashlib.sha256(SAMPLE_EML_CONTENT).hexdigest()

    response = client.post(
        "/api/upload",
        files={"file": ("sample.eml", io.BytesIO(SAMPLE_EML_CONTENT), "message/rfc822")},
    )
    assert response.status_code == 201
    assert response.json()["sha256"] == expected_hash


def test_3_byte_for_byte_preservation():
    """TEST 3: Quarantined file bytes must be 100% identical to original input bytes."""
    response = client.post(
        "/api/upload",
        files={"file": ("raw_evidence.eml", io.BytesIO(SAMPLE_EML_CONTENT), "message/rfc822")},
    )
    assert response.status_code == 201
    case_id = response.json()["case_id"]

    stored_file = QUARANTINE_DIR / f"{case_id}.eml"
    assert stored_file.exists()

    with open(stored_file, "rb") as f:
        quarantined_bytes = f.read()

    assert quarantined_bytes == SAMPLE_EML_CONTENT
    assert len(quarantined_bytes) == len(SAMPLE_EML_CONTENT)


def test_4_same_file_uploaded_twice():
    """TEST 4: Duplicate file uploads produce separate cases with identical SHA-256."""
    resp1 = client.post(
        "/api/upload",
        files={"file": ("duplicate.eml", io.BytesIO(SAMPLE_EML_CONTENT), "message/rfc822")},
    )
    resp2 = client.post(
        "/api/upload",
        files={"file": ("duplicate.eml", io.BytesIO(SAMPLE_EML_CONTENT), "message/rfc822")},
    )

    assert resp1.status_code == 201
    assert resp2.status_code == 201

    data1 = resp1.json()
    data2 = resp2.json()

    assert data1["case_id"] != data2["case_id"]
    assert data1["sha256"] == data2["sha256"]


def test_5_modified_file_hash_difference():
    """TEST 5: Two files differing by one byte produce different hashes."""
    modified_content = SAMPLE_EML_CONTENT + b"X"

    resp1 = client.post(
        "/api/upload",
        files={"file": ("orig.eml", io.BytesIO(SAMPLE_EML_CONTENT), "message/rfc822")},
    )
    resp2 = client.post(
        "/api/upload",
        files={"file": ("mod.eml", io.BytesIO(modified_content), "message/rfc822")},
    )

    assert resp1.status_code == 201
    assert resp2.status_code == 201
    assert resp1.json()["sha256"] != resp2.json()["sha256"]


def test_6_unsupported_extension_rejected():
    """TEST 6: Files with unsupported extensions are rejected with HTTP 400."""
    response = client.post(
        "/api/upload",
        files={"file": ("malware.exe", io.BytesIO(b"MZ\x90\x00executable"), "application/octet-stream")},
    )
    assert response.status_code == 400
    assert "Unsupported file type" in response.json()["detail"]


def test_7_empty_file_rejected():
    """TEST 7: Zero-byte files are rejected with HTTP 400."""
    response = client.post(
        "/api/upload",
        files={"file": ("empty.eml", io.BytesIO(b""), "message/rfc822")},
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_8_oversized_file_rejected(monkeypatch):
    """TEST 8: Files exceeding MAX_UPLOAD_SIZE_BYTES are rejected with HTTP 413."""
    # Temporarily set upload limit to 100 bytes for test
    import app.services.quarantine as q_module

    monkeypatch.setattr(q_module, "MAX_UPLOAD_SIZE_BYTES", 100)
    monkeypatch.setattr(q_module, "MAX_UPLOAD_SIZE_MB", 0.0001)

    oversized_data = b"A" * 250
    response = client.post(
        "/api/upload",
        files={"file": ("big.eml", io.BytesIO(oversized_data), "message/rfc822")},
    )
    assert response.status_code == 413
    assert "exceeds" in response.json()["detail"].lower()


def test_9_path_traversal_filename_sanitization():
    """TEST 9: Directory traversal in filename does not escape quarantine directory."""
    traversal_filename = "../../evil_outside.eml"
    response = client.post(
        "/api/upload",
        files={"file": (traversal_filename, io.BytesIO(SAMPLE_EML_CONTENT), "message/rfc822")},
    )
    assert response.status_code == 201
    data = response.json()

    # The original filename stored in metadata should be sanitized
    assert data["original_filename"] == "evil_outside.eml"

    # The quarantined file must strictly be inside QUARANTINE_DIR
    stored_path = Path(QUARANTINE_DIR / f"{data['case_id']}.eml").resolve()
    assert stored_path.parent == QUARANTINE_DIR.resolve()
    assert stored_path.exists()


def test_10_database_persistence():
    """TEST 10: Case record persists in SQLite and can be retrieved in a new session."""
    response = client.post(
        "/api/upload",
        files={"file": ("persistence_test.eml", io.BytesIO(SAMPLE_EML_CONTENT), "message/rfc822")},
    )
    assert response.status_code == 201
    case_id = response.json()["case_id"]

    # Open a completely fresh database session to verify persistence
    with SessionLocal() as db:
        case = db.query(Case).filter(Case.case_id == case_id).one_or_none()
        assert case is not None
        assert case.case_id == case_id
        assert case.original_filename == "persistence_test.eml"
        assert case.status in ("uploaded", "queued")


def test_11_msg_file_accepted():
    """TEST 11: .msg files are accepted and stored as raw evidence."""
    msg_raw_bytes = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64  # OLE Compound File header
    response = client.post(
        "/api/upload",
        files={"file": ("outlook_message.msg", io.BytesIO(msg_raw_bytes), "application/vnd.ms-outlook")},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["file_extension"] == ".msg"

    stored_file = QUARANTINE_DIR / f"{data['case_id']}.msg"
    assert stored_file.exists()
    with open(stored_file, "rb") as f:
        assert f.read() == msg_raw_bytes
