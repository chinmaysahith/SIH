import hashlib
import io
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from pathlib import Path
import fakeredis
import pytest
from fastapi.testclient import TestClient

from app.config import ATTACHMENTS_DIR, PARSER_VERSION, QUARANTINE_DIR
from app.db.database import SessionLocal, init_db
from app.db.models import Case, ParsedData
from app.jobs.process_case import process_case
from app.main import app
from app.parser.eml_parser import parse_email
import app.services.queue as queue_service

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_env(monkeypatch):
    """Ensure database initialized and mock Redis with fakeredis."""
    init_db()
    fake_redis = fakeredis.FakeRedis()
    monkeypatch.setattr(queue_service, "get_redis_connection", lambda url=None: fake_redis)
    return fake_redis


def build_multipart_email_with_attachments(
    from_addr="attacker@phish.net",
    to_addr="victim@corp.com",
    subject="Urgent Security Notice",
    body_text="Please click: https://security.corp.com/verify",
    body_html="<p>Please click: <a href='https://security.corp.com/verify'>Verify</a></p>",
    attachments=None,
    received_headers=None,
) -> bytes:
    """Helper to construct raw RFC 822 MIME email bytes."""
    msg = MIMEMultipart("mixed")
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["Date"] = "Sat, 05 Sep 2026 13:00:00 +0000"
    msg["Message-ID"] = "<test-msg-id-001@phish.net>"

    if received_headers:
        for rec in received_headers:
            msg.add_header("Received", rec)

    # Alternative text and html parts
    alt_part = MIMEMultipart("alternative")
    if body_text:
        alt_part.attach(MIMEText(body_text, "plain", "utf-8"))
    if body_html:
        alt_part.attach(MIMEText(body_html, "html", "utf-8"))
    msg.attach(alt_part)

    # Attachments
    if attachments:
        for fname, data, ctype in attachments:
            att = MIMEApplication(data)
            att.add_header("Content-Disposition", "attachment", filename=fname)
            del att["Content-Type"]
            att["Content-Type"] = ctype
            msg.attach(att)

    return msg.as_bytes()


def test_1_basic_headers_extraction():
    """TEST 1: From, To, Subject, Date, Message-ID are accurately parsed."""
    raw = (
        b"From: \"Alice Security\" <alice@targetcorp.org>\r\n"
        b"To: \"Bob Executive\" <bob@targetcorp.org>\r\n"
        b"Subject: Meeting Notes\r\n"
        b"Date: Sat, 05 Sep 2026 12:00:00 +0000\r\n"
        b"Message-ID: <unique-id-123@targetcorp.org>\r\n"
        b"\r\n"
        b"Hello Bob, here are the notes.\r\n"
    )
    parsed = parse_email(raw, case_id="CASE-T1")
    assert parsed.parser_status == "success"
    assert parsed.subject == "Meeting Notes"
    assert parsed.sender is not None
    assert parsed.sender.display_name == "Alice Security"
    assert parsed.sender.address == "alice@targetcorp.org"
    assert parsed.sender.domain == "targetcorp.org"
    assert len(parsed.recipients["to"]) == 1
    assert parsed.recipients["to"][0].address == "bob@targetcorp.org"
    assert parsed.headers.get("Message-ID") == "<unique-id-123@targetcorp.org>"


def test_2_received_chain_preservation():
    """TEST 2: All Received headers are preserved in their exact parsed sequence."""
    import re

    received = [
        "from mail1.relay.com (1.2.3.4) by mx.victim.com with ESMTP; Sat, 05 Sep 2026 13:00:00 +0000",
        "from internal.hop.net (10.0.0.1) by mail1.relay.com with SMTP; Sat, 05 Sep 2026 12:59:00 +0000",
        "from client.local (192.168.1.50) by internal.hop.net; Sat, 05 Sep 2026 12:58:00 +0000",
    ]
    raw = build_multipart_email_with_attachments(received_headers=received)
    parsed = parse_email(raw, case_id="CASE-T2")
    assert len(parsed.received_headers) == 3

    # Verify each hop matches preserving order
    normalized_parsed = [re.sub(r"\s+", " ", r.strip()) for r in parsed.received_headers]
    normalized_expected = [re.sub(r"\s+", " ", r.strip()) for r in received]
    assert normalized_parsed == normalized_expected


def test_3_plain_text_body():
    """TEST 3: Plain text body is decoded and extracted."""
    text_content = "This is a confidential plain text message with no HTML."
    raw = f"From: a@b.com\r\nTo: c@d.com\r\nSubject: Text\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{text_content}".encode()
    parsed = parse_email(raw, case_id="CASE-T3")
    assert parsed.body_text is not None
    assert text_content in parsed.body_text
    assert parsed.body_html is None


def test_4_html_body():
    """TEST 4: HTML body is extracted separately without evaluation."""
    html_content = "<html><body><h1>Urgent Notice</h1><p>Action needed.</p></body></html>"
    raw = f"From: a@b.com\r\nTo: c@d.com\r\nSubject: HTML\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{html_content}".encode()
    parsed = parse_email(raw, case_id="CASE-T4")
    assert parsed.body_html is not None
    assert "<h1>Urgent Notice</h1>" in parsed.body_html
    assert parsed.body_text is None


def test_5_multipart_alternative():
    """TEST 5: Both text and HTML representations are preserved."""
    raw = build_multipart_email_with_attachments(
        body_text="Plain alternative version.",
        body_html="<p>HTML alternative version.</p>",
    )
    parsed = parse_email(raw, case_id="CASE-T5")
    assert parsed.body_text == "Plain alternative version."
    assert parsed.body_html == "<p>HTML alternative version.</p>"


def test_6_url_extraction():
    """TEST 6: URLs are extracted from plain text, HTML text, and HTML anchor href tags."""
    body_text = "Visit https://portal.company.com/login now."
    body_html = (
        "<p>Also check <a href='https://secure-docs.cloud/view?id=499'>Doc</a> "
        "and raw link https://helpdesk.support.net/faq.</p>"
    )
    raw = build_multipart_email_with_attachments(body_text=body_text, body_html=body_html)
    parsed = parse_email(raw, case_id="CASE-T6")
    assert "https://portal.company.com/login" in parsed.urls
    assert "https://secure-docs.cloud/view?id=499" in parsed.urls
    assert "https://helpdesk.support.net/faq" in parsed.urls


def test_7_url_deduplication():
    """TEST 7: Repeated identical URLs are deduplicated without mutating original strings."""
    body_text = "Check https://example.com/test and again https://example.com/test please."
    body_html = "<a href='https://example.com/test'>link</a>"
    raw = build_multipart_email_with_attachments(body_text=body_text, body_html=body_html)
    parsed = parse_email(raw, case_id="CASE-T7")
    assert parsed.urls.count("https://example.com/test") == 1


def test_8_attachment_extraction():
    """TEST 8: Attachment metadata (filename, content type, size, and SHA-256) is extracted."""
    att_bytes = b"%PDF-1.5 fake invoice content for test"
    raw = build_multipart_email_with_attachments(
        attachments=[("invoice.pdf", att_bytes, "application/pdf")]
    )
    parsed = parse_email(raw, case_id="CASE-T8")
    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att.filename == "invoice.pdf"
    assert att.content_type == "application/pdf"
    assert att.size == len(att_bytes)
    assert att.sha256 == hashlib.sha256(att_bytes).hexdigest()


def test_9_attachment_integrity():
    """TEST 9: Quarantined attachment file on disk matches original attachment bytes exactly."""
    att_bytes = b"\x50\x4b\x03\x04fake_macro_payload_data"
    raw = build_multipart_email_with_attachments(
        attachments=[("macro.docm", att_bytes, "application/vnd.ms-word.document.macroEnabled.12")]
    )
    parsed = parse_email(raw, case_id="CASE-T9")
    att = parsed.attachments[0]
    saved_path = Path(att.stored_path)
    assert saved_path.exists()
    assert saved_path.read_bytes() == att_bytes


def test_10_attachment_path_traversal():
    """TEST 10: Path traversal in attachment filename cannot escape data/attachments/<case_id>/."""
    att_bytes = b"safe_bytes"
    raw = build_multipart_email_with_attachments(
        attachments=[("../../escape_attempt.exe", att_bytes, "application/octet-stream")]
    )
    parsed = parse_email(raw, case_id="CASE-T10")
    att = parsed.attachments[0]
    saved_path = Path(att.stored_path)
    expected_parent = (ATTACHMENTS_DIR / "CASE-T10").resolve()
    assert saved_path.resolve().parent == expected_parent
    assert saved_path.name.startswith("attachment_")


def test_11_malformed_email_graceful_handling():
    """TEST 11: Malformed raw bytes do not crash the parser."""
    malformed_bytes = b"Malformed header line without colon\r\nSubject: Hello\r\n\r\nTruncated body"
    parsed = parse_email(malformed_bytes, case_id="CASE-T11")
    assert parsed.case_id == "CASE-T11"
    # Even if malformed, parsing proceeds gracefully without crashing the worker
    assert parsed.body_text is not None
    assert "Truncated body" in parsed.body_text


def test_12_evidence_integrity_precheck(monkeypatch):
    """TEST 12: If quarantined file SHA-256 differs from database record, parser refuses to run."""
    raw = build_multipart_email_with_attachments()
    resp = client.post("/api/upload", files={"file": ("tamper.eml", io.BytesIO(raw), "message/rfc822")})
    assert resp.status_code == 201
    case_id = resp.json()["case_id"]

    # Tamper with the quarantined file on disk (simulate corruption)
    quarantined_file = QUARANTINE_DIR / f"{case_id}.eml"
    with open(quarantined_file, "ab") as f:
        f.write(b"TAMPERED_BYTE")

    # Run worker job
    result = process_case(case_id)
    assert result["status"] == "failed"
    assert "integrity" in result["error"].lower()

    # Verify no ParsedData record was created for tampered file
    with SessionLocal() as db:
        parsed = db.query(ParsedData).filter(ParsedData.case_id == case_id).one_or_none()
        assert parsed is None


def test_13_original_evidence_unchanged_after_parsing():
    """TEST 13: Original quarantined evidence SHA-256 and bytes remain 100% unchanged after parsing."""
    raw = build_multipart_email_with_attachments(
        attachments=[("report.pdf", b"pdf_data_123", "application/pdf")]
    )
    resp = client.post("/api/upload", files={"file": ("immutable.eml", io.BytesIO(raw), "message/rfc822")})
    assert resp.status_code == 201
    case_id = resp.json()["case_id"]
    original_hash = resp.json()["sha256"]

    quarantined_file = QUARANTINE_DIR / f"{case_id}.eml"
    pre_hash = hashlib.sha256(quarantined_file.read_bytes()).hexdigest()

    # Run parser job
    result = process_case(case_id)
    assert result["status"] == "complete"

    # Post-check hash and bytes
    post_bytes = quarantined_file.read_bytes()
    post_hash = hashlib.sha256(post_bytes).hexdigest()

    assert pre_hash == original_hash
    assert post_hash == original_hash
    assert post_bytes == raw


def test_14_script_containing_html_not_evaluated():
    """TEST 14: HTML containing <script> tags is extracted passively and never executed."""
    script_html = "<html><body><script>alert('pwned')</script><p>Text with <a href='https://safe.org'>link</a></p></body></html>"
    raw = f"From: a@b.com\r\nTo: c@d.com\r\nSubject: XSS\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{script_html}".encode()
    parsed = parse_email(raw, case_id="CASE-T14")
    assert parsed.body_html is not None
    assert "<script>alert('pwned')</script>" in parsed.body_html
    assert "https://safe.org" in parsed.urls


def test_15_msg_file_explicitly_handled():
    """TEST 15: Binary .msg file is rejected by EML parser with explicit unsupported_format status."""
    msg_raw = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64
    resp = client.post("/api/upload", files={"file": ("outlook.msg", io.BytesIO(msg_raw), "application/vnd.ms-outlook")})
    assert resp.status_code == 201
    case_id = resp.json()["case_id"]

    # Execute worker on .msg
    result = process_case(case_id)
    assert result["status"] == "failed"
    assert "not supported" in result["error"].lower()

    # Verify ParsedData record exists with status 'unsupported_format'
    with SessionLocal() as db:
        parsed = db.query(ParsedData).filter(ParsedData.case_id == case_id).one_or_none()
        assert parsed is not None
        assert parsed.parser_status == "unsupported_format"


def test_16_get_parsed_api_endpoint():
    """TEST 16: GET /api/cases/{case_id}/parsed returns structured summary."""
    raw = build_multipart_email_with_attachments(
        subject="API Test",
        body_text="Visit https://api-test.com",
        attachments=[("data.csv", b"col1,col2\n1,2", "text/csv")]
    )
    resp = client.post("/api/upload", files={"file": ("api_test.eml", io.BytesIO(raw), "message/rfc822")})
    case_id = resp.json()["case_id"]

    # Run worker job
    process_case(case_id)

    # Call endpoint
    get_resp = client.get(f"/api/cases/{case_id}/parsed")
    assert get_resp.status_code == 200
    pdata = get_resp.json()
    assert pdata["case_id"] == case_id
    assert pdata["subject"] == "API Test"
    assert "https://api-test.com" in pdata["urls"]
    assert pdata["attachments_count"] == 1
    assert pdata["parser_version"] == PARSER_VERSION
    assert pdata["parser_status"] == "success"
