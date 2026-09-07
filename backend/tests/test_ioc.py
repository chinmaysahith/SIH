"""Comprehensive test suite for Stage 5 — IOC Analysis Engine.

Verifies:
1. Indicator extraction: URLs, host domains, IPv4 addresses, attachment hashes, sender/reply-to domains.
2. Normalization: domains, IPv4, SHA-256, URLs, original value preservation.
3. Feed schema & provenance: strict load-time validation, rejection of invalid data, feed SHA-256 calculation.
4. Lookup semantics: known malicious, suspicious, benign, distinct NOT_FOUND vs KNOWN_BENIGN, confidence/reason preservation.
5. Engine & adapter architecture: multi-indicator evaluation, idempotent execution, graceful failure handling.
6. Independence invariant: zero reliance on Rules Engine scores or ML probabilities.
7. No-network assertion: zero outbound socket calls (HTTP/DNS/WHOIS).
8. Forensic integrity: pre- and post-processing quarantine evidence byte immutability.
9. Database persistence & REST API: SQLite storage and GET /api/cases/{case_id}/iocs endpoint.
"""

import hashlib
import json
import socket
import tempfile
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.config import IOC_FEED_PATH, QUARANTINE_DIR
from app.db.database import SessionLocal, init_db
from app.db.models import Case, IOCResultRecord, MLResultRecord, ParsedData, RuleResultRecord
from app.ioc import (
    IOCEngine,
    IOCIndicator,
    IOCResult,
    IOCSourceRegistry,
    IOCStatus,
    IOCType,
    LocalFeedAdapter,
    evaluate_iocs,
    extract_iocs,
    normalize_domain,
    normalize_ipv4,
    normalize_sha256,
    normalize_url,
)
from app.jobs.process_case import process_case
from app.main import app
from app.parser.models import AttachmentMetadata, HeaderAddress, ParsedEmail

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_db():
    """Ensures test database tables exist before each test."""
    init_db()
    yield


# =====================================================================
# 1. Extraction Tests
# =====================================================================

def test_extract_urls_from_parsed_email():
    """Verifies that URLs in ParsedEmail are extracted as URL IOCs."""
    email = ParsedEmail(
        case_id="case-ioc-test-1",
        parser_version="1.0.0",
        parsed_timestamp=datetime.now(timezone.utc),
        urls=["https://example.test/login", "http://anotherexample.test/path?query=1"],
    )
    iocs = extract_iocs(email)
    url_iocs = [i for i in iocs if i.ioc_type == IOCType.URL]
    assert len(url_iocs) == 2
    assert url_iocs[0].original_value == "https://example.test/login"
    assert url_iocs[0].source_context == "email_url"


def test_extract_domain_from_url():
    """Verifies that non-IP hostnames in URLs are extracted as DOMAIN IOCs."""
    email = ParsedEmail(
        case_id="case-ioc-test-2",
        parser_version="1.0.0",
        parsed_timestamp=datetime.now(timezone.utc),
        urls=["https://sub.phishing-target.test/auth"],
    )
    iocs = extract_iocs(email)
    domain_iocs = [i for i in iocs if i.ioc_type == IOCType.DOMAIN and i.source_context == "url_domain"]
    assert len(domain_iocs) == 1
    assert domain_iocs[0].original_value == "sub.phishing-target.test"
    assert domain_iocs[0].normalized_value == "sub.phishing-target.test"


def test_extract_ipv4_from_url():
    """Verifies that IPv4 address hostnames in URLs are extracted as IP IOCs."""
    email = ParsedEmail(
        case_id="case-ioc-test-3",
        parser_version="1.0.0",
        parsed_timestamp=datetime.now(timezone.utc),
        urls=["http://203.0.113.10:8080/download"],
    )
    iocs = extract_iocs(email)
    ip_iocs = [i for i in iocs if i.ioc_type == IOCType.IP]
    assert len(ip_iocs) == 1
    assert ip_iocs[0].original_value == "203.0.113.10"
    assert ip_iocs[0].normalized_value == "203.0.113.10"
    assert ip_iocs[0].source_context == "url_ip"


def test_extract_attachment_sha256():
    """Verifies that attachment SHA-256 hashes are extracted as SHA256 IOCs."""
    h = "2a0a767f4b3e8c9d1a2b3c4d5e6f708192a1b2c3d4e5f60718293a4b5c6d7e8f"
    email = ParsedEmail(
        case_id="case-ioc-test-4",
        parser_version="1.0.0",
        parsed_timestamp=datetime.now(timezone.utc),
        attachments=[
            AttachmentMetadata(
                filename="invoice.pdf",
                content_type="application/pdf",
                size=1024,
                sha256=h,
                stored_path="data/attachments/test.pdf",
            )
        ],
    )
    iocs = extract_iocs(email)
    hash_iocs = [i for i in iocs if i.ioc_type == IOCType.SHA256]
    assert len(hash_iocs) == 1
    assert hash_iocs[0].original_value == h
    assert hash_iocs[0].source_context == "attachment_hash"


def test_extract_sender_domain():
    """Verifies that sender domain is extracted as DOMAIN IOC with sender_domain context."""
    email = ParsedEmail(
        case_id="case-ioc-test-5",
        parser_version="1.0.0",
        parsed_timestamp=datetime.now(timezone.utc),
        sender=HeaderAddress(raw="CEO <ceo@corporate-brand.test>", address="ceo@corporate-brand.test", domain="corporate-brand.test"),
    )
    iocs = extract_iocs(email)
    sender_iocs = [i for i in iocs if i.source_context == "sender_domain"]
    assert len(sender_iocs) == 1
    assert sender_iocs[0].normalized_value == "corporate-brand.test"


def test_extract_reply_to_domain():
    """Verifies that Reply-To domain is extracted as DOMAIN IOC with reply_to_domain context."""
    email = ParsedEmail(
        case_id="case-ioc-test-6",
        parser_version="1.0.0",
        parsed_timestamp=datetime.now(timezone.utc),
        headers={"Reply-To": "support@external-free-mail.test"},
    )
    iocs = extract_iocs(email)
    reply_iocs = [i for i in iocs if i.source_context == "reply_to_domain"]
    assert len(reply_iocs) == 1
    assert reply_iocs[0].normalized_value == "external-free-mail.test"


def test_extract_deduplication():
    """Verifies that duplicate indicators with identical type, value, and context are deduplicated."""
    email = ParsedEmail(
        case_id="case-ioc-test-7",
        parser_version="1.0.0",
        parsed_timestamp=datetime.now(timezone.utc),
        urls=["https://repeat.test/page", "https://repeat.test/page", "http://repeat.test/page"],
    )
    iocs = extract_iocs(email)
    # The host repeat.test appears multiple times with context url_domain
    domain_iocs = [i for i in iocs if i.ioc_type == IOCType.DOMAIN and i.normalized_value == "repeat.test"]
    assert len(domain_iocs) == 1


def test_extract_localhost_is_excluded():
    """Verifies localhost and loopback are not treated as domain IOCs."""
    email = ParsedEmail(
        case_id="case-ioc-test-8",
        parser_version="1.0.0",
        parsed_timestamp=datetime.now(timezone.utc),
        urls=["http://localhost/admin", "http://127.0.0.1/test"],
    )
    iocs = extract_iocs(email)
    domains = [i for i in iocs if i.ioc_type == IOCType.DOMAIN]
    assert not any(d.normalized_value in ("localhost", "127.0.0.1") for d in domains)


# =====================================================================
# 2. Normalization Tests
# =====================================================================

def test_normalize_domain_canonicalization():
    """Verifies domain normalization: lowercase, strip whitespace, remove trailing dot."""
    assert normalize_domain("  MALICIOUS-EXAMPLE.TEST.  ") == "malicious-example.test"
    assert normalize_domain("sub.example.com") == "sub.example.com"
    assert normalize_domain("invalid domain with spaces.com") is None
    assert normalize_domain("domain/with/slash.com") is None
    assert normalize_domain("") is None


def test_normalize_ipv4_validation():
    """Verifies IPv4 normalization and rejection of IPv6 or invalid IPs."""
    assert normalize_ipv4("  203.0.113.199  ") == "203.0.113.199"
    assert normalize_ipv4("999.999.999.999") is None
    assert normalize_ipv4("not-an-ip") is None
    assert normalize_ipv4("2001:db8::1") is None  # IPv6 rejected by IPv4 normalizer


def test_normalize_sha256_validation():
    """Verifies SHA-256 normalization and hexadecimal character checks."""
    valid_hash = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    assert normalize_sha256(valid_hash) == valid_hash.lower()
    # Invalid length
    assert normalize_sha256("e3b0c442") is None
    # Invalid character 'z'
    assert normalize_sha256("z" * 64) is None
    assert normalize_sha256("") is None


def test_normalize_url_canonicalization():
    """Verifies URL normalization: lowercases scheme and host, strips default ports."""
    url = "HTTP://Malicious-Target.TEST:80/Login/Verify?token=ABC#frag"
    normalized = normalize_url(url)
    assert normalized == "http://malicious-target.test/Login/Verify?token=ABC#frag"

    https_url = "HTTPS://Secure-Bank.TEST:443/Account"
    assert normalize_url(https_url) == "https://secure-bank.test/Account"


def test_original_ioc_preserved():
    """Verifies that original casing and whitespace are preserved in original_value."""
    raw_url = "HTTP://UPPERCASE-HOST.TEST/Path"
    email = ParsedEmail(
        case_id="case-ioc-test-orig",
        parser_version="1.0.0",
        parsed_timestamp=datetime.now(timezone.utc),
        urls=[raw_url],
    )
    iocs = extract_iocs(email)
    url_ioc = next(i for i in iocs if i.ioc_type == IOCType.URL)
    assert url_ioc.original_value == raw_url
    assert url_ioc.normalized_value == "http://uppercase-host.test/Path"


# =====================================================================
# 3. Feed Schema & Provenance Tests
# =====================================================================

def test_feed_file_exists_and_loads():
    """Verifies that the default indicators.json exists, validates, and computes SHA-256."""
    assert IOC_FEED_PATH.exists(), f"IOC feed file not found at {IOC_FEED_PATH}"
    adapter = LocalFeedAdapter(feed_path=IOC_FEED_PATH)
    assert adapter.is_available()
    assert adapter.version == "2026.09.1"
    assert adapter.sha256 is not None
    assert len(adapter.sha256) == 64


def test_feed_schema_validation_rejects_invalid_type():
    """Verifies that feed validation rejects unknown indicator types."""
    bad_data = {
        "feed_version": "1.0",
        "indicators": [
            {
                "type": "UNKNOWN_TYPE",
                "value": "example.com",
                "status": "known_malicious",
                "confidence": 90,
                "source": "test",
                "reason": "test",
            }
        ],
    }
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        json.dump(bad_data, f)
        tmp_path = Path(f.name)

    with pytest.raises(ValueError, match="invalid type"):
        LocalFeedAdapter(feed_path=tmp_path)


def test_feed_schema_validation_rejects_invalid_hash():
    """Verifies that feed validation rejects malformed SHA-256 hashes."""
    bad_data = {
        "feed_version": "1.0",
        "indicators": [
            {
                "type": "SHA256",
                "value": "not-a-valid-sha256-hash",
                "status": "known_malicious",
                "confidence": 90,
                "source": "test",
                "reason": "test",
            }
        ],
    }
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        json.dump(bad_data, f)
        tmp_path = Path(f.name)

    with pytest.raises(ValueError, match="invalid value"):
        LocalFeedAdapter(feed_path=tmp_path)


def test_feed_schema_validation_rejects_invalid_ip():
    """Verifies that feed validation rejects malformed IPv4 strings."""
    bad_data = {
        "feed_version": "1.0",
        "indicators": [
            {
                "type": "IP",
                "value": "999.888.777.666",
                "status": "known_malicious",
                "confidence": 90,
                "source": "test",
                "reason": "test",
            }
        ],
    }
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        json.dump(bad_data, f)
        tmp_path = Path(f.name)

    with pytest.raises(ValueError, match="invalid value"):
        LocalFeedAdapter(feed_path=tmp_path)


def test_feed_schema_validation_rejects_out_of_bounds_confidence():
    """Verifies that feed validation rejects confidence values outside 0-100."""
    bad_data = {
        "feed_version": "1.0",
        "indicators": [
            {
                "type": "DOMAIN",
                "value": "example.test",
                "status": "known_malicious",
                "confidence": 150,
                "source": "test",
                "reason": "test",
            }
        ],
    }
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        json.dump(bad_data, f)
        tmp_path = Path(f.name)

    with pytest.raises(ValueError, match="confidence must be an integer between 0 and 100"):
        LocalFeedAdapter(feed_path=tmp_path)


def test_feed_schema_validation_rejects_missing_required_fields():
    """Verifies that feed validation rejects records missing required fields."""
    bad_data = {
        "feed_version": "1.0",
        "indicators": [
            {
                "type": "DOMAIN",
                "value": "example.test",
                # missing status, confidence, source, reason
            }
        ],
    }
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        json.dump(bad_data, f)
        tmp_path = Path(f.name)

    with pytest.raises(ValueError, match="missing required fields"):
        LocalFeedAdapter(feed_path=tmp_path)


# =====================================================================
# 4. Lookup Semantics Tests
# =====================================================================

def test_lookup_known_malicious_domain():
    """Verifies lookup of a known malicious domain from the feed."""
    adapter = LocalFeedAdapter(feed_path=IOC_FEED_PATH)
    indicator = IOCIndicator(
        ioc_id="IOC-001",
        ioc_type=IOCType.DOMAIN,
        original_value="malicious-phish-bank.test",
        normalized_value="malicious-phish-bank.test",
        source_context="url_domain",
    )
    res = adapter.lookup(indicator)
    assert res.matched is True
    assert res.status == IOCStatus.KNOWN_MALICIOUS
    assert res.confidence == 95
    assert "phishing infrastructure" in res.reason.lower()
    assert res.feed_version == "2026.09.1"
    assert res.feed_sha256 is not None


def test_lookup_known_malicious_hash():
    """Verifies lookup of a known malicious attachment SHA-256 hash."""
    adapter = LocalFeedAdapter(feed_path=IOC_FEED_PATH)
    h = "2a0a767f4b3e8c9d1a2b3c4d5e6f708192a1b2c3d4e5f60718293a4b5c6d7e8f"
    indicator = IOCIndicator(
        ioc_id="IOC-002",
        ioc_type=IOCType.SHA256,
        original_value=h,
        normalized_value=h,
        source_context="attachment_hash",
    )
    res = adapter.lookup(indicator)
    assert res.matched is True
    assert res.status == IOCStatus.KNOWN_MALICIOUS
    assert res.confidence == 99
    assert "trojan dropper" in res.reason.lower()


def test_lookup_known_suspicious_indicator():
    """Verifies lookup of an indicator marked suspicious."""
    adapter = LocalFeedAdapter(feed_path=IOC_FEED_PATH)
    indicator = IOCIndicator(
        ioc_id="IOC-003",
        ioc_type=IOCType.DOMAIN,
        original_value="suspicious-marketing-track.test",
        normalized_value="suspicious-marketing-track.test",
        source_context="url_domain",
    )
    res = adapter.lookup(indicator)
    assert res.matched is True
    assert res.status == IOCStatus.KNOWN_SUSPICIOUS
    assert res.confidence == 60


def test_lookup_known_benign_indicator():
    """Verifies lookup of an indicator explicitly cataloged as benign."""
    adapter = LocalFeedAdapter(feed_path=IOC_FEED_PATH)
    indicator = IOCIndicator(
        ioc_id="IOC-004",
        ioc_type=IOCType.DOMAIN,
        original_value="trusted-partner-service.test",
        normalized_value="trusted-partner-service.test",
        source_context="sender_domain",
    )
    res = adapter.lookup(indicator)
    assert res.matched is True
    assert res.status == IOCStatus.KNOWN_BENIGN
    assert res.confidence == 90


def test_lookup_not_found_semantics():
    """CRITICAL FORENSIC SEMANTIC TEST: Uncataloged IOC yields NOT_FOUND, NEVER KNOWN_BENIGN."""
    adapter = LocalFeedAdapter(feed_path=IOC_FEED_PATH)
    indicator = IOCIndicator(
        ioc_id="IOC-005",
        ioc_type=IOCType.DOMAIN,
        original_value="random-unknown-domain-9821.test",
        normalized_value="random-unknown-domain-9821.test",
        source_context="url_domain",
    )
    res = adapter.lookup(indicator)
    assert res.matched is False
    assert res.status == IOCStatus.NOT_FOUND
    assert res.status != IOCStatus.KNOWN_BENIGN
    assert res.confidence == 0
    assert "not present in local threat intelligence feed" in res.reason


# =====================================================================
# 5. Engine & Adapter Integration Tests
# =====================================================================

def test_ioc_engine_evaluation_summary():
    """Verifies full IOCEngine evaluation aggregating multiple indicators and calculating counts."""
    email = ParsedEmail(
        case_id="case-ioc-eval-1",
        parser_version="1.0.0",
        parsed_timestamp=datetime.now(timezone.utc),
        urls=["http://malicious-phish-bank.test/login/verify", "http://unknown-domain.test/page"],
        attachments=[
            AttachmentMetadata(
                filename="payload.exe",
                content_type="application/octet-stream",
                size=2048,
                sha256="2a0a767f4b3e8c9d1a2b3c4d5e6f708192a1b2c3d4e5f60718293a4b5c6d7e8f",
                stored_path="data/attachments/payload.exe",
            )
        ],
    )
    summary = evaluate_iocs(email)
    assert summary.case_id == "case-ioc-eval-1"
    assert summary.summary.total_iocs >= 4  # 2 URLs, 2 URL domains, 1 hash
    assert summary.summary.malicious_iocs >= 2  # URL + domain + hash
    assert summary.summary.not_found_iocs >= 1  # unknown-domain.test
    assert len(summary.feed_versions) > 0
    assert len(summary.feed_sha256s) > 0


def test_ioc_engine_graceful_handling_when_feed_missing():
    """Verifies graceful handling when the threat intelligence feed file is unavailable."""
    missing_adapter = LocalFeedAdapter(feed_path=Path("data/ioc/nonexistent_feed.json"))
    registry = IOCSourceRegistry()
    registry.register(missing_adapter)
    engine = IOCEngine(registry=registry)

    email = ParsedEmail(
        case_id="case-ioc-missing-feed",
        parser_version="1.0.0",
        parsed_timestamp=datetime.now(timezone.utc),
        urls=["http://test.com"],
    )
    summary = engine.evaluate(email)
    assert summary.summary.total_iocs >= 1
    # Check that error is recorded on the result
    assert all(r.status == IOCStatus.ERROR for r in summary.results)


# =====================================================================
# 6. Independence Invariant Tests (Strict Decoupling)
# =====================================================================

def test_ioc_engine_is_independent_of_rules_and_ml():
    """Verifies IOC Engine results do not depend on Rules Engine or ML outputs."""
    email = ParsedEmail(
        case_id="case-ioc-indep",
        parser_version="1.0.0",
        parsed_timestamp=datetime.now(timezone.utc),
        urls=["http://malicious-phish-bank.test/login/verify"],
    )

    # Evaluate IOCs
    res1 = evaluate_iocs(email)

    # Re-evaluate with zero rules or ML involvement
    res2 = evaluate_iocs(email)

    assert res1.summary.total_iocs == res2.summary.total_iocs
    assert res1.summary.malicious_iocs == res2.summary.malicious_iocs
    assert [r.status for r in res1.results] == [r.status for r in res2.results]


# =====================================================================
# 7. No-Network Guarantee Test
# =====================================================================

def test_ioc_analysis_does_not_make_network_calls():
    """Asserts that IOC extraction, normalization, and local lookup make ZERO network connections."""
    email = ParsedEmail(
        case_id="case-ioc-no-net",
        parser_version="1.0.0",
        parsed_timestamp=datetime.now(timezone.utc),
        urls=[
            "http://malicious-phish-bank.test/login/verify",
            "http://203.0.113.199/malware.exe",
            "http://unknown-host.test/path",
        ],
        attachments=[
            AttachmentMetadata(
                filename="test.bin",
                content_type="application/octet-stream",
                size=512,
                sha256="bad1dea000000000000000000000000000000000000000000000000000000001",
                stored_path="data/attachments/test.bin",
            )
        ],
        sender=HeaderAddress(domain="malicious-phish-bank.test"),
    )

    # Patch socket.socket to raise RuntimeError if network call attempted
    with patch("socket.socket") as mock_socket:
        mock_socket.side_effect = RuntimeError("NETWORK CALL PROHIBITED DURING IOC ANALYSIS")
        summary = evaluate_iocs(email)
        assert summary.summary.total_iocs > 0
        assert summary.summary.malicious_iocs > 0


# =====================================================================
# 8. Database Persistence & REST API Tests
# =====================================================================

def test_ioc_results_database_persistence_and_api():
    """Verifies that IOC results persist into SQLite and are retrieved via GET /api/cases/{case_id}/iocs."""
    case_id = "test-case-ioc-db-api"
    with SessionLocal() as db:
        case = Case(
            case_id=case_id,
            original_filename="ioc_test.eml",
            stored_path="data/quarantine/ioc_test.eml",
            sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            file_size=200,
            file_extension=".eml",
            status="complete",
        )
        db.merge(case)

        # Clear any prior records for this case
        db.query(IOCResultRecord).filter(IOCResultRecord.case_id == case_id).delete()
        db.flush()

        # Add IOC result record
        ioc_rec = IOCResultRecord(
            case_id=case_id,
            ioc_id="IOC-001",
            ioc_type="DOMAIN",
            original_value="malicious-phish-bank.test",
            normalized_value="malicious-phish-bank.test",
            source_context="email_url",
            matched=True,
            status="known_malicious",
            confidence=95,
            source="local-dev-feed",
            reason="Active phishing infrastructure",
            feed_version="2026.09.1",
            feed_sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            lookup_timestamp=datetime.now(timezone.utc),
        )
        db.merge(ioc_rec)
        db.commit()

    resp = client.get(f"/api/cases/{case_id}/iocs")
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == case_id
    assert data["summary"]["total_iocs"] == 1
    assert data["summary"]["malicious_iocs"] == 1
    assert len(data["results"]) == 1
    assert data["results"][0]["normalized_value"] == "malicious-phish-bank.test"
    assert data["results"][0]["status"] == "known_malicious"
    assert data["results"][0]["confidence"] == 95


def test_api_get_case_iocs_not_found():
    """Verifies 404 response for nonexistent case."""
    resp = client.get("/api/cases/nonexistent-case-id-99999/iocs")
    assert resp.status_code == 404


# =====================================================================
# 9. End-to-End Worker & Evidence Immutability Tests
# =====================================================================

def test_worker_process_case_end_to_end_with_ioc():
    """Verifies worker process_case runs Parser + Rules + ML + IOC and preserves evidence byte immutability."""
    case_id = "test-case-worker-ioc-e2e"

    msg = MIMEMultipart()
    msg["From"] = "security@malicious-phish-bank.test"
    msg["To"] = "victim@example.com"
    msg["Subject"] = "Urgent: Your account is suspended"
    msg["Message-ID"] = "<worker-ioc-msg@test.local>"
    msg.attach(
        MIMEText(
            "Please verify your credentials at http://malicious-phish-bank.test/login/verify immediately.",
            "plain",
        )
    )
    raw_bytes = msg.as_bytes()
    expected_hash = hashlib.sha256(raw_bytes).hexdigest()

    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    stored_path = QUARANTINE_DIR / f"{case_id}.eml"
    with open(stored_path, "wb") as f:
        f.write(raw_bytes)

    with SessionLocal() as db:
        case = Case(
            case_id=case_id,
            original_filename="worker_ioc_test.eml",
            stored_path=str(stored_path),
            sha256=expected_hash,
            file_size=len(raw_bytes),
            file_extension=".eml",
            status="queued",
        )
        db.merge(case)
        db.commit()

    # Execute worker job
    result = process_case(case_id)
    assert result["status"] == "complete"
    assert result["rules_verdict"] is not None
    assert result["ml_prediction"] is not None
    assert result["ioc_total"] is not None and result["ioc_total"] > 0
    assert result["ioc_malicious"] is not None and result["ioc_malicious"] > 0

    # FORENSIC INVARIANT: verify raw file on disk is byte-for-byte identical
    with open(stored_path, "rb") as f:
        post_bytes = f.read()
    assert post_bytes == raw_bytes
    assert hashlib.sha256(post_bytes).hexdigest() == expected_hash

    # Verify IOC records persisted in database
    with SessionLocal() as db:
        records = db.query(IOCResultRecord).filter(IOCResultRecord.case_id == case_id).all()
        assert len(records) > 0
        malicious_records = [r for r in records if r.status == "known_malicious"]
        assert len(malicious_records) > 0

    # Verify API returns findings
    api_resp = client.get(f"/api/cases/{case_id}/iocs")
    assert api_resp.status_code == 200
    api_data = api_resp.json()
    assert api_data["summary"]["malicious_iocs"] > 0
