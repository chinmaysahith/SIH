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
from app.db.models import Case, GeoOriginResultRecord
from app.geo.models import (
    CandidateIP,
    GeoIPRecord,
    GeoOriginResult,
    IPClassification,
    NetworkIntelligenceRecord,
    OriginConfidence,
)
from app.geo.ip_classifier import classify_ip
from app.geo.received_parser import parse_received_headers
from app.geo.origin import select_origin_ip
from app.geo.providers import LocalGeoIPProvider, LocalNetworkIntelProvider
from app.geo.engine import GeoOriginEngine, evaluate_geo_origin
from app.jobs.process_case import process_case
from app.main import app
from app.parser.models import ParsedEmail

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_db():
    """Ensures test database tables exist before each test."""
    init_db()
    yield


# =====================================================================
# 1. IP Classifier Tests
# =====================================================================

def test_ip_classifier_standard_ranges():
    # Loopback
    c, v = classify_ip("127.0.0.1")
    assert c == IPClassification.LOOPBACK
    assert v == 4

    c6, v6 = classify_ip("::1")
    assert c6 == IPClassification.LOOPBACK
    assert v6 == 6

    # Private RFC 1918
    assert classify_ip("10.0.0.1")[0] == IPClassification.PRIVATE
    assert classify_ip("172.16.5.2")[0] == IPClassification.PRIVATE
    assert classify_ip("192.168.1.1")[0] == IPClassification.PRIVATE

    # Documentation RFC 5737 & RFC 3849
    assert classify_ip("192.0.2.1")[0] == IPClassification.DOCUMENTATION
    assert classify_ip("198.51.100.25")[0] == IPClassification.DOCUMENTATION
    assert classify_ip("203.0.113.199")[0] == IPClassification.DOCUMENTATION
    assert classify_ip("2001:db8::1")[0] == IPClassification.DOCUMENTATION

    # Global routable
    assert classify_ip("8.8.8.8")[0] == IPClassification.GLOBAL
    assert classify_ip("1.1.1.1")[0] == IPClassification.GLOBAL
    assert classify_ip("2606:4700:4700::1111")[0] == IPClassification.GLOBAL

    # Link Local & Multicast
    assert classify_ip("169.254.1.1")[0] == IPClassification.LINK_LOCAL
    assert classify_ip("224.0.0.1")[0] == IPClassification.MULTICAST

    # Invalid
    assert classify_ip("999.999.999.999")[0] == IPClassification.INVALID
    assert classify_ip("not-an-ip")[0] == IPClassification.INVALID


# =====================================================================
# 2. Received Header Parsing Tests
# =====================================================================

def test_received_headers_parsing():
    headers = [
        "from mail-relay.internal (10.0.0.2) by recipient.internal (10.0.0.1) with SMTP; Fri, 05 Sep 2026 12:00:00 +0000",
        "from mail.suspicious-origin.test (198.51.100.50) by mail-relay.internal (10.0.0.2); Fri, 05 Sep 2026 11:59:50 +0000",
        "from [192.168.1.100] by mail.suspicious-origin.test (198.51.100.50); Fri, 05 Sep 2026 11:59:40 +0000",
    ]

    candidates = parse_received_headers(headers)
    assert len(candidates) >= 3

    hop0_candidates = [c for c in candidates if c.hop_index == 0]
    assert any(c.ip == "192.168.1.100" for c in hop0_candidates)
    assert any(c.ip == "198.51.100.50" for c in hop0_candidates)

    priv = next(c for c in candidates if c.ip == "192.168.1.100")
    assert priv.classification == IPClassification.PRIVATE
    assert priv.is_origin_candidate is False

    doc = next(c for c in candidates if c.ip == "198.51.100.50")
    assert doc.classification == IPClassification.DOCUMENTATION
    assert doc.is_origin_candidate is True


def test_empty_received_headers():
    candidates = parse_received_headers([])
    assert candidates == []

    selected_ip, method, conf, limits = select_origin_ip([])
    assert selected_ip is None
    assert conf == OriginConfidence.UNKNOWN


# =====================================================================
# 3. Origin Selection Heuristic Tests
# =====================================================================

def test_origin_selection_earliest_public():
    c1 = CandidateIP(
        ip="10.0.1.5",
        ip_version=4,
        classification=IPClassification.PRIVATE,
        hop_index=0,
        raw_header_snippet="from 10.0.1.5",
        is_origin_candidate=False,
    )
    c2 = CandidateIP(
        ip="203.0.113.10",
        ip_version=4,
        classification=IPClassification.DOCUMENTATION,
        hop_index=0,
        raw_header_snippet="by 203.0.113.10",
        is_origin_candidate=True,
    )
    c3 = CandidateIP(
        ip="8.8.8.8",
        ip_version=4,
        classification=IPClassification.GLOBAL,
        hop_index=1,
        raw_header_snippet="by 8.8.8.8",
        is_origin_candidate=True,
    )

    selected_ip, method, conf, limits = select_origin_ip([c1, c2, c3])
    assert selected_ip == "203.0.113.10"
    assert method == "earliest_plausible_public_ip"
    assert conf == OriginConfidence.HIGH
    assert any("private" in lim.lower() for lim in limits)


def test_origin_selection_all_private():
    c1 = CandidateIP(
        ip="10.0.1.5",
        ip_version=4,
        classification=IPClassification.PRIVATE,
        hop_index=0,
        raw_header_snippet="from 10.0.1.5",
        is_origin_candidate=False,
    )
    c2 = CandidateIP(
        ip="127.0.0.1",
        ip_version=4,
        classification=IPClassification.LOOPBACK,
        hop_index=1,
        raw_header_snippet="by 127.0.0.1",
        is_origin_candidate=False,
    )

    selected_ip, method, conf, limits = select_origin_ip([c1, c2])
    assert selected_ip is None
    assert conf == OriginConfidence.UNKNOWN
    assert any("no public originating ip" in lim.lower() for lim in limits)


# =====================================================================
# 4. Local Providers Tests
# =====================================================================

def test_local_geoip_and_network_intel_providers():
    geoip = LocalGeoIPProvider()
    net_intel = LocalNetworkIntelProvider()

    assert geoip.version != "unknown"
    assert geoip.sha256 is not None
    assert net_intel.version != "unknown"
    assert net_intel.sha256 is not None

    # Lookup 198.51.100.50 (Amsterdam, Leaseweb, Tor Exit)
    geo_res = geoip.lookup("198.51.100.50")
    assert geo_res is not None
    assert geo_res.country_code == "NL"
    assert geo_res.city == "Amsterdam"
    assert geo_res.asn == 60781

    intel_res = net_intel.lookup("198.51.100.50")
    assert intel_res is not None
    assert intel_res.is_tor_exit is True
    assert intel_res.is_datacenter_hosting is True

    # Lookup 203.0.113.199 (Romania, M247, VPN)
    geo_vpn = geoip.lookup("203.0.113.199")
    assert geo_vpn is not None
    assert geo_vpn.country_code == "RO"

    intel_vpn = net_intel.lookup("203.0.113.199")
    assert intel_vpn is not None
    assert intel_vpn.is_vpn is True
    assert intel_vpn.is_proxy is True

    # Lookup non-existent IP in local fixture
    geo_none = geoip.lookup("192.0.2.99")
    assert geo_none is None

    intel_unknown = net_intel.lookup("192.0.2.99")
    assert intel_unknown.is_tor_exit is None
    assert intel_unknown.is_vpn is None


# =====================================================================
# 5. Engine Independence & Offline Guarantee
# =====================================================================

def test_geo_engine_end_to_end_independence():
    """Confirms GeoOriginEngine evaluates ONLY received_headers and requires NO Rules, ML, or IOC results."""
    dummy_email = ParsedEmail(
        case_id="case_geo_test_01",
        parser_version="1.0.0",
        parsed_timestamp=datetime.now(timezone.utc),
        headers={"subject": "Urgent notice"},
        received_headers=[
            "from mx.test (10.0.0.1) by dest.internal; Fri, 05 Sep 2026 12:00:00 +0000",
            "from client.test (203.0.113.199) by mx.test; Fri, 05 Sep 2026 11:59:00 +0000",
        ],
        subject="Urgent notice",
        body_text="Click here to login: https://example.test",
        urls=["https://example.test"],
    )

    result = evaluate_geo_origin(dummy_email)
    assert isinstance(result, GeoOriginResult)
    assert result.case_id == "case_geo_test_01"
    assert result.selected_origin_ip == "203.0.113.199"
    assert result.confidence in (OriginConfidence.HIGH, OriginConfidence.MEDIUM)
    assert result.geo_data is not None
    assert result.geo_data.country_code == "RO"
    assert result.network_intel is not None
    assert result.network_intel.is_vpn is True
    assert "Forensic Disclaimer" in result.disclaimer


# =====================================================================
# 6. API Endpoint Tests
# =====================================================================

def test_api_get_case_geo_not_found():
    resp = client.get("/api/cases/nonexistent-case-geo-404/geo")
    assert resp.status_code == 404


def test_api_get_case_geo_success():
    case_id = "test-case-api-geo-01"
    with SessionLocal() as db:
        db.query(GeoOriginResultRecord).filter(GeoOriginResultRecord.case_id == case_id).delete()
        db.query(Case).filter(Case.case_id == case_id).delete()
        db.commit()

        case = Case(
            case_id=case_id,
            original_filename="geo_api_test.eml",
            stored_path="dummy/path",
            sha256="abc123sha256",
            file_size=100,
            file_extension=".eml",
            status="complete",
        )
        db.add(case)

        geo_record = GeoOriginResultRecord(
            case_id=case_id,
            analysis_version="1.0.0",
            analysis_timestamp=datetime.now(timezone.utc),
            selected_origin_ip="198.51.100.50",
            selection_method="earliest_plausible_public_ip",
            confidence="HIGH",
            status="SUCCESS",
            candidate_ips_json=json.dumps([
                {"ip": "198.51.100.50", "ip_version": 4, "classification": "DOCUMENTATION", "hop_index": 0, "raw_header_snippet": "from test", "is_origin_candidate": True}
            ]),
            geo_data_json=json.dumps({
                "ip": "198.51.100.50", "country_code": "NL", "country_name": "Netherlands", "city": "Amsterdam", "asn": 60781, "asn_org": "LEASENEWEB"
            }),
            network_intel_json=json.dumps({
                "ip": "198.51.100.50", "is_tor_exit": True, "is_vpn": False, "is_proxy": False, "is_datacenter_hosting": True
            }),
            limitations_json=json.dumps(["Sample limitation"]),
            disclaimer="Forensic Disclaimer: Approximate location only.",
        )
        db.merge(geo_record)
        db.commit()

    resp = client.get(f"/api/cases/{case_id}/geo")
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == case_id
    assert data["selected_origin_ip"] == "198.51.100.50"
    assert data["geo_data"]["country_code"] == "NL"
    assert data["network_intel"]["is_tor_exit"] is True


# =====================================================================
# 7. End-to-End Worker & Evidence Immutability Tests
# =====================================================================

def test_worker_process_case_end_to_end_with_geo():
    """Verifies worker process_case runs Parser + Rules + ML + IOC + Geo and preserves evidence byte immutability."""
    case_id = "test-case-worker-geo-e2e"

    msg = MIMEMultipart()
    msg["From"] = "attacker@external-source.test"
    msg["To"] = "target@company.test"
    msg["Subject"] = "Invoice Overdue Action Required"
    msg["Message-ID"] = "<worker-geo-msg@test.local>"
    # Add Received headers with 198.51.100.50 (Tor exit node in local fixture)
    msg["Received"] = "from relay.internal (10.0.0.1) by dest.internal; Fri, 05 Sep 2026 12:00:00 +0000"
    msg["Received"] = "from tor-exit.test (198.51.100.50) by relay.internal; Fri, 05 Sep 2026 11:59:00 +0000"

    msg.attach(MIMEText("Please pay invoice immediately.", "plain"))
    raw_bytes = msg.as_bytes()
    expected_hash = hashlib.sha256(raw_bytes).hexdigest()

    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    stored_path = QUARANTINE_DIR / f"{case_id}.eml"
    with open(stored_path, "wb") as f:
        f.write(raw_bytes)

    with SessionLocal() as db:
        case = Case(
            case_id=case_id,
            original_filename="worker_geo_test.eml",
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
    assert result["ioc_total"] is not None
    assert result["origin_ip"] == "198.51.100.50"
    assert result["origin_confidence"] in ("HIGH", "MEDIUM", "LOW")
    assert result["origin_country"] == "NL"

    # FORENSIC INVARIANT: verify raw file on disk is byte-for-byte identical (0 bytes mutated)
    with open(stored_path, "rb") as f:
        post_bytes = f.read()
    assert post_bytes == raw_bytes
    assert hashlib.sha256(post_bytes).hexdigest() == expected_hash

    # Verify Geo record persisted in database
    with SessionLocal() as db:
        rec = db.query(GeoOriginResultRecord).filter(GeoOriginResultRecord.case_id == case_id).one_or_none()
        assert rec is not None
        assert rec.selected_origin_ip == "198.51.100.50"
        geo_data = json.loads(rec.geo_data_json)
        assert geo_data["city"] == "Amsterdam"
        intel_data = json.loads(rec.network_intel_json)
        assert intel_data["is_tor_exit"] is True

    # Verify API endpoint returns Geo findings
    api_resp = client.get(f"/api/cases/{case_id}/geo")
    assert api_resp.status_code == 200
    api_data = api_resp.json()
    assert api_data["selected_origin_ip"] == "198.51.100.50"
    assert api_data["geo_data"]["country_name"] == "Netherlands"
    assert api_data["network_intel"]["is_tor_exit"] is True
