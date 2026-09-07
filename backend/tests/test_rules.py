"""Comprehensive test suite for Stage 3 — Rules Engine.

Verifies:
1. All individual rule logic (headers, sender, recipient, content, url, attachment).
2. Scoring arithmetic, category caps, total capping at 100, and verdict thresholds.
3. Strict determinism: identical parsed input produces identical output.
4. Edge cases: missing fields, empty strings, malformed URLs, empty attachments.
5. Evidence structure: machine-readable JSON dictionary for each matched rule.
6. False-positive context availability across all rules.
7. End-to-end integration via process_case worker and API endpoint.
8. Quarantine evidence immutability (forensic invariant).
"""

import hashlib
import io
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
import fakeredis
from fastapi.testclient import TestClient
import pytest

from app.config import QUARANTINE_DIR
from app.db.database import SessionLocal, init_db
from app.db.models import Case, ParsedData, RuleResultRecord
from app.jobs.process_case import process_case
from app.main import app
from app.rules.engine import RULES_ENGINE_VERSION, evaluate_rules
from app.rules.models import RuleCategory, RuleSeverity, RulesVerdict
from app.rules.scoring import CATEGORY_CAPS, calculate_scores_and_verdict
from app.rules.rules.header_rules import (
    MultipleReceivedHopsRule,
    MissingMessageIdRule,
    InconsistentSenderHeadersRule,
    RuleHdr001,
    RuleHdr002,
    RuleHdr003,
)
from app.rules.rules.sender_rules import (
    ReplyToMismatchRule,
    DisplayNameImpersonationRule,
    MissingSenderDomainRule,
    RuleSender001,
    RuleSender002,
    RuleSender003,
)
from app.rules.rules.recipient_rules import (
    UndisclosedRecipientsRule,
    RuleRecipient001,
)
from app.rules.rules.content_rules import (
    UrgencyLanguageRule,
    SensitiveInformationRequestRule,
    ThreatLanguageRule,
    HtmlContentPresentRule,
    RuleContent001,
    RuleContent002,
    RuleContent003,
    RuleContent004,
)
from app.rules.rules.url_rules import (
    UrlPresentRule,
    InsecureHttpLinkRule,
    IpAddressHostLinkRule,
    SuspiciousUrlObfuscationRule,
    CredentialAuthPathRule,
    RuleUrl001,
    RuleUrl002,
    RuleUrl003,
    RuleUrl004,
    RuleUrl005,
)
from app.rules.rules.attachment_rules import (
    AttachmentPresentRule,
    DangerousExtensionRule,
    DoubleExtensionRule,
    FinancialAttachmentNameRule,
    RuleAttach001,
    RuleAttach002,
    RuleAttach003,
    RuleAttach004,
)
import app.services.queue as queue_service

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_env(monkeypatch):
    """Ensure database initialized and mock Redis with fakeredis."""
    init_db()
    fake_redis = fakeredis.FakeRedis()
    monkeypatch.setattr(queue_service, "get_redis_connection", lambda url=None: fake_redis)
    return fake_redis


# ---------------------------------------------------------------------------
# 1. Header Rules Tests
# ---------------------------------------------------------------------------

def test_rule_hdr_001_multiple_received_hops():
    rule = RuleHdr001()
    # >= 3 hops matches
    res_three = rule.evaluate({"received_headers": ["hop1", "hop2", "hop3"]})
    assert res_three.matched is True
    assert res_three.score == 5
    assert res_three.evidence["received_count"] == 3

    # < 3 hops does not match
    res_one = rule.evaluate({"received_headers": ["hop1"]})
    assert res_one.matched is False
    assert res_one.score == 0


def test_rule_hdr_002_missing_message_id():
    rule = RuleHdr002()
    # Missing Message-ID matches
    res = rule.evaluate({"headers": {"subject": "Hello", "from": "a@b.com"}})
    assert res.matched is True
    assert res.score == 10
    assert res.evidence["message_id_present"] is False

    # Present Message-ID does not match
    res2 = rule.evaluate({"headers": {"message-id": "<123@domain.com>"}})
    assert res2.matched is False
    assert res2.score == 0


def test_rule_hdr_003_inconsistent_sender_headers():
    rule = RuleHdr003()
    # From domain differs from Return-Path domain
    data = {
        "sender": {"domain": "legit.com"},
        "headers": {"return-path": "<bounce@marketing-relay.net>"},
    }
    res = rule.evaluate(data)
    assert res.matched is True
    assert res.score == 10
    assert res.evidence["from_domain"] == "legit.com"
    assert res.evidence["return_path_domain"] == "marketing-relay.net"

    # Matching domains
    data_match = {
        "sender": {"domain": "legit.com"},
        "headers": {"return-path": "<mailer@legit.com>"},
    }
    assert rule.evaluate(data_match).matched is False


# ---------------------------------------------------------------------------
# 2. Sender Rules Tests
# ---------------------------------------------------------------------------

def test_rule_sender_001_from_reply_to_mismatch():
    rule = RuleSender001()
    data = {
        "sender": {"domain": "legit-company.com"},
        "recipients": {"reply_to": [{"domain": "attacker-gmail.com"}]},
    }
    res = rule.evaluate(data)
    assert res.matched is True
    assert res.score == 20
    assert res.evidence["from_domain"] == "legit-company.com"
    assert res.evidence["reply_to_domain"] == "attacker-gmail.com"

    # Matching domains
    data_match = {
        "sender": {"domain": "corp.com"},
        "recipients": {"reply_to": [{"domain": "corp.com"}]},
    }
    assert rule.evaluate(data_match).matched is False


def test_rule_sender_002_display_name_impersonation():
    rule = RuleSender002()
    data = {
        "sender": {
            "display_name": "Microsoft Security Team",
            "domain": "evil-phish.net",
        }
    }
    res = rule.evaluate(data)
    assert res.matched is True
    assert res.score == 25
    assert res.evidence["claimed_brand"] == "microsoft"

    # Legitimate Microsoft domain
    data_legit = {
        "sender": {
            "display_name": "Microsoft Support",
            "domain": "microsoft.com",
        }
    }
    assert rule.evaluate(data_legit).matched is False


def test_rule_sender_003_missing_sender_domain():
    rule = RuleSender003()
    data = {"sender": {"domain": ""}}
    res = rule.evaluate(data)
    assert res.matched is True
    assert res.score == 15

    # Present sender domain
    data_valid = {"sender": {"domain": "example.com"}}
    assert rule.evaluate(data_valid).matched is False


# ---------------------------------------------------------------------------
# 3. Recipient Rules Tests
# ---------------------------------------------------------------------------

def test_rule_recipient_001_undisclosed_recipients():
    rule = RuleRecipient001()
    # Missing To list
    res_empty = rule.evaluate({"recipients": {"to": []}})
    assert res_empty.matched is True
    assert res_empty.score == 5

    # Explicit undisclosed-recipients
    res_undisc = rule.evaluate({"recipients": {"to": [{"raw": "undisclosed-recipients:;"}]}})
    assert res_undisc.matched is True
    assert res_undisc.score == 5

    # Valid recipient
    res_valid = rule.evaluate({"recipients": {"to": [{"raw": "victim@corp.com"}]}})
    assert res_valid.matched is False


# ---------------------------------------------------------------------------
# 4. Content Rules Tests
# ---------------------------------------------------------------------------

def test_rule_content_001_urgency_language():
    rule = RuleContent001()
    data = {
        "subject": "Urgent: Action required on your account",
        "body_text": "Please verify now within 24 hours.",
    }
    res = rule.evaluate(data)
    assert res.matched is True
    assert res.score == 10
    assert len(res.evidence["matched_terms"]) > 0

    # Benign content
    data_benign = {
        "subject": "Quarterly meeting notes",
        "body_text": "Here are the notes from today's discussion.",
    }
    assert rule.evaluate(data_benign).matched is False


def test_rule_content_002_sensitive_info_request():
    rule = RuleContent002()
    data = {
        "body_text": "Please confirm your password, credentials, and verification code to proceed.",
    }
    res = rule.evaluate(data)
    assert res.matched is True
    assert res.score == 20
    assert "password" in res.evidence["matched_terms"]


def test_rule_content_003_threat_language():
    rule = RuleContent003()
    data = {
        "body_text": "Failure to comply will result in account suspended and immediate legal action.",
    }
    res = rule.evaluate(data)
    assert res.matched is True
    assert res.score == 15
    assert "account suspended" in res.evidence["matched_terms"]


def test_rule_content_004_html_content_present():
    rule = RuleContent004()
    assert rule.evaluate({"body_html": "<p>Formatted content</p>"}).matched is True
    assert rule.evaluate({"body_html": None}).matched is False


# ---------------------------------------------------------------------------
# 5. URL Rules Tests
# ---------------------------------------------------------------------------

def test_rule_url_001_url_present():
    rule = RuleUrl001()
    assert rule.evaluate({"urls": ["https://example.com"]}).matched is True
    assert rule.evaluate({"urls": []}).matched is False


def test_rule_url_002_insecure_http_link():
    rule = RuleUrl002()
    data = {"urls": ["http://insecure-site.org/login", "https://secure.org"]}
    res = rule.evaluate(data)
    assert res.matched is True
    assert res.score == 10
    assert res.evidence["insecure_url_count"] == 1


def test_rule_url_003_ip_address_host():
    rule = RuleUrl003()
    data = {"urls": ["http://192.168.1.100/login.php", "https://example.com"]}
    res = rule.evaluate(data)
    assert res.matched is True
    assert res.score == 25
    assert res.evidence["ip_host_url_count"] == 1

    # Normal domain
    assert rule.evaluate({"urls": ["https://google.com"]}).matched is False


def test_rule_url_004_suspicious_url_obfuscation():
    rule = RuleUrl004()
    # Obfuscated with userinfo @
    data_userinfo = {"urls": ["https://google.com@evil-attacker.com/payload"]}
    res = rule.evaluate(data_userinfo)
    assert res.matched is True
    assert res.score == 20

    # Obfuscated with excessive percent-encoding (>3 '%')
    data_enc = {"urls": ["https://evil.com/%25%2e%2e%2fadmin"]}
    assert rule.evaluate(data_enc).matched is True


def test_rule_url_005_credential_auth_path():
    rule = RuleUrl005()
    data = {"urls": ["https://fake-bank.com/signin/verify"]}
    res = rule.evaluate(data)
    assert res.matched is True
    assert res.score == 15
    assert len(res.evidence["matched_samples"]) > 0


# ---------------------------------------------------------------------------
# 6. Attachment Rules Tests
# ---------------------------------------------------------------------------

def test_rule_attach_001_attachment_present():
    rule = RuleAttach001()
    assert rule.evaluate({"attachments": [{"filename": "doc.pdf"}]}).matched is True
    assert rule.evaluate({"attachments": []}).matched is False


def test_rule_attach_002_dangerous_extension():
    rule = RuleAttach002()
    data = {"attachments": [{"filename": "trojan.exe"}, {"filename": "normal.pdf"}]}
    res = rule.evaluate(data)
    assert res.matched is True
    assert res.score == 30
    assert res.evidence["dangerous_count"] == 1

    # Safe attachment
    assert rule.evaluate({"attachments": [{"filename": "notes.txt"}]}).matched is False


def test_rule_attach_003_double_extension():
    rule = RuleAttach003()
    data = {"attachments": [{"filename": "urgent_invoice.pdf.exe"}]}
    res = rule.evaluate(data)
    assert res.matched is True
    assert res.score == 35
    assert res.evidence["matches"][0]["decoy_extension"] == ".pdf"
    assert res.evidence["matches"][0]["actual_extension"] == ".exe"

    # Benign archive extension
    assert rule.evaluate({"attachments": [{"filename": "archive.tar.gz"}]}).matched is False


def test_rule_attach_004_financial_attachment_name():
    rule = RuleAttach004()
    data = {"attachments": [{"filename": "INVOICE_49102.pdf"}]}
    res = rule.evaluate(data)
    assert res.matched is True
    assert res.score == 15
    assert "INVOICE_49102.pdf" in res.evidence["matched_filenames"]


# ---------------------------------------------------------------------------
# 7. Scoring, Category Caps, and Verdict Thresholds
# ---------------------------------------------------------------------------

def test_scoring_category_caps():
    # URL category: 5 rules with scores 2 + 10 + 25 + 20 + 15 = 72, capped at 40
    data = {
        "urls": ["http://192.168.1.50@phish.net/login?token=%20%21%22%23"]
    }
    summary = evaluate_rules(data)
    assert summary.category_scores["url"] <= CATEGORY_CAPS[RuleCategory.URL]
    assert summary.category_scores["url"] == 40


def test_verdict_thresholds():
    # 1. Benign: score < 20
    benign_data = {
        "headers": {"message-id": "<msg-01@corp.com>"},
        "received_headers": ["hop1"],
        "sender": {"domain": "corp.com", "display_name": "Alice"},
        "recipients": {"to": [{"raw": "bob@corp.com"}], "reply_to": [{"domain": "corp.com"}]},
        "subject": "Quick sync",
        "body_text": "Let's chat about the project tomorrow.",
        "body_html": None,
        "urls": [],
        "attachments": [],
    }
    s_benign = evaluate_rules(benign_data)
    assert s_benign.total_score < 20
    assert s_benign.verdict == RulesVerdict.BENIGN

    # 2. Suspicious: 20 <= score < 50
    suspicious_data = {
        **benign_data,
        "sender": {"domain": "support-corp.com", "display_name": "Microsoft Support"},  # triggers display name spoof (25)
    }
    s_susp = evaluate_rules(suspicious_data)
    assert 20 <= s_susp.total_score < 50
    assert s_susp.verdict == RulesVerdict.SUSPICIOUS

    # 3. High Risk: score >= 50
    high_risk_data = {
        **suspicious_data,
        "subject": "URGENT: Immediate action required regarding account suspension",  # urgency (10) + threat (15) = 25
        "urls": ["http://192.168.1.50/login"],  # url present (2) + insecure (10) + ip host (25) + auth path (15) = capped at 40
        "attachments": [{"filename": "invoice_payment.pdf.exe"}],  # attach (2) + dangerous (30) + double ext (35) + financial (15) = capped at 45
    }
    s_high = evaluate_rules(high_risk_data)
    assert s_high.total_score >= 50
    assert s_high.verdict == RulesVerdict.HIGH_RISK
    assert s_high.total_score <= 100


# ---------------------------------------------------------------------------
# 8. Determinism and Metadata Completeness
# ---------------------------------------------------------------------------

def test_engine_determinism():
    sample_payload = {
        "headers": {"message-id": "<test@bank.com>"},
        "sender": {"domain": "evil.com", "display_name": "PayPal Security"},
        "recipients": {"to": [{"raw": "victim@domain.com"}], "reply_to": [{"domain": "attacker.com"}]},
        "subject": "Urgent Security Notice",
        "body_text": "Please update your password credentials immediately.",
        "body_html": "<p>Update</p>",
        "urls": ["http://10.0.0.1/verify"],
        "attachments": [{"filename": "invoice.docm"}],
    }

    run1 = evaluate_rules(sample_payload)
    run2 = evaluate_rules(sample_payload)

    assert run1.total_score == run2.total_score
    assert run1.verdict == run2.verdict
    assert run1.matched_rules_count == run2.matched_rules_count
    assert run1.category_scores == run2.category_scores
    for r1, r2 in zip(run1.results, run2.results):
        assert r1.rule_id == r2.rule_id
        assert r1.matched == r2.matched
        assert r1.score == r2.score
        assert r1.evidence == r2.evidence


def test_rule_metadata_and_false_positive_contexts():
    from app.rules.registry import rule_registry
    rules = rule_registry.get_all()
    assert len(rules) == 20

    for rule in rules:
        d = rule.definition
        assert d.rule_id.startswith("RULE-")
        assert len(d.name) > 0
        assert len(d.false_positive_context) > 0
        assert d.default_score > 0


# ---------------------------------------------------------------------------
# 9. End-to-End Worker & API Verification
# ---------------------------------------------------------------------------

def test_e2e_worker_evaluates_rules_and_preserves_evidence():
    """Verifies that worker parses, runs rules engine, persists RuleResultRecord,

    and leaves quarantined evidence byte-for-byte unchanged.
    """
    msg = MIMEMultipart()
    msg["From"] = "PayPal Support <service@fake-paypal.com>"
    msg["To"] = "target@corp.com"
    msg["Reply-To"] = "harvest@evil-attacker.com"
    msg["Subject"] = "URGENT: Verify your account credentials now"
    msg["Date"] = "Sat, 05 Sep 2026 14:00:00 +0000"
    msg["Message-ID"] = "<msg-e2e-stage3@fake.com>"
    msg.attach(MIMEText("Please login: http://192.168.1.1/login within 24 hours.", "plain", "utf-8"))
    raw_email = msg.as_bytes()

    # 1. Upload
    resp = client.post("/api/upload", files={"file": ("phish.eml", io.BytesIO(raw_email), "message/rfc822")})
    assert resp.status_code == 201
    case_id = resp.json()["case_id"]
    original_hash = resp.json()["sha256"]

    # 2. Quarantined file verification before execution
    qfile = QUARANTINE_DIR / f"{case_id}.eml"
    pre_bytes = qfile.read_bytes()
    assert hashlib.sha256(pre_bytes).hexdigest() == original_hash

    # 3. Process case (runs parser + rules)
    result = process_case(case_id)
    assert result["status"] == "complete"
    assert result["rules_verdict"] in ["SUSPICIOUS", "HIGH_RISK"]
    assert result["total_score"] > 20

    # 4. Quarantined file verification AFTER execution (forensic invariance)
    post_bytes = qfile.read_bytes()
    assert post_bytes == pre_bytes
    assert hashlib.sha256(post_bytes).hexdigest() == original_hash

    # 5. Database verification
    with SessionLocal() as db:
        rule_rec = db.query(RuleResultRecord).filter(RuleResultRecord.case_id == case_id).one_or_none()
        assert rule_rec is not None
        assert rule_rec.rules_engine_version == RULES_ENGINE_VERSION
        assert rule_rec.matched_rules_count > 0
        assert rule_rec.total_rules_evaluated == 20

    # 6. API verification: GET /api/cases/{case_id}/rules
    api_resp = client.get(f"/api/cases/{case_id}/rules")
    assert api_resp.status_code == 200
    rdata = api_resp.json()
    assert rdata["rules_engine_version"] == RULES_ENGINE_VERSION
    assert rdata["total_score"] == rule_rec.total_score
    assert rdata["verdict"] == rule_rec.rules_verdict
    assert len(rdata["results"]) == 20
    assert "url" in rdata["category_scores"]
    assert "sender" in rdata["category_scores"]

