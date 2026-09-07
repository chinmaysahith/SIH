"""Comprehensive test suite for Stage 4 — ML Engine.

Verifies:
1. Training pipeline: reproducible split, leakage prevention, metadata generation.
2. Preprocessing: HTML stripping, whitespace normalization, text sufficiency.
3. Inference determinism: identical inputs yield identical probabilities.
4. Standardization: prediction labels, threshold mapping, confidence levels.
5. Explainability: feature contributions with directionality and weights.
6. Edge cases: insufficient text, missing model file, error recovery.
7. Independence invariant: zero reliance on rules engine scores or verdicts.
8. Database persistence: MLResultRecord storage and retrieval.
9. REST API: GET /api/cases/{case_id}/ml endpoint behavior.
10. Worker pipeline: process_case end-to-end execution and evidence immutability.
"""

import hashlib
import json
import tempfile
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import joblib
import pytest
from fastapi.testclient import TestClient

from app.config import QUARANTINE_DIR
from app.db.database import SessionLocal, init_db
from app.db.models import Case, MLResultRecord, ParsedData, RuleResultRecord
from app.jobs.process_case import process_case
from app.main import app
from app.ml.models import (
    MLConfidenceEnum,
    MLFeatureContribution,
    MLModelStatusEnum,
    MLPredictionEnum,
    MLResult,
)
from app.ml.predictor import (
    ML_MODEL_VERSION,
    MLPredictor,
    calculate_prediction_and_confidence,
    get_ml_predictor,
    predict_email,
)
from app.ml.preprocessing import (
    PREPROCESSING_VERSION,
    clean_text_whitespace,
    extract_content_for_ml,
    extract_visible_html_text,
)
from app.parser.models import ParsedEmail, HeaderAddress
from ml_training.train import DEFAULT_DATA_PATH, load_dataset, train_model

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_environment():
    """Ensures test database tables exist before each test."""
    init_db()
    yield


# =====================================================================
# 1. Training & Dataset Pipeline Tests
# =====================================================================

def test_training_fixture_dataset_exists_and_balanced():
    """Verifies that the training fixture exists, parses, and has balanced classes."""
    assert DEFAULT_DATA_PATH.exists(), f"Dataset fixture missing at {DEFAULT_DATA_PATH}"
    texts, labels = load_dataset(DEFAULT_DATA_PATH)
    assert len(texts) >= 40
    assert len(labels) == len(texts)

    phishing_count = sum(labels)
    legit_count = len(labels) - phishing_count
    assert phishing_count > 0
    assert legit_count > 0
    # Balanced within 10%
    assert abs(phishing_count - legit_count) <= 5


def test_train_model_generates_artifact_and_metadata():
    """Verifies that train_model outputs a working pipeline and metadata without leakage."""
    texts, labels = load_dataset(DEFAULT_DATA_PATH)
    with tempfile.TemporaryDirectory() as tmp_dir:
        out_dir = Path(tmp_dir)
        metrics = train_model(texts, labels, output_dir=out_dir, test_size=0.25, random_state=42)

        # Assert metrics calculated on held-out split
        assert "accuracy" in metrics
        assert "f1" in metrics
        assert metrics["accuracy"] >= 0.80

        # Assert files created
        model_file = out_dir / "phishing_model_v1.joblib"
        metadata_file = out_dir / "metadata.json"
        assert model_file.exists()
        assert metadata_file.exists()

        # Check metadata content
        with open(metadata_file, "r", encoding="utf-8") as f:
            meta = json.load(f)
        assert meta["model_version"] == "1.0.0"
        assert meta["preprocessing_version"] == "1.0.0"
        assert meta["vocabulary_size"] > 500

        # Check deserialization of trained pipeline
        pipeline = joblib.load(model_file)
        test_pred = pipeline.predict(["SUBJECT:\nUrgent verify\n\nBODY:\nClick here to verify password"])
        assert len(test_pred) == 1


# =====================================================================
# 2. Preprocessing & HTML Stripping Tests
# =====================================================================

def test_extract_visible_html_text_removes_scripts_and_tags():
    """Verifies HTML text extraction strips dangerous scripts and formatting tags."""
    raw_html = """
    <html>
        <head><title>Test Email</title><style>.hidden { display:none; }</style></head>
        <body>
            <script>alert('malicious')</script>
            <h1>Security Alert</h1>
            <p>Please update your credentials <a href="http://evil.com">here</a>.</p>
        </body>
    </html>
    """
    clean_text = extract_visible_html_text(raw_html)
    assert "malicious" not in clean_text
    assert "alert('malicious')" not in clean_text
    assert "Security Alert" in clean_text
    assert "update your credentials" in clean_text
    assert "here" in clean_text


def test_clean_text_whitespace_normalizes():
    """Verifies multiple newlines and spaces are collapsed."""
    raw = "  Hello   \n\n\t world!   This   is   a test.  "
    res = clean_text_whitespace(raw)
    assert res == "Hello world! This is a test."


def test_extract_content_for_ml_with_plain_body():
    """Verifies composite formatting when plain body text is present."""
    comp, is_suff = extract_content_for_ml(
        subject="Important Notice",
        body_text="Your account billing was updated.",
        body_html=None,
    )
    assert is_suff is True
    assert comp == "SUBJECT:\nImportant Notice\n\nBODY:\nYour account billing was updated."


def test_extract_content_for_ml_fallback_to_html():
    """Verifies fallback to HTML visible text when body_text is missing."""
    comp, is_suff = extract_content_for_ml(
        subject="HTML Notice",
        body_text="",
        body_html="<p>This is extracted from HTML visible text.</p>",
    )
    assert is_suff is True
    assert "HTML visible text" in comp


def test_extract_content_for_ml_insufficient_length():
    """Verifies insufficient text flag when content length is below threshold."""
    comp, is_suff = extract_content_for_ml(
        subject="Hi",
        body_text="ok",
    )
    assert is_suff is False


# =====================================================================
# 3. Standardized Threshold & Confidence Tests
# =====================================================================

@pytest.mark.parametrize(
    "prob,expected_pred,expected_conf",
    [
        (0.10, MLPredictionEnum.LEGITIMATE, MLConfidenceEnum.HIGH),
        (0.25, MLPredictionEnum.LEGITIMATE, MLConfidenceEnum.MEDIUM),
        (0.29, MLPredictionEnum.LEGITIMATE, MLConfidenceEnum.MEDIUM),
        (0.30, MLPredictionEnum.UNCERTAIN, MLConfidenceEnum.MEDIUM),
        (0.50, MLPredictionEnum.UNCERTAIN, MLConfidenceEnum.LOW),
        (0.60, MLPredictionEnum.UNCERTAIN, MLConfidenceEnum.LOW),
        (0.70, MLPredictionEnum.UNCERTAIN, MLConfidenceEnum.MEDIUM),
        (0.71, MLPredictionEnum.PHISHING, MLConfidenceEnum.MEDIUM),
        (0.86, MLPredictionEnum.PHISHING, MLConfidenceEnum.HIGH),
        (0.99, MLPredictionEnum.PHISHING, MLConfidenceEnum.HIGH),
    ],
)
def test_calculate_prediction_and_confidence(prob, expected_pred, expected_conf):
    """Verifies strict threshold mapping and confidence calculations."""
    pred, conf = calculate_prediction_and_confidence(prob)
    assert pred == expected_pred
    assert conf == expected_conf


# =====================================================================
# 4. Inference & Determinism Tests
# =====================================================================

def test_inference_determinism():
    """Verifies identical email content produces bit-for-bit identical probabilities."""
    subject = "Action Required: Verify corporate credentials"
    body = "Dear employee, please verify your credentials at http://corp-login.xyz immediately."

    res1 = predict_email(subject=subject, body_text=body)
    res2 = predict_email(subject=subject, body_text=body)

    assert res1.phishing_probability == res2.phishing_probability
    assert res1.prediction == res2.prediction
    assert res1.confidence == res2.confidence
    assert [f.token for f in res1.top_features] == [f.token for f in res2.top_features]


def test_inference_phishing_sample():
    """Verifies clear phishing indicators produce PHISHING prediction."""
    subject = "URGENT: Your account has been suspended"
    body = "Dear Customer, your bank account access has been suspended due to suspicious activity. Please verify your credentials immediately at http://secure-bank-login.com/verify to prevent permanent closure."

    res = predict_email(subject=subject, body_text=body)
    assert res.prediction == MLPredictionEnum.PHISHING
    assert res.phishing_probability > 0.70
    assert res.model_status == MLModelStatusEnum.READY


def test_inference_legitimate_sample():
    """Verifies clear legitimate indicators produce LEGITIMATE prediction."""
    subject = "Dentist appointment confirmation for Tuesday at 10:00 AM"
    body = "This is a friendly reminder of your upcoming dental checkup with Dr. Smith on Tuesday, September 8, 2026 at 10:00 AM. Please contact our clinic office to reschedule."

    res = predict_email(subject=subject, body_text=body)
    assert res.prediction == MLPredictionEnum.LEGITIMATE
    assert res.phishing_probability < 0.30
    assert res.model_status == MLModelStatusEnum.READY


# =====================================================================
# 5. Explainability & Feature Contribution Tests
# =====================================================================

def test_explain_features_returns_valid_contributions():
    """Verifies top positive and negative features have proper directions and weights."""
    subject = "URGENT: Update your banking password immediately"
    body = "Your banking access requires password confirmation today."

    res = predict_email(subject=subject, body_text=body)
    assert len(res.top_features) > 0

    # Ensure weights are positive floats
    for feat in res.top_features:
        assert isinstance(feat.token, str)
        assert feat.weight >= 0.0
        assert feat.direction in ("phishing", "legitimate")

    # Tokens like 'password', 'banking', 'urgent', or 'immediately' should contribute towards phishing
    phishing_tokens = [f.token for f in res.top_features if f.direction == "phishing"]
    assert any(t in phishing_tokens for t in ["password", "banking", "urgent", "immediately", "update"])


# =====================================================================
# 6. Edge Cases & Fallback Handling Tests
# =====================================================================

def test_insufficient_text_fallback():
    """Verifies handling when text is shorter than 10 characters."""
    res = predict_email(subject="Hi", body_text="")
    assert res.model_status == MLModelStatusEnum.INSUFFICIENT_TEXT
    assert res.prediction == MLPredictionEnum.UNCERTAIN
    assert res.phishing_probability == 0.5
    assert res.confidence == MLConfidenceEnum.LOW
    assert "Insufficient text" in (res.error_message or "")


def test_missing_model_file_fallback():
    """Verifies handling when model file is not present on disk."""
    missing_predictor = MLPredictor(model_path=Path("data/does_not_exist.joblib"))
    assert not missing_predictor.is_available()

    res = missing_predictor.predict(subject="Important email subject", body_text="Hello team, this is body.")
    assert res.model_status == MLModelStatusEnum.UNAVAILABLE
    assert res.prediction == MLPredictionEnum.UNCERTAIN
    assert res.phishing_probability == 0.5
    assert res.confidence == MLConfidenceEnum.LOW
    assert "Model artifact not found" in (res.error_message or "")


# =====================================================================
# 7. Independence Invariant Tests (Strict Decoupling from Rules)
# =====================================================================

def test_ml_is_independent_of_rules_engine():
    """Verifies ML engine results are 100% decoupled from Rules Engine evaluations.

    ML output must depend ONLY on email content, regardless of rules triggers or verdicts.
    """
    email_text = "Please find the monthly financial performance report attached for review."
    subj = "Monthly Financial Report"

    # Evaluation via standard email
    res1 = predict_email(subject=subj, body_text=email_text)

    # Now create a mock ParsedEmail with identical subject and body
    parsed = ParsedEmail(
        case_id="case-ml-test-indep",
        parser_version="1.0.0",
        parsed_timestamp=datetime.now(timezone.utc),
        headers={"Subject": subj},
        subject=subj,
        body_text=email_text,
        body_html=None,
        urls=[],
        attachments=[],
        parser_status="success",
    )
    res2 = predict_email(parsed_email=parsed)

    # Identical predictions and probabilities
    assert res1.phishing_probability == res2.phishing_probability
    assert res1.prediction == res2.prediction

    # Ensure MLPredictor has no references to rules models or scores
    predictor = get_ml_predictor()
    assert not hasattr(predictor, "rules")
    assert not hasattr(predictor, "verdict")


# =====================================================================
# 8. Database Persistence & API Tests
# =====================================================================

def test_ml_results_table_persistence():
    """Verifies MLResultRecord can be persisted and retrieved from SQLite."""
    case_id = "test-case-ml-db-1"
    with SessionLocal() as db:
        # Create case
        case = Case(
            case_id=case_id,
            original_filename="test.eml",
            stored_path="data/quarantine/test.eml",
            sha256="dummyhash1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            file_size=100,
            file_extension=".eml",
            status="complete",
        )
        db.merge(case)

        # Create ML record
        ml_rec = MLResultRecord(
            case_id=case_id,
            model_version=ML_MODEL_VERSION,
            preprocessing_version=PREPROCESSING_VERSION,
            prediction_timestamp=datetime.now(timezone.utc),
            prediction="PHISHING",
            phishing_probability=0.885,
            confidence="HIGH",
            model_status="ready",
            features_json=json.dumps([{"token": "verify", "weight": 0.35, "direction": "phishing"}]),
            error_message=None,
        )
        db.merge(ml_rec)
        db.commit()

    # Query via API
    resp = client.get(f"/api/cases/{case_id}/ml")
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == case_id
    assert data["prediction"] == "PHISHING"
    assert data["phishing_probability"] == 0.885
    assert data["confidence"] == "HIGH"
    assert len(data["top_features"]) == 1
    assert data["top_features"][0]["token"] == "verify"


def test_api_get_case_ml_not_found():
    """Verifies 404 response for nonexistent case or missing ML record."""
    resp = client.get("/api/cases/nonexistent-case-id-12345/ml")
    assert resp.status_code == 404


# =====================================================================
# 9. End-to-End Worker Integration & Forensic Invariant Tests
# =====================================================================

def test_worker_process_case_end_to_end_with_ml():
    """Verifies worker process_case executes Parser + Rules + ML and preserves evidence."""
    case_id = "test-case-ml-worker-e2e"

    msg = MIMEMultipart()
    msg["From"] = "security-notice@bankofamerica-alert.com"
    msg["To"] = "victim@example.com"
    msg["Subject"] = "URGENT: Your account has been suspended"
    msg["Message-ID"] = "<msg-worker-ml-test@test.local>"
    msg.attach(
        MIMEText(
            "Dear Customer, your bank account access has been suspended due to suspicious activity. "
            "Please verify your credentials immediately at http://secure-bank-login.com/verify to prevent closure.",
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
            original_filename="phishing_test.eml",
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
    assert result["rules_verdict"] in ("SUSPICIOUS", "HIGH_RISK")
    assert result["ml_prediction"] == "PHISHING"
    assert result["phishing_probability"] > 0.70

    # FORENSIC INVARIANT: verify file untouched
    with open(stored_path, "rb") as f:
        post_bytes = f.read()
    assert hashlib.sha256(post_bytes).hexdigest() == expected_hash

    # Verify ML record persisted
    with SessionLocal() as db:
        ml_record = db.query(MLResultRecord).filter(MLResultRecord.case_id == case_id).one_or_none()
        assert ml_record is not None
        assert ml_record.prediction == "PHISHING"
        assert ml_record.phishing_probability > 0.70
        assert ml_record.confidence in ("MEDIUM", "HIGH")
        assert ml_record.model_status == "ready"

    # Verify API returns ML results
    resp = client.get(f"/api/cases/{case_id}/ml")
    assert resp.status_code == 200
    data = resp.json()
    assert data["prediction"] == "PHISHING"
    assert data["phishing_probability"] > 0.70
    assert len(data["top_features"]) > 0
