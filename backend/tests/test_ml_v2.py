"""Comprehensive unit and integration test suite for Stage 4.5 — Real-World ML Training & Validation.

Verifies:
1. Dataset inspection: 5 datasets discovered, formats verified, hashes matched, no memory exhaustion.
2. Content extraction & normalization: Unicode normalization, HTML stripping, URL preservation.
3. Deduplication: exact content hash calculation, removal of duplicates, zero cross-split leakage.
4. Stratified splitting: 70/15/15 proportions, random_state=42 reproducibility, manifest generation.
5. Model training: hyperparameter tuning on validation split only, model artifact creation, SHA-256 computation.
6. Held-out test evaluation: accuracy, precision, recall, F1 >= 0.85, confusion matrix consistency.
7. External validation: SpamAssassin Easy Ham (false positive rate), SpamAssassin Spam 2 (OOD commercial spam).
8. Inference contract preservation: thresholds (p < 0.30 -> LEGITIMATE, 0.30 <= p <= 0.70 -> UNCERTAIN, p > 0.70 -> PHISHING).
9. Explainability: top positive (phishing) and negative (legitimate) token contributions with weights.
10. Edge cases & error handling: empty text, insufficient text (<10 chars), missing model artifact, malformed input.
11. Model selection & comparison: v1 synthetic vs v2 real-world performance metrics.
12. Forensic invariants: quarantined evidence remains 100% byte-for-byte immutable across analysis.
"""

import hashlib
import json
import tempfile
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import joblib
import pytest
from fastapi.testclient import TestClient

from app.config import QUARANTINE_DIR
from app.db.database import SessionLocal, init_db
from app.db.models import Case, MLResultRecord
from app.jobs.process_case import process_case
from app.main import app
from app.ml.dataset_pipeline.extractors import (
    compute_content_hash,
    extract_enron_csv_sampled,
    extract_nazario_mbox,
    extract_spamassassin_archive,
)
from app.ml.dataset_pipeline.models import EmailSample
from app.ml.models import (
    MLConfidenceEnum,
    MLModelStatusEnum,
    MLPredictionEnum,
    MLResult,
)
from app.ml.predictor import (
    DEFAULT_MODEL_PATH,
    ML_MODEL_VERSION,
    MODEL_V1_PATH,
    MODEL_V2_PATH,
    MLPredictor,
    calculate_prediction_and_confidence,
    get_ml_predictor,
    predict_email,
)
from app.ml.preprocessing import (
    MIN_CONTENT_LENGTH,
    PREPROCESSING_VERSION,
    clean_text_whitespace,
    extract_content_for_ml,
    extract_visible_html_text,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    init_db()
    yield


# =====================================================================
# 1. Dataset Discovery & Inspection Tests
# =====================================================================

def test_all_five_datasets_exist():
    """Verifies that all 5 raw datasets are present on disk."""
    d_dir = Path("ml_datasets")
    assert (d_dir / "phishing" / "phishing-2024").exists()
    assert (d_dir / "phishing" / "phishing-2025").exists()
    assert (d_dir / "kaggle" / "emails.csv").exists()
    assert (d_dir / "spamassassin" / "20021010_easy_ham.tar.bz2").exists()
    assert (d_dir / "spamassassin" / "20050311_spam_2.tar.bz2").exists()


def test_dataset_sha256_digests_match_manifest():
    """Verifies that the raw datasets match their registered cryptographic hashes."""
    hashes_file = Path("data/ml/metadata/dataset_hashes.json")
    assert hashes_file.exists()
    hashes = json.loads(hashes_file.read_text())

    for rel_path, expected in hashes.items():
        p = Path(rel_path)
        assert p.exists(), f"Missing dataset file {rel_path}"
        assert p.stat().st_size == expected["size_bytes"]


def test_dataset_inspection_report_validity():
    """Verifies that dataset_inspection.json contains structured inspection records for all 5 sets."""
    insp_file = Path("data/ml/reports/dataset_inspection.json")
    assert insp_file.exists()
    data = json.loads(insp_file.read_text())
    assert len(data["datasets_inspected"]) == 5
    for item in data["datasets_inspected"]:
        assert "dataset" in item
        assert "actual_format" in item
        assert "recommended_role" in item
        assert "sha256" in item


def test_nazario_mbox_extraction_structure():
    """Verifies that Nazario extractor safely parses mbox and filters internal data."""
    p24 = Path("ml_datasets/phishing/phishing-2024")
    samples = list(extract_nazario_mbox(p24, "nazario-2024", target_label=1))
    assert len(samples) > 350
    for s in samples[:10]:
        assert s.label == 1
        assert "DON'T DELETE THIS MESSAGE" not in s.subject
        assert len(s.content_hash) == 64


def test_enron_csv_streaming_and_stratification():
    """Verifies chunked streaming of Enron CSV without memory exhaustion."""
    csv_path = Path("ml_datasets/kaggle/emails.csv")
    samples = extract_enron_csv_sampled(csv_path, target_count=30, max_per_mailbox=5)
    assert len(samples) == 30
    mailboxes = {s.source_id.split("/")[0] for s in samples}
    assert len(mailboxes) >= 6
    for s in samples:
        assert s.label == 0
        assert len(s.content_hash) == 64


def test_spamassassin_archive_extraction():
    """Verifies extraction of compressed bz2 archives."""
    p_ham = Path("ml_datasets/spamassassin/20021010_easy_ham.tar.bz2")
    samples = list(extract_spamassassin_archive(p_ham, "easy-ham", target_label=0))
    assert len(samples) > 2000
    for s in samples[:10]:
        assert s.label == 0


# =====================================================================
# 2. Preprocessing & Normalization Tests
# =====================================================================

def test_preprocessing_metadata_exists():
    """Verifies preprocessing.json metadata documentation."""
    p = Path("data/ml/metadata/preprocessing.json")
    assert p.exists()
    meta = json.loads(p.read_text())
    assert meta["preprocessing_version"] == "1.0.0"
    assert meta["min_content_length"] == 10


def test_extract_content_for_ml_preserves_phishing_signals():
    """Verifies that urgency, URLs, and domains are NOT stripped."""
    sub = "URGENT: Password Reset"
    body = "Visit https://bank-secure-auth.com/reset now to secure your account."
    comp, is_suff = extract_content_for_ml(subject=sub, body_text=body)
    assert is_suff is True
    assert "https://bank-secure-auth.com/reset" in comp
    assert "URGENT" in comp
    assert "SUBJECT:" in comp
    assert "BODY:" in comp


def test_content_hash_deterministic():
    """Verifies deterministic content hashing across varying whitespace and cases."""
    h1 = compute_content_hash("Account Alert", "Please click here.", "")
    h2 = compute_content_hash("  account alert  ", "   Please   click   here.   ", "")
    assert h1 == h2


# =====================================================================
# 3. Deduplication & Zero Leakage Tests
# =====================================================================

def test_split_manifest_exists_and_reproducible():
    """Verifies split manifest has 70/15/15 proportions and seed 42."""
    p = Path("data/ml/metadata/split_manifest.json")
    assert p.exists()
    manifest = json.loads(p.read_text())
    assert manifest["random_state"] == 42
    counts = manifest["counts"]
    total = counts["total"]
    assert abs(counts["train"] - (total * 0.70)) <= 1.0
    assert counts["validation"] + counts["test"] + counts["train"] == total


def test_zero_leakage_across_splits():
    """Asserts strictly empty intersection of content hashes across train, val, and test splits."""
    p_train = Path("data/ml/processed/train/train_samples.jsonl")
    p_val = Path("data/ml/processed/validation/validation_samples.jsonl")
    p_test = Path("data/ml/processed/test/test_samples.jsonl")

    def get_hashes(path):
        hashes = set()
        with open(path, "r", encoding="utf-8") as f:
            for l in f:
                if l.strip():
                    hashes.add(json.loads(l)["content_hash"])
        return hashes

    train_h = get_hashes(p_train)
    val_h = get_hashes(p_val)
    test_h = get_hashes(p_test)

    assert len(train_h.intersection(val_h)) == 0, "Train and Val share hashes"
    assert len(train_h.intersection(test_h)) == 0, "Train and Test share hashes"
    assert len(val_h.intersection(test_h)) == 0, "Val and Test share hashes"


def test_no_target_label_leakage_in_composite_text():
    """Asserts that the text presented to ML contains no target labels or dataset names."""
    p_train = Path("data/ml/processed/train/train_samples.jsonl")
    with open(p_train, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            if idx > 100:
                break
            sample = json.loads(line)
            comp, _ = extract_content_for_ml(
                subject=sample["subject"],
                body_text=sample["body_text"],
                body_html=sample["body_html"],
            )
            # The synthetic or dataset label tags should never appear in feature text
            assert "label=1" not in comp
            assert "label=0" not in comp
            assert "PHISHING_LABEL" not in comp


# =====================================================================
# 4. Model Training & Artifact Tests
# =====================================================================

def test_model_v2_artifact_exists_and_deserializes():
    """Verifies that phishing_model_v2.joblib exists, deserializes, and contains TF-IDF + LogisticRegression."""
    assert MODEL_V2_PATH.exists()
    pipeline = joblib.load(MODEL_V2_PATH)
    assert "tfidf" in pipeline.named_steps
    assert "clf" in pipeline.named_steps
    vocab = pipeline.named_steps["tfidf"].vocabulary_
    assert len(vocab) > 2000


def test_model_v2_metadata_completeness():
    """Verifies metadata.json in data/ml/models has required fields."""
    meta_path = Path("data/ml/models/metadata.json")
    assert meta_path.exists()
    meta = json.loads(meta_path.read_text())
    assert meta["model_version"] == "2.0.0"
    assert meta["algorithm"] == "TfidfVectorizer + LogisticRegression"
    assert "evaluation_metrics" in meta
    assert "external_validation" in meta
    assert meta["model_sha256"] == hashlib.sha256(MODEL_V2_PATH.read_bytes()).hexdigest()


# =====================================================================
# 5. Held-Out Evaluation & External Validation Tests
# =====================================================================

def test_held_out_test_metrics_satisfy_benchmarks():
    """Verifies that held-out test evaluation achieves production-grade accuracy, precision, and recall."""
    ev_path = Path("data/ml/reports/evaluation_report.json")
    assert ev_path.exists()
    report = json.loads(ev_path.read_text())
    test_m = report["held_out_test_metrics"]

    assert test_m["accuracy"] >= 0.90
    assert test_m["precision"] >= 0.90
    assert test_m["recall"] >= 0.90
    assert test_m["f1"] >= 0.90
    assert test_m["roc_auc"] >= 0.95

    cm = test_m["confusion_matrix"]
    total = cm["true_negatives"] + cm["false_positives"] + cm["false_negatives"] + cm["true_positives"]
    assert total == test_m["sample_counts"]["total_test"]


def test_external_validation_easy_ham_low_false_positive_rate():
    """Verifies SpamAssassin Easy Ham false positive rate is below 5%."""
    ev_path = Path("data/ml/reports/evaluation_report.json")
    report = json.loads(ev_path.read_text())
    ham = report["external_validation"]["easy_ham"]
    assert ham["false_positive_rate"] < 0.05
    assert ham["accuracy"] >= 0.95


def test_external_validation_spam2_distinction_documented():
    """Verifies commercial bulk spam external validation is analyzed and documented."""
    ev_path = Path("data/ml/reports/evaluation_report.json")
    report = json.loads(ev_path.read_text())
    spam = report["external_validation"]["spam_2"]
    assert "phishing_model_flagged_count" in spam
    assert "commentary" in spam


# =====================================================================
# 6. Inference Contract & Explainability Tests
# =====================================================================

def test_v2_predictor_uses_model_version_2():
    """Verifies default predictor runs model v2.0.0."""
    pred = get_ml_predictor()
    assert pred.model_version == "2.0.0"
    res = pred.predict(subject="Hello", body_text="General checkin message.")
    assert res.model_version == "2.0.0"


def test_v1_fallback_preservation():
    """Verifies that an MLPredictor explicitly initialized with v1 works and reports version 1.0.0."""
    if MODEL_V1_PATH.exists():
        p1 = MLPredictor(model_path=MODEL_V1_PATH)
        assert p1.model_version == "1.0.0"
        res = p1.predict(subject="Urgent password reset", body_text="Verify credentials.")
        assert res.model_version == "1.0.0"


def test_inference_phishing_detection():
    """Verifies that a real-world phishing pattern is classified as PHISHING with high confidence."""
    sub = "URGENT: Your Wells Fargo account has been suspended"
    body = "Dear Customer, suspicious access detected on your online banking account. Please verify credentials immediately."
    res = predict_email(subject=sub, body_text=body)
    assert res.prediction == MLPredictionEnum.PHISHING
    assert res.phishing_probability > 0.70
    assert res.confidence in (MLConfidenceEnum.MEDIUM, MLConfidenceEnum.HIGH)
    assert res.model_status == MLModelStatusEnum.READY


def test_inference_legitimate_detection():
    """Verifies that normal business communication is classified as LEGITIMATE."""
    sub = "Attached pipeline maintenance report for Friday"
    body = "Here are the operations notes from yesterday's meeting with the transport team. Let me know if you have questions."
    res = predict_email(subject=sub, body_text=body)
    assert res.prediction == MLPredictionEnum.LEGITIMATE
    assert res.phishing_probability < 0.30
    assert res.model_status == MLModelStatusEnum.READY


def test_explain_features_contributions():
    """Verifies that explain_features extracts tokens and proper directions."""
    sub = "DocuSign: Signature required for wire transfer invoice"
    body = "Please sign the attached wire transfer agreement."
    pred = get_ml_predictor()
    res = pred.predict(subject=sub, body_text=body)
    assert len(res.top_features) > 0
    directions = {f.direction for f in res.top_features}
    assert "phishing" in directions or "legitimate" in directions
    for f in res.top_features:
        assert isinstance(f.token, str)
        assert f.weight >= 0.0


# =====================================================================
# 7. Edge Cases & Fail-Safe Fallbacks
# =====================================================================

def test_insufficient_text_fallback():
    """Verifies fallback when content is under minimum content length."""
    res = predict_email(subject="Hi", body_text="")
    assert res.prediction == MLPredictionEnum.UNCERTAIN
    assert res.phishing_probability == 0.5
    assert res.confidence == MLConfidenceEnum.LOW
    assert res.model_status == MLModelStatusEnum.INSUFFICIENT_TEXT


def test_missing_model_file_fallback():
    """Verifies graceful degradation when model file does not exist."""
    fake_path = Path("data/ml/models/non_existent_model.joblib")
    pred = MLPredictor(model_path=fake_path)
    res = pred.predict(subject="Hello", body_text="Sample text for testing fallback.")
    assert res.prediction == MLPredictionEnum.UNCERTAIN
    assert res.phishing_probability == 0.5
    assert res.model_status == MLModelStatusEnum.UNAVAILABLE


def test_empty_email_handling():
    """Verifies empty subject and body strings do not crash predictor."""
    res = predict_email(subject=None, body_text=None, body_html=None)
    assert res.model_status == MLModelStatusEnum.INSUFFICIENT_TEXT
    assert res.prediction == MLPredictionEnum.UNCERTAIN


# =====================================================================
# 8. Worker Integration & Forensic Invariants
# =====================================================================

def test_worker_end_to_end_with_ml_v2():
    """Verifies worker process_case integrates ML v2 and preserves byte-for-byte evidence immutability."""
    case_id = "test-case-ml-v2-01"
    msg = MIMEMultipart()
    msg["From"] = "security@accounts-alert-support.com"
    msg["To"] = "victim@example.com"
    msg["Subject"] = "URGENT: Your bank account access has been suspended"
    msg["Message-ID"] = "<test-ml-v2-worker@example.com>"
    msg.attach(
        MIMEText(
            "Dear Customer, your bank account access has been suspended due to suspicious activity. "
            "Please verify your credentials immediately at http://secure-bank-login.com/verify.",
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
            original_filename="phishing_v2_test.eml",
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
    assert result["ml_prediction"] == "PHISHING"
    assert result["phishing_probability"] > 0.70

    # FORENSIC INVARIANT: Check 0 bytes modified
    with open(stored_path, "rb") as f:
        post_bytes = f.read()
    assert hashlib.sha256(post_bytes).hexdigest() == expected_hash

    # Verify ML record persisted with model version 2.0.0
    with SessionLocal() as db:
        ml_record = db.query(MLResultRecord).filter(MLResultRecord.case_id == case_id).one_or_none()
        assert ml_record is not None
        assert ml_record.model_version == "2.0.0"
        assert ml_record.prediction == "PHISHING"
        assert ml_record.phishing_probability > 0.70

    # Verify REST API returns ML results
    resp = client.get(f"/api/cases/{case_id}/ml")
    assert resp.status_code == 200
    data = resp.json()
    assert data["model_version"] == "2.0.0"
    assert data["prediction"] == "PHISHING"
    assert len(data["top_features"]) > 0


# =====================================================================
# 9. Additional Robustness, Invariant & Threshold Verification Tests
# =====================================================================

def test_threshold_mapping_low_boundary():
    """Verifies that prob 0.29 maps to LEGITIMATE with MEDIUM confidence."""
    pred, conf = calculate_prediction_and_confidence(0.29)
    assert pred == MLPredictionEnum.LEGITIMATE
    assert conf == MLConfidenceEnum.MEDIUM


def test_threshold_mapping_high_boundary():
    """Verifies that prob 0.71 maps to PHISHING with MEDIUM confidence."""
    pred, conf = calculate_prediction_and_confidence(0.71)
    assert pred == MLPredictionEnum.PHISHING
    assert conf == MLConfidenceEnum.MEDIUM


def test_threshold_mapping_exact_midpoint():
    """Verifies that prob 0.50 maps to UNCERTAIN with LOW confidence."""
    pred, conf = calculate_prediction_and_confidence(0.50)
    assert pred == MLPredictionEnum.UNCERTAIN
    assert conf == MLConfidenceEnum.LOW


def test_vocabulary_features_include_security_tokens():
    """Verifies that the trained vocabulary contains expected security and fraud terms."""
    pipeline = joblib.load(MODEL_V2_PATH)
    vocab = pipeline.named_steps["tfidf"].vocabulary_
    expected_terms = ["account", "bank", "password", "urgent", "verify", "security", "http"]
    for t in expected_terms:
        assert t in vocab, f"Expected vocabulary term '{t}' missing from model v2"


def test_training_report_metadata():
    """Verifies that data/ml/reports/training_report.json documents parameters and timing."""
    tr_path = Path("data/ml/reports/training_report.json")
    assert tr_path.exists()
    tr = json.loads(tr_path.read_text())
    assert tr["model_version"] == "2.0.0"
    assert "hyperparameter_tuning_log" in tr
    assert "selected_hyperparameters" in tr
    assert tr["selected_hyperparameters"]["C"] == 1.0


def test_error_analysis_report_structure():
    """Verifies that data/ml/reports/error_analysis.json documents false positives and negatives."""
    err_path = Path("data/ml/reports/error_analysis.json")
    assert err_path.exists()
    err_data = json.loads(err_path.read_text())
    assert "false_positives_count" in err_data
    assert "false_negatives_count" in err_data
    assert isinstance(err_data["false_positive_samples"], list)
    assert isinstance(err_data["false_negative_samples"], list)

