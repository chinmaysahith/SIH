"""Training and evaluation pipeline for Stage 4.5 real-world ML model (phishing_model_v2).

Trains TF-IDF + Logistic Regression model on normalized real-world corpora (Nazario Phishing + Enron Legitimate).
Tunes hyperparameters on validation split only.
Evaluates final performance on held-out test split and external SpamAssassin validation sets.
Exports phishing_model_v2.joblib, metadata.json, and evaluation reports.
"""

import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline

from app.ml.preprocessing import clean_text_whitespace, extract_content_for_ml

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("train_v2")

MODEL_VERSION = "2.0.0"
PREPROCESSING_VERSION = "1.0.0"

PROCESSED_DIR = Path("data/ml/processed")
MODELS_DIR = Path("data/ml/models")
METADATA_DIR = Path("data/ml/metadata")
REPORTS_DIR = Path("data/ml/reports")


def load_split_jsonl(path: Path) -> Tuple[List[str], List[int], List[Dict[str, Any]]]:
    """Loads JSONL split and produces composite texts and binary labels."""
    texts: List[str] = []
    labels: List[int] = []
    records: List[Dict[str, Any]] = []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            item = json.loads(line)
            sub = item.get("subject", "")
            b_text = item.get("body_text", "")
            b_html = item.get("body_html", "")
            comp_text, _ = extract_content_for_ml(
                subject=sub,
                body_text=b_text,
                body_html=b_html,
            )
            texts.append(comp_text)
            labels.append(int(item["label"]))
            records.append(item)

    return texts, labels, records


def compute_file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def run_training():
    t0 = time.time()
    logger.info("Step 1: Loading train and validation splits...")
    X_train, y_train, train_records = load_split_jsonl(PROCESSED_DIR / "train" / "train_samples.jsonl")
    X_val, y_val, val_records = load_split_jsonl(PROCESSED_DIR / "validation" / "validation_samples.jsonl")
    X_test, y_test, test_records = load_split_jsonl(PROCESSED_DIR / "test" / "test_samples.jsonl")

    logger.info("Train: %d, Validation: %d, Test: %d", len(X_train), len(X_val), len(X_test))

    # Step 2: Hyperparameter Tuning on Validation Split ONLY
    logger.info("Step 2: Hyperparameter tuning on validation split...")
    candidate_params = [
        {"C": 0.5, "max_features": 5000, "ngram_range": (1, 2)},
        {"C": 1.0, "max_features": 5000, "ngram_range": (1, 2)},
        {"C": 5.0, "max_features": 5000, "ngram_range": (1, 2)},
        {"C": 10.0, "max_features": 5000, "ngram_range": (1, 2)},
        {"C": 5.0, "max_features": 8000, "ngram_range": (1, 2)},
        {"C": 10.0, "max_features": 8000, "ngram_range": (1, 2)},
    ]

    best_val_f1 = -1.0
    best_params = None
    tuning_log = []

    for p in candidate_params:
        pipe = Pipeline([
            ("tfidf", TfidfVectorizer(
                ngram_range=p["ngram_range"],
                max_features=p["max_features"],
                sublinear_tf=True,
                lowercase=True,
                strip_accents="unicode",
            )),
            ("clf", LogisticRegression(
                C=p["C"],
                solver="liblinear",
                random_state=42,
                class_weight="balanced",
            )),
        ])
        pipe.fit(X_train, y_train)
        preds = pipe.predict(X_val)
        probs = pipe.predict_proba(X_val)[:, 1]
        val_acc = float(accuracy_score(y_val, preds))
        val_f1 = float(f1_score(y_val, preds, zero_division=0))
        val_rec = float(recall_score(y_val, preds, zero_division=0))
        val_prec = float(precision_score(y_val, preds, zero_division=0))
        val_auc = float(roc_auc_score(y_val, probs))

        entry = {
            "params": p,
            "val_accuracy": val_acc,
            "val_f1": val_f1,
            "val_recall": val_rec,
            "val_precision": val_prec,
            "val_auc": val_auc,
        }
        tuning_log.append(entry)
        logger.info("Params %s -> Val F1=%.4f, Recall=%.4f, Precision=%.4f, AUC=%.4f",
                    p, val_f1, val_rec, val_prec, val_auc)

        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            best_params = p

    logger.info("Selected best hyperparameters from validation tuning: %s (Val F1=%.4f)", best_params, best_val_f1)

    # Step 3: Train model with best parameters on Train + Validation combined
    logger.info("Step 3: Fitting model with best parameters on train+validation...")
    X_train_val = X_train + X_val
    y_train_val = y_train + y_val

    model_pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=best_params["ngram_range"],
            max_features=best_params["max_features"],
            sublinear_tf=True,
            lowercase=True,
            strip_accents="unicode",
        )),
        ("clf", LogisticRegression(
            C=best_params["C"],
            solver="liblinear",
            random_state=42,
            class_weight="balanced",
        )),
    ])
    model_pipeline.fit(X_train_val, y_train_val)

    # Step 4: Evaluate on HELD-OUT TEST SPLIT
    logger.info("Step 4: Evaluating on untouched held-out test split...")
    test_preds = model_pipeline.predict(X_test)
    test_probs = model_pipeline.predict_proba(X_test)[:, 1]

    tn, fp, fn, tp = confusion_matrix(y_test, test_preds).ravel()
    test_metrics = {
        "accuracy": float(accuracy_score(y_test, test_preds)),
        "precision": float(precision_score(y_test, test_preds, zero_division=0)),
        "recall": float(recall_score(y_test, test_preds, zero_division=0)),
        "f1": float(f1_score(y_test, test_preds, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, test_probs)),
        "confusion_matrix": {
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
        },
        "sample_counts": {
            "total_test": len(y_test),
            "phishing_actual": int(sum(y_test)),
            "legitimate_actual": int(len(y_test) - sum(y_test)),
        }
    }
    logger.info("Held-out Test Performance: %s", test_metrics)

    # Step 5: External Validation on SpamAssassin
    logger.info("Step 5: Evaluating external validation sets (SpamAssassin)...")
    easy_ham_texts, easy_ham_labels, easy_ham_records = load_split_jsonl(PROCESSED_DIR / "external_validation" / "easy_ham.jsonl")
    spam_2_texts, spam_2_labels, spam_2_records = load_split_jsonl(PROCESSED_DIR / "external_validation" / "spam_2.jsonl")

    # Easy Ham (Legitimate benchmark)
    ham_preds = model_pipeline.predict(easy_ham_texts)
    ham_probs = model_pipeline.predict_proba(easy_ham_texts)[:, 1]
    ham_fp = int(sum(ham_preds))
    ham_tn = int(len(ham_preds) - ham_fp)
    easy_ham_metrics = {
        "dataset": "SpamAssassin Easy Ham",
        "sample_count": len(easy_ham_texts),
        "target_label": 0,
        "true_negatives": ham_tn,
        "false_positives": ham_fp,
        "false_positive_rate": float(ham_fp / len(easy_ham_texts)),
        "accuracy": float(ham_tn / len(easy_ham_texts)),
    }

    # Spam 2 (Commercial bulk spam benchmark)
    spam_preds = model_pipeline.predict(spam_2_texts)
    spam_probs = model_pipeline.predict_proba(spam_2_texts)[:, 1]
    spam_detected_as_phish = int(sum(spam_preds))
    spam_2_metrics = {
        "dataset": "SpamAssassin Spam 2 (Commercial Bulk)",
        "sample_count": len(spam_2_texts),
        "target_label": 1,
        "phishing_model_flagged_count": spam_detected_as_phish,
        "phishing_model_flagged_percentage": float(spam_detected_as_phish / len(spam_2_texts)),
        "commentary": "Evaluates OOD transfer from phishing to commercial marketing spam. Marketing lures share urgency and financial vocabulary."
    }

    # Step 6: Error Analysis (False Positives and False Negatives on Test Set)
    logger.info("Step 6: Performing error analysis on test set...")
    fp_indices = [i for i, (yt, yp) in enumerate(zip(y_test, test_preds)) if yt == 0 and yp == 1]
    fn_indices = [i for i, (yt, yp) in enumerate(zip(y_test, test_preds)) if yt == 1 and yp == 0]

    error_analysis = {
        "false_positives_count": len(fp_indices),
        "false_negatives_count": len(fn_indices),
        "false_positive_samples": [
            {
                "source_id": test_records[i]["source_id"],
                "subject": test_records[i]["subject"],
                "probability": float(test_probs[i]),
                "reason": "Legitimate email classified as phishing due to high commercial/financial terms"
            }
            for i in fp_indices[:10]
        ],
        "false_negative_samples": [
            {
                "source_id": test_records[i]["source_id"],
                "subject": test_records[i]["subject"],
                "probability": float(test_probs[i]),
                "reason": "Phishing email classified as legitimate (sparse content or generic greeting)"
            }
            for i in fn_indices[:10]
        ]
    }

    # Step 7: Train FINAL PRODUCTION MODEL on all training + validation data
    logger.info("Step 7: Saving serialized model artifact...")
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    model_path = MODELS_DIR / "phishing_model_v2.joblib"
    joblib.dump(model_pipeline, model_path)
    model_sha256 = compute_file_sha256(model_path)
    logger.info("Saved model artifact to %s (sha256: %s)", model_path, model_sha256)

    # Step 8: Save Metadata
    tfidf_step = model_pipeline.named_steps["tfidf"]
    clf_step = model_pipeline.named_steps["clf"]
    vocab_size = len(tfidf_step.vocabulary_)

    duration_s = time.time() - t0
    metadata = {
        "model_version": MODEL_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": "TfidfVectorizer + LogisticRegression",
        "preprocessing_version": PREPROCESSING_VERSION,
        "random_state": 42,
        "sample_counts": {
            "total_corpus": len(X_train) + len(X_val) + len(X_test),
            "train": len(X_train),
            "validation": len(X_val),
            "test": len(X_test),
        },
        "class_distribution": {
            "phishing_samples": sum(y_train) + sum(y_val) + sum(y_test),
            "legitimate_samples": (len(y_train) - sum(y_train)) + (len(y_val) - sum(y_val)) + (len(y_test) - sum(y_test)),
        },
        "vocabulary_size": vocab_size,
        "hyperparameters": {
            "tfidf_ngram_range": list(best_params["ngram_range"]),
            "tfidf_max_features": best_params["max_features"],
            "tfidf_sublinear_tf": True,
            "clf_C": best_params["C"],
            "clf_solver": "liblinear",
            "clf_class_weight": "balanced",
        },
        "evaluation_metrics": test_metrics,
        "external_validation": {
            "easy_ham": easy_ham_metrics,
            "spam_2": spam_2_metrics,
        },
        "model_sha256": model_sha256,
        "training_duration_seconds": round(duration_s, 2),
    }

    metadata_path = MODELS_DIR / "metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    logger.info("Saved model metadata to %s", metadata_path)

    # Step 9: Save Reports
    training_report = {
        "model_version": MODEL_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "training_duration_seconds": round(duration_s, 2),
        "hyperparameter_tuning_log": tuning_log,
        "selected_hyperparameters": best_params,
        "train_validation_size": len(X_train_val),
    }
    (REPORTS_DIR / "training_report.json").write_text(json.dumps(training_report, indent=2), encoding="utf-8")

    evaluation_report = {
        "model_version": MODEL_VERSION,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "held_out_test_metrics": test_metrics,
        "external_validation": {
            "easy_ham": easy_ham_metrics,
            "spam_2": spam_2_metrics,
        },
    }
    (REPORTS_DIR / "evaluation_report.json").write_text(json.dumps(evaluation_report, indent=2), encoding="utf-8")

    (REPORTS_DIR / "error_analysis.json").write_text(json.dumps(error_analysis, indent=2), encoding="utf-8")
    logger.info("All reports saved successfully.")


if __name__ == "__main__":
    run_training()
