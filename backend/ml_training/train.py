"""Offline reproducible training pipeline for Stage 4 — ML Engine.

Trains a TF-IDF + Logistic Regression baseline classifier for phishing email detection.
Strictly separates training split from test split to prevent data leakage.
Exports model artifact to data/ml_model/phishing_model_v1.joblib and metadata.json.
"""

import argparse
import csv
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ml_training")

MODEL_VERSION = "1.0.0"
PREPROCESSING_VERSION = "1.0.0"
DEFAULT_DATA_PATH = Path(__file__).parent / "dataset" / "training_fixture.csv"
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "ml_model"


def load_dataset(csv_path: Path) -> Tuple[List[str], List[int]]:
    """Loads CSV dataset and formats input as composite text."""
    if not csv_path.exists():
        raise FileNotFoundError(f"Training dataset fixture not found at {csv_path}")

    texts: List[str] = []
    labels: List[int] = []

    with open(csv_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            lbl_str = row["label"].strip().lower()
            # 1 = phishing, 0 = legitimate
            label = 1 if lbl_str == "phishing" else 0
            subject = row.get("subject", "").strip()
            body = row.get("body", "").strip()
            composite = f"SUBJECT:\n{subject}\n\nBODY:\n{body}"
            texts.append(composite)
            labels.append(label)

    logger.info("Loaded %d examples from %s", len(texts), csv_path)
    return texts, labels


def train_model(
    texts: List[str],
    labels: List[int],
    output_dir: Path,
    test_size: float = 0.25,
    random_state: int = 42,
) -> Dict[str, float]:
    """Fits TF-IDF + LogisticRegression pipeline and evaluates metrics."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Stratified train/test split to prevent leakage
    X_train, X_test, y_train, y_test = train_test_split(
        texts,
        labels,
        test_size=test_size,
        random_state=random_state,
        stratify=labels,
    )
    logger.info("Train samples: %d, Test samples: %d", len(X_train), len(X_test))

    # 2. Build pipeline
    pipeline = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    ngram_range=(1, 2),
                    max_features=5000,
                    sublinear_tf=True,
                    lowercase=True,
                    strip_accents="unicode",
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    C=10.0,
                    solver="liblinear",
                    random_state=random_state,
                ),
            ),
        ]
    )

    # 3. Fit pipeline on training split only
    pipeline.fit(X_train, y_train)

    # 4. Evaluate on test split
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, y_prob)),
    }
    logger.info("Evaluation metrics on held-out test split: %s", metrics)

    # 5. Fit final production model on full dataset for maximum vocabulary & generalization
    # (While logging test split metrics accurately in metadata)
    prod_pipeline = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    ngram_range=(1, 2),
                    max_features=5000,
                    sublinear_tf=True,
                    lowercase=True,
                    strip_accents="unicode",
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    C=10.0,
                    solver="liblinear",
                    random_state=random_state,
                ),
            ),
        ]
    )
    prod_pipeline.fit(texts, labels)

    # 6. Save serialized model
    model_path = output_dir / "phishing_model_v1.joblib"
    joblib.dump(prod_pipeline, model_path)
    logger.info("Saved serialized model artifact to %s", model_path)

    # 7. Extract vocabulary statistics
    vocab_size = len(prod_pipeline.named_steps["tfidf"].vocabulary_)

    # 8. Save metadata
    metadata = {
        "model_version": MODEL_VERSION,
        "preprocessing_version": PREPROCESSING_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": "TfidfVectorizer + LogisticRegression",
        "sample_count": len(texts),
        "vocabulary_size": vocab_size,
        "random_state": random_state,
        "evaluation_metrics": metrics,
        "hyperparameters": {
            "tfidf_ngram_range": [1, 2],
            "tfidf_max_features": 5000,
            "tfidf_sublinear_tf": True,
            "clf_C": 1.0,
            "clf_solver": "liblinear",
        },
    }

    metadata_path = output_dir / "metadata.json"
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    logger.info("Saved model metadata to %s", metadata_path)

    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Train offline ML baseline model")
    parser.add_argument(
        "--data",
        type=Path,
        default=DEFAULT_DATA_PATH,
        help="Path to training CSV file",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory to save model artifact and metadata",
    )
    args = parser.parse_args()

    texts, labels = load_dataset(args.data)
    train_model(texts, labels, args.output_dir)


if __name__ == "__main__":
    main()
