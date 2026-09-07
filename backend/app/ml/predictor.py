"""Inference engine and prediction explanation for Stage 4 — ML Engine.

Loads trained TF-IDF + Logistic Regression model from disk, evaluates email text,
extracts local feature contributions, and maps probabilities to predictions and confidence.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

import joblib
import numpy as np

from app.ml.models import (
    MLConfidenceEnum,
    MLFeatureContribution,
    MLModelStatusEnum,
    MLPredictionEnum,
    MLResult,
)
from app.ml.preprocessing import (
    PREPROCESSING_VERSION,
    extract_content_for_ml,
)
from app.parser.models import ParsedEmail

logger = logging.getLogger("email_forensics.ml")

ML_MODEL_VERSION = "2.0.0"
MODEL_V2_PATH = Path(__file__).resolve().parent.parent.parent.parent / "data" / "ml" / "models" / "phishing_model_v2.joblib"
MODEL_V1_PATH = Path(__file__).resolve().parent.parent.parent.parent / "data" / "ml_model" / "phishing_model_v1.joblib"
DEFAULT_MODEL_PATH = MODEL_V2_PATH if MODEL_V2_PATH.exists() else MODEL_V1_PATH


def calculate_prediction_and_confidence(
    prob: float,
) -> Tuple[MLPredictionEnum, MLConfidenceEnum]:
    """Applies standardized thresholds to derive prediction label and confidence rating."""
    # Prediction thresholds
    if prob < 0.30:
        prediction = MLPredictionEnum.LEGITIMATE
    elif prob > 0.70:
        prediction = MLPredictionEnum.PHISHING
    else:
        prediction = MLPredictionEnum.UNCERTAIN

    # Confidence rating based on divergence from 0.5 decision boundary
    distance = abs(prob - 0.5)
    if distance >= 0.35:
        confidence = MLConfidenceEnum.HIGH
    elif distance >= 0.15:
        confidence = MLConfidenceEnum.MEDIUM
    else:
        confidence = MLConfidenceEnum.LOW

    return prediction, confidence


class MLPredictor:
    """Thread-safe singleton predictor for offline phishing detection."""

    _instance: Optional["MLPredictor"] = None

    def __init__(self, model_path: Optional[Path] = None):
        if model_path is not None:
            self.model_path = model_path
        elif MODEL_V2_PATH.exists():
            self.model_path = MODEL_V2_PATH
        else:
            self.model_path = MODEL_V1_PATH

        self.model_version = "2.0.0" if "v2" in self.model_path.name else "1.0.0"
        self._pipeline = None
        self._load_error: Optional[str] = None
        self._load_model()

    def _load_model(self) -> None:
        """Attempts to load the joblib model artifact into memory."""
        if not self.model_path.exists():
            self._load_error = f"Model artifact not found at {self.model_path}"
            logger.warning(self._load_error)
            self._pipeline = None
            return

        try:
            self._pipeline = joblib.load(self.model_path)
            self._load_error = None
            logger.info("Loaded ML model v%s from %s", self.model_version, self.model_path)
        except Exception as exc:
            self._load_error = f"Failed to deserialize model artifact: {str(exc)}"
            logger.exception("Failed to load model from %s", self.model_path)
            self._pipeline = None

    def is_available(self) -> bool:
        """Returns True if model pipeline is loaded and ready for inference."""
        return self._pipeline is not None

    def explain_features(
        self,
        composite_text: str,
        top_k: int = 5,
    ) -> List[MLFeatureContribution]:
        """Calculates local feature contributions (w_i * x_i) for the given input text."""
        if not self.is_available():
            return []

        try:
            tfidf = self._pipeline.named_steps["tfidf"]
            clf = self._pipeline.named_steps["clf"]

            # Transform text to sparse tf-idf vector
            tfidf_vector = tfidf.transform([composite_text])
            feature_names = tfidf.get_feature_names_out()

            # Coefficients for class 1 (phishing)
            coefs = clf.coef_[0]

            # Multiply token weights by classifier coefficients
            # Sparse matrix row iteration
            coo = tfidf_vector.tocoo()
            contributions: List[Tuple[str, float]] = []
            for col_idx, value in zip(coo.col, coo.data):
                weight = float(coefs[col_idx] * value)
                contributions.append((str(feature_names[col_idx]), weight))

            # Separate positive (phishing) and negative (legitimate) contributions
            positives = sorted(
                [c for c in contributions if c[1] > 0],
                key=lambda x: x[1],
                reverse=True,
            )[:top_k]

            negatives = sorted(
                [c for c in contributions if c[1] < 0],
                key=lambda x: x[1],
            )[:top_k]

            results: List[MLFeatureContribution] = []
            for token, weight in positives:
                results.append(
                    MLFeatureContribution(
                        token=token,
                        weight=round(weight, 4),
                        direction="phishing",
                    )
                )

            for token, weight in negatives:
                results.append(
                    MLFeatureContribution(
                        token=token,
                        weight=round(abs(weight), 4),
                        direction="legitimate",
                    )
                )

            return results
        except Exception as exc:
            logger.warning("Feature explanation failed: %s", exc)
            return []

    def predict(
        self,
        parsed_email: Optional[ParsedEmail] = None,
        subject: Optional[str] = None,
        body_text: Optional[str] = None,
        body_html: Optional[str] = None,
    ) -> MLResult:
        """Evaluates email content and produces an MLResult signal."""
        now = datetime.now(timezone.utc)

        # 1. Check model availability
        if not self.is_available():
            return MLResult(
                model_version=self.model_version,
                preprocessing_version=PREPROCESSING_VERSION,
                prediction_timestamp=now,
                prediction=MLPredictionEnum.UNCERTAIN,
                phishing_probability=0.5,
                confidence=MLConfidenceEnum.LOW,
                model_status=MLModelStatusEnum.UNAVAILABLE,
                top_features=[],
                error_message=self._load_error or "ML model artifact is unavailable",
            )

        # 2. Extract and validate text content
        composite_text, is_sufficient = extract_content_for_ml(
            parsed_email=parsed_email,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
        )

        if not is_sufficient:
            return MLResult(
                model_version=self.model_version,
                preprocessing_version=PREPROCESSING_VERSION,
                prediction_timestamp=now,
                prediction=MLPredictionEnum.UNCERTAIN,
                phishing_probability=0.5,
                confidence=MLConfidenceEnum.LOW,
                model_status=MLModelStatusEnum.INSUFFICIENT_TEXT,
                top_features=[],
                error_message="Insufficient text content for ML evaluation",
            )

        # 3. Perform inference
        try:
            proba = self._pipeline.predict_proba([composite_text])[0]
            # Class 1 is phishing
            phishing_prob = float(proba[1])
            phishing_prob = max(0.0, min(1.0, phishing_prob))

            prediction, confidence = calculate_prediction_and_confidence(phishing_prob)
            top_features = self.explain_features(composite_text)

            return MLResult(
                model_version=self.model_version,
                preprocessing_version=PREPROCESSING_VERSION,
                prediction_timestamp=now,
                prediction=prediction,
                phishing_probability=round(phishing_prob, 4),
                confidence=confidence,
                model_status=MLModelStatusEnum.READY,
                top_features=top_features,
                error_message=None,
            )
        except Exception as exc:
            logger.exception("Inference failed during predict: %s", exc)
            return MLResult(
                model_version=self.model_version,
                preprocessing_version=PREPROCESSING_VERSION,
                prediction_timestamp=now,
                prediction=MLPredictionEnum.UNCERTAIN,
                phishing_probability=0.5,
                confidence=MLConfidenceEnum.LOW,
                model_status=MLModelStatusEnum.ERROR,
                top_features=[],
                error_message=f"ML inference failure: {str(exc)}",
            )


# Default singleton instance
_default_predictor: Optional[MLPredictor] = None


def get_ml_predictor(model_path: Optional[Path] = None) -> MLPredictor:
    """Returns the singleton MLPredictor instance."""
    global _default_predictor
    if model_path is not None:
        return MLPredictor(model_path=model_path)
    if _default_predictor is None:
        _default_predictor = MLPredictor()
    return _default_predictor


def predict_email(
    parsed_email: Optional[ParsedEmail] = None,
    subject: Optional[str] = None,
    body_text: Optional[str] = None,
    body_html: Optional[str] = None,
) -> MLResult:
    """Convenience function to evaluate an email using the default predictor."""
    predictor = get_ml_predictor()
    return predictor.predict(
        parsed_email=parsed_email,
        subject=subject,
        body_text=body_text,
        body_html=body_html,
    )
