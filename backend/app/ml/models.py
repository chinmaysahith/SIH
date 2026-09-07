"""Data models for Stage 4 — ML Engine."""

from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class MLPredictionEnum(str, Enum):
    LEGITIMATE = "LEGITIMATE"
    UNCERTAIN = "UNCERTAIN"
    PHISHING = "PHISHING"


class MLConfidenceEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class MLModelStatusEnum(str, Enum):
    READY = "ready"
    INSUFFICIENT_TEXT = "insufficient_text"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class MLFeatureContribution(BaseModel):
    """Represents the contribution of an individual token/ngram to the prediction."""
    token: str
    weight: float
    direction: str  # "phishing" or "legitimate"


class MLResult(BaseModel):
    """Represents the complete result produced by the ML Engine for an email."""
    model_version: str
    preprocessing_version: str
    prediction_timestamp: datetime
    prediction: MLPredictionEnum
    phishing_probability: float
    confidence: MLConfidenceEnum
    model_status: MLModelStatusEnum
    top_features: List[MLFeatureContribution] = Field(default_factory=list)
    error_message: Optional[str] = None
