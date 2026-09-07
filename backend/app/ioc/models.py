"""Data models for Stage 5 — IOC Analysis Engine."""

from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class IOCType(str, Enum):
    URL = "URL"
    DOMAIN = "DOMAIN"
    IP = "IP"
    SHA256 = "SHA256"


class IOCStatus(str, Enum):
    KNOWN_MALICIOUS = "known_malicious"
    KNOWN_SUSPICIOUS = "known_suspicious"
    KNOWN_BENIGN = "known_benign"
    NOT_FOUND = "not_found"
    UNKNOWN = "unknown"
    ERROR = "error"


class IOCIndicator(BaseModel):
    """Represents an extracted indicator before threat intelligence lookup."""
    model_config = ConfigDict(from_attributes=True)

    ioc_id: str
    ioc_type: IOCType
    original_value: str
    normalized_value: str
    source_context: str  # e.g., "email_url", "url_domain", "url_ip", "attachment_hash", "sender_domain", "reply_to_domain"


class IOCSourceResult(BaseModel):
    """Represents the observation returned by a threat intelligence source adapter."""
    model_config = ConfigDict(from_attributes=True)

    matched: bool
    status: IOCStatus
    confidence: int = Field(ge=0, le=100, default=0)
    source: str
    reason: str
    feed_version: str
    feed_sha256: Optional[str] = None
    lookup_timestamp: datetime
    error_message: Optional[str] = None


class IOCResult(BaseModel):
    """Complete IOC analysis result combining indicator metadata and source observation."""
    model_config = ConfigDict(from_attributes=True)

    case_id: str
    ioc_id: str
    ioc_type: IOCType
    original_value: str
    normalized_value: str
    source_context: str
    matched: bool
    status: IOCStatus
    confidence: int = Field(ge=0, le=100, default=0)
    source: str
    reason: str
    feed_version: str
    feed_sha256: Optional[str] = None
    lookup_timestamp: datetime
    error_message: Optional[str] = None


class IOCSummaryCounts(BaseModel):
    """Aggregated counts across all evaluated IOCs for a case."""
    model_config = ConfigDict(from_attributes=True)

    total_iocs: int = 0
    matched_iocs: int = 0
    malicious_iocs: int = 0
    suspicious_iocs: int = 0
    not_found_iocs: int = 0


class IOCSummary(BaseModel):
    """Top-level evaluation summary for a case containing provenance and indicator results."""
    model_config = ConfigDict(from_attributes=True)

    case_id: str
    feed_versions: List[str] = Field(default_factory=list)
    feed_sha256s: List[str] = Field(default_factory=list)
    summary: IOCSummaryCounts
    results: List[IOCResult] = Field(default_factory=list)
