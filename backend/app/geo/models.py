from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class IPClassification(str, Enum):
    PRIVATE = "PRIVATE"
    LOOPBACK = "LOOPBACK"
    LINK_LOCAL = "LINK_LOCAL"
    MULTICAST = "MULTICAST"
    RESERVED = "RESERVED"
    DOCUMENTATION = "DOCUMENTATION"
    GLOBAL = "GLOBAL"
    INVALID = "INVALID"


class OriginConfidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class CandidateIP(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ip: str
    ip_version: int  # 4 or 6
    classification: IPClassification
    hop_index: int  # 0 is closest to client / earliest in chain
    raw_header_snippet: str
    reverse_dns_hint: Optional[str] = None
    is_origin_candidate: bool = False


class GeoIPRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ip: str
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    accuracy_radius_km: Optional[int] = None
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    database_version: Optional[str] = None
    database_sha256: Optional[str] = None


class NetworkIntelligenceRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ip: str
    is_tor_exit: Optional[bool] = None
    is_vpn: Optional[bool] = None
    is_proxy: Optional[bool] = None
    is_datacenter_hosting: Optional[bool] = None
    provider_name: Optional[str] = None
    source: Optional[str] = None
    feed_version: Optional[str] = None
    feed_sha256: Optional[str] = None


class GeoOriginResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    case_id: str
    analysis_version: str = "1.0.0"
    analysis_timestamp: str
    selected_origin_ip: Optional[str] = None
    selection_method: str = "earliest_plausible_public_ip"
    confidence: OriginConfidence = OriginConfidence.UNKNOWN
    status: str = "SUCCESS"  # SUCCESS, NO_CANDIDATE, ERROR

    candidate_ips: List[CandidateIP] = Field(default_factory=list)
    geo_data: Optional[GeoIPRecord] = None
    network_intel: Optional[NetworkIntelligenceRecord] = None
    limitations: List[str] = Field(default_factory=list)

    disclaimer: str = (
        "Forensic Disclaimer: Geolocation and network origin data indicate the approximate "
        "originating routing point or exit infrastructure of the transmission. They do NOT "
        "definitively identify the physical location, identity, or nation-state of the attacker."
    )
    error_message: Optional[str] = None
