"""Stage 5 — IOC Analysis Engine module."""

from app.ioc.engine import IOCEngine, evaluate_iocs
from app.ioc.extractor import extract_iocs
from app.ioc.models import (
    IOCIndicator,
    IOCResult,
    IOCSourceResult,
    IOCStatus,
    IOCSummary,
    IOCSummaryCounts,
    IOCType,
)
from app.ioc.normalizer import (
    normalize_domain,
    normalize_ipv4,
    normalize_sha256,
    normalize_url,
)
from app.ioc.registry import IOCSourceRegistry, get_ioc_registry
from app.ioc.sources import IOCSource, LocalFeedAdapter

__all__ = [
    "IOCEngine",
    "evaluate_iocs",
    "extract_iocs",
    "IOCIndicator",
    "IOCResult",
    "IOCSourceResult",
    "IOCStatus",
    "IOCSummary",
    "IOCSummaryCounts",
    "IOCType",
    "normalize_domain",
    "normalize_ipv4",
    "normalize_sha256",
    "normalize_url",
    "IOCSourceRegistry",
    "get_ioc_registry",
    "IOCSource",
    "LocalFeedAdapter",
]
