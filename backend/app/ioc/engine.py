"""IOC Analysis Engine orchestrating indicator extraction, source lookup, and aggregation."""

import logging
from typing import List, Optional

from app.ioc.extractor import extract_iocs
from app.ioc.models import (
    IOCResult,
    IOCStatus,
    IOCSummary,
    IOCSummaryCounts,
)
from app.ioc.registry import IOCSourceRegistry, get_ioc_registry
from app.parser.models import ParsedEmail

logger = logging.getLogger("email_forensics.ioc")


class IOCEngine:
    """Orchestrates indicator extraction and evaluation across registered threat sources."""

    def __init__(self, registry: Optional[IOCSourceRegistry] = None):
        self.registry = registry or get_ioc_registry()

    def evaluate(self, parsed_email: ParsedEmail) -> IOCSummary:
        """Evaluates all indicators extracted from ParsedEmail against registered sources."""
        indicators = extract_iocs(parsed_email)
        sources = self.registry.get_sources()

        results: List[IOCResult] = []
        feed_versions_set = set()
        feed_sha256s_set = set()

        for ind in indicators:
            for src in sources:
                try:
                    src_res = src.lookup(ind)
                    if src_res.feed_version:
                        feed_versions_set.add(src_res.feed_version)
                    if src_res.feed_sha256:
                        feed_sha256s_set.add(src_res.feed_sha256)

                    results.append(
                        IOCResult(
                            case_id=parsed_email.case_id,
                            ioc_id=ind.ioc_id,
                            ioc_type=ind.ioc_type,
                            original_value=ind.original_value,
                            normalized_value=ind.normalized_value,
                            source_context=ind.source_context,
                            matched=src_res.matched,
                            status=src_res.status,
                            confidence=src_res.confidence,
                            source=src_res.source,
                            reason=src_res.reason,
                            feed_version=src_res.feed_version,
                            feed_sha256=src_res.feed_sha256,
                            lookup_timestamp=src_res.lookup_timestamp,
                            error_message=src_res.error_message,
                        )
                    )
                except Exception as exc:
                    logger.exception("Source %s failed lookup for %s: %s", src.name, ind.original_value, exc)

        # Compute summary counts
        matched_count = sum(1 for r in results if r.matched)
        malicious_count = sum(1 for r in results if r.status == IOCStatus.KNOWN_MALICIOUS)
        suspicious_count = sum(1 for r in results if r.status == IOCStatus.KNOWN_SUSPICIOUS)
        not_found_count = sum(1 for r in results if r.status == IOCStatus.NOT_FOUND)

        summary_counts = IOCSummaryCounts(
            total_iocs=len(indicators),
            matched_iocs=matched_count,
            malicious_iocs=malicious_count,
            suspicious_iocs=suspicious_count,
            not_found_iocs=not_found_count,
        )

        return IOCSummary(
            case_id=parsed_email.case_id,
            feed_versions=sorted(list(feed_versions_set)),
            feed_sha256s=sorted(list(feed_sha256s_set)),
            summary=summary_counts,
            results=results,
        )


def evaluate_iocs(
    parsed_email: ParsedEmail,
    registry: Optional[IOCSourceRegistry] = None,
) -> IOCSummary:
    """Convenience function to evaluate IOCs for a parsed email using default engine."""
    engine = IOCEngine(registry=registry)
    return engine.evaluate(parsed_email)
