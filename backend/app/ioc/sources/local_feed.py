"""Local file-based threat intelligence feed adapter for Stage 5 — IOC Analysis.

Loads, validates, hashes, and queries a controlled local indicator feed without any
external network access.
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from app.config import IOC_FEED_PATH
from app.ioc.models import IOCIndicator, IOCSourceResult, IOCStatus, IOCType
from app.ioc.normalizer import (
    normalize_domain,
    normalize_ipv4,
    normalize_sha256,
    normalize_url,
)

logger = logging.getLogger("email_forensics.ioc.local_feed")


class LocalFeedAdapter:
    """Offline adapter querying a local JSON threat intelligence feed."""

    def __init__(self, feed_path: Optional[Path] = None):
        self.feed_path = Path(feed_path or IOC_FEED_PATH).resolve()
        self.name = "local-dev-feed"
        self.version = "unknown"
        self.sha256: Optional[str] = None
        self._indicators: Dict[Tuple[IOCType, str], Dict[str, Any]] = {}
        self._load_error: Optional[str] = None
        self._load_and_validate()

    def _load_and_validate(self) -> None:
        """Loads and strictly validates feed schema and indicator integrity."""
        if not self.feed_path.exists() or not self.feed_path.is_file():
            self._load_error = f"IOC intelligence feed not found at {self.feed_path}"
            logger.warning(self._load_error)
            return

        try:
            with open(self.feed_path, "rb") as f:
                raw_bytes = f.read()

            self.sha256 = hashlib.sha256(raw_bytes).hexdigest()
            data = json.loads(raw_bytes.decode("utf-8"))

            # Validate top-level schema
            if not isinstance(data, dict):
                raise ValueError("IOC feed root must be a JSON object")

            feed_ver = data.get("feed_version")
            if not feed_ver or not isinstance(feed_ver, str) or not feed_ver.strip():
                raise ValueError("IOC feed missing required 'feed_version' string")
            self.version = feed_ver.strip()

            raw_indicators = data.get("indicators")
            if not isinstance(raw_indicators, list):
                raise ValueError("IOC feed 'indicators' must be a list")

            # Validate each indicator record
            indicators_map: Dict[Tuple[IOCType, str], Dict[str, Any]] = {}
            for idx, item in enumerate(raw_indicators):
                if not isinstance(item, dict):
                    raise ValueError(f"Indicator at index {idx} must be a JSON object")

                raw_type = item.get("type")
                raw_val = item.get("value")
                raw_status = item.get("status")
                raw_conf = item.get("confidence")
                raw_source = item.get("source")
                raw_reason = item.get("reason")

                # Validate required presence
                if not raw_type or not raw_val or not raw_status or raw_conf is None or not raw_source or not raw_reason:
                    raise ValueError(
                        f"Indicator at index {idx} missing required fields (type, value, status, confidence, source, reason)"
                    )

                # Validate type
                try:
                    ioc_type = IOCType(raw_type.strip().upper())
                except ValueError:
                    raise ValueError(f"Indicator at index {idx} has invalid type '{raw_type}'")

                # Validate status
                try:
                    status_enum = IOCStatus(raw_status.strip().lower())
                except ValueError:
                    raise ValueError(f"Indicator at index {idx} has invalid status '{raw_status}'")

                # Validate confidence
                if not isinstance(raw_conf, int) or raw_conf < 0 or raw_conf > 100:
                    raise ValueError(f"Indicator at index {idx} confidence must be an integer between 0 and 100")

                # Validate and normalize value based on type
                norm_val: Optional[str] = None
                if ioc_type == IOCType.SHA256:
                    norm_val = normalize_sha256(raw_val)
                elif ioc_type == IOCType.IP:
                    norm_val = normalize_ipv4(raw_val)
                elif ioc_type == IOCType.DOMAIN:
                    norm_val = normalize_domain(raw_val)
                elif ioc_type == IOCType.URL:
                    norm_val = normalize_url(raw_val)

                if not norm_val:
                    raise ValueError(f"Indicator at index {idx} ({ioc_type.value}) contains invalid value '{raw_val}'")

                key = (ioc_type, norm_val)
                indicators_map[key] = {
                    "type": ioc_type,
                    "normalized_value": norm_val,
                    "status": status_enum,
                    "confidence": raw_conf,
                    "source": str(raw_source).strip(),
                    "reason": str(raw_reason).strip(),
                }

            self._indicators = indicators_map
            self._load_error = None
            logger.info(
                "Successfully loaded IOC feed %s (v%s, sha256=%s, %d indicators)",
                self.feed_path.name,
                self.version,
                self.sha256[:12] if self.sha256 else "",
                len(self._indicators),
            )
        except Exception as exc:
            self._load_error = f"Failed to load/validate IOC feed: {str(exc)}"
            logger.exception("IOC feed loading error from %s", self.feed_path)
            raise ValueError(self._load_error) from exc

    def is_available(self) -> bool:
        """Returns True if the feed was successfully loaded and is ready for queries."""
        return self._load_error is None and len(self._indicators) > 0

    def lookup(self, indicator: IOCIndicator) -> IOCSourceResult:
        """Queries the local feed for the given indicator.

        CRITICAL FORENSIC SEMANTICS:
        If an indicator is not found in the feed, status is NOT_FOUND, NEVER KNOWN_BENIGN.
        """
        now = datetime.now(timezone.utc)

        if not self.is_available():
            return IOCSourceResult(
                matched=False,
                status=IOCStatus.ERROR,
                confidence=0,
                source=self.name,
                reason="Threat intelligence source unavailable",
                feed_version=self.version,
                feed_sha256=self.sha256,
                lookup_timestamp=now,
                error_message=self._load_error or "Feed not loaded",
            )

        key = (indicator.ioc_type, indicator.normalized_value)
        match = self._indicators.get(key)

        if match:
            return IOCSourceResult(
                matched=True,
                status=match["status"],
                confidence=match["confidence"],
                source=match["source"],
                reason=match["reason"],
                feed_version=self.version,
                feed_sha256=self.sha256,
                lookup_timestamp=now,
                error_message=None,
            )
        else:
            return IOCSourceResult(
                matched=False,
                status=IOCStatus.NOT_FOUND,
                confidence=0,
                source=self.name,
                reason="Indicator not present in local threat intelligence feed",
                feed_version=self.version,
                feed_sha256=self.sha256,
                lookup_timestamp=now,
                error_message=None,
            )
