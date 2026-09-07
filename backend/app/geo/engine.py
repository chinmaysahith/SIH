from datetime import datetime, timezone
import logging
from typing import Optional

from app.config import GEO_ANALYSIS_VERSION
from app.parser.models import ParsedEmail
from app.geo.models import GeoOriginResult, OriginConfidence
from app.geo.received_parser import parse_received_headers
from app.geo.origin import select_origin_ip
from app.geo.providers import GeoIPProvider, NetworkIntelProvider, LocalGeoIPProvider, LocalNetworkIntelProvider

logger = logging.getLogger("email_forensics.geo.engine")


class GeoOriginEngine:
    """Stage 6 Geo / Origin Forensics Engine.

    Evaluates email network origin strictly from ParsedEmail.received_headers.
    Does NOT depend on Rules, ML, or IOC results.
    Does NOT make runtime external network calls.
    """

    def __init__(
        self,
        geoip_provider: Optional[GeoIPProvider] = None,
        network_intel_provider: Optional[NetworkIntelProvider] = None,
    ):
        self.geoip_provider = geoip_provider or LocalGeoIPProvider()
        self.network_intel_provider = network_intel_provider or LocalNetworkIntelProvider()

    def analyze(self, email: ParsedEmail) -> GeoOriginResult:
        now_str = datetime.now(timezone.utc).isoformat()

        # 1. Parse Received headers into candidate IPs
        candidates = parse_received_headers(email.received_headers)

        # 2. Select originating candidate IP via earliest_plausible_public_ip heuristic
        selected_ip, method, confidence, limitations = select_origin_ip(candidates)

        # 3. Enrich selected IP if found
        geo_data = None
        network_intel = None
        status = "SUCCESS" if selected_ip else "NO_CANDIDATE"

        if selected_ip:
            geo_data = self.geoip_provider.lookup(selected_ip)
            network_intel = self.network_intel_provider.lookup(selected_ip)

            # Mark selected candidate
            for c in candidates:
                if c.ip == selected_ip:
                    c.is_origin_candidate = True

        return GeoOriginResult(
            case_id=email.case_id,
            analysis_version=GEO_ANALYSIS_VERSION,
            analysis_timestamp=now_str,
            selected_origin_ip=selected_ip,
            selection_method=method,
            confidence=confidence,
            status=status,
            candidate_ips=candidates,
            geo_data=geo_data,
            network_intel=network_intel,
            limitations=limitations,
        )


_default_engine: Optional[GeoOriginEngine] = None


def get_geo_engine() -> GeoOriginEngine:
    global _default_engine
    if _default_engine is None:
        _default_engine = GeoOriginEngine()
    return _default_engine


def evaluate_geo_origin(email: ParsedEmail) -> GeoOriginResult:
    """Main public evaluation entrypoint for Stage 6."""
    return get_geo_engine().analyze(email)
