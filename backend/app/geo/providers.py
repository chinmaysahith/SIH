import hashlib
import json
import logging
from pathlib import Path
from typing import Optional, Protocol
from app.geo.models import GeoIPRecord, NetworkIntelligenceRecord
from app.config import GEOIP_DATABASE_PATH, NETWORK_INTEL_PATH

logger = logging.getLogger("email_forensics.geo.providers")


def calculate_file_sha256(path: Path) -> Optional[str]:
    if not path.exists() or not path.is_file():
        return None
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


class GeoIPProvider(Protocol):
    def lookup(self, ip: str) -> Optional[GeoIPRecord]:
        ...

    @property
    def version(self) -> str:
        ...

    @property
    def sha256(self) -> Optional[str]:
        ...


class NetworkIntelProvider(Protocol):
    def lookup(self, ip: str) -> Optional[NetworkIntelligenceRecord]:
        ...

    @property
    def version(self) -> str:
        ...

    @property
    def sha256(self) -> Optional[str]:
        ...


class LocalGeoIPProvider:
    """Offline local JSON provider for GeoIP and ASN intelligence."""

    def __init__(self, db_path: Path = GEOIP_DATABASE_PATH):
        self.db_path = db_path
        self._version = "unknown"
        self._records = {}
        self._sha256 = None
        self._load()

    def _load(self):
        if not self.db_path.exists():
            logger.warning("Local GeoIP database not found at %s", self.db_path)
            return

        self._sha256 = calculate_file_sha256(self.db_path)
        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._version = data.get("database_version", "unknown")
            self._records = data.get("records", {})
            logger.info("Loaded GeoIP database v%s (%d records)", self._version, len(self._records))
        except Exception as e:
            logger.error("Failed to load GeoIP database: %s", e)

    @property
    def version(self) -> str:
        return self._version

    @property
    def sha256(self) -> Optional[str]:
        return self._sha256

    def lookup(self, ip: str) -> Optional[GeoIPRecord]:
        clean_ip = ip.strip("[]()")
        entry = self._records.get(clean_ip)
        if not entry:
            return None

        return GeoIPRecord(
            ip=clean_ip,
            country_code=entry.get("country_code"),
            country_name=entry.get("country_name"),
            region=entry.get("region"),
            city=entry.get("city"),
            latitude=entry.get("latitude"),
            longitude=entry.get("longitude"),
            accuracy_radius_km=entry.get("accuracy_radius_km", 50),
            asn=entry.get("asn"),
            asn_org=entry.get("asn_org"),
            database_version=self._version,
            database_sha256=self._sha256,
        )


class LocalNetworkIntelProvider:
    """Offline local JSON provider for Tor exit, VPN, Proxy, and Hosting detection."""

    def __init__(self, feed_path: Path = NETWORK_INTEL_PATH):
        self.feed_path = feed_path
        self._version = "unknown"
        self._records = {}
        self._sha256 = None
        self._load()

    def _load(self):
        if not self.feed_path.exists():
            logger.warning("Local Network Intel feed not found at %s", self.feed_path)
            return

        self._sha256 = calculate_file_sha256(self.feed_path)
        try:
            with open(self.feed_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._version = data.get("feed_version", "unknown")
            self._records = data.get("records", {})
            logger.info("Loaded Network Intel feed v%s (%d records)", self._version, len(self._records))
        except Exception as e:
            logger.error("Failed to load Network Intel feed: %s", e)

    @property
    def version(self) -> str:
        return self._version

    @property
    def sha256(self) -> Optional[str]:
        return self._sha256

    def lookup(self, ip: str) -> Optional[NetworkIntelligenceRecord]:
        clean_ip = ip.strip("[]()")
        entry = self._records.get(clean_ip)
        if not entry:
            # Return unknown record rather than assuming false
            return NetworkIntelligenceRecord(
                ip=clean_ip,
                is_tor_exit=None,
                is_vpn=None,
                is_proxy=None,
                is_datacenter_hosting=None,
                provider_name=None,
                source="unmatched",
                feed_version=self._version,
                feed_sha256=self._sha256,
            )

        return NetworkIntelligenceRecord(
            ip=clean_ip,
            is_tor_exit=entry.get("is_tor_exit"),
            is_vpn=entry.get("is_vpn"),
            is_proxy=entry.get("is_proxy"),
            is_datacenter_hosting=entry.get("is_datacenter_hosting"),
            provider_name=entry.get("provider_name"),
            source=entry.get("source", "local-intel"),
            feed_version=self._version,
            feed_sha256=self._sha256,
        )
