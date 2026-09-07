"""Abstract base protocol for IOC threat intelligence sources."""

from typing import Optional, Protocol
from app.ioc.models import IOCIndicator, IOCSourceResult


class IOCSource(Protocol):
    """Protocol that all IOC threat intelligence source adapters must implement."""

    name: str
    version: str
    sha256: Optional[str]

    def lookup(self, indicator: IOCIndicator) -> IOCSourceResult:
        """Evaluates an extracted IOC indicator against the intelligence source."""
        ...
