"""Registry of active IOC threat intelligence source adapters."""

from typing import List, Optional
from app.ioc.sources.base import IOCSource
from app.ioc.sources.local_feed import LocalFeedAdapter


class IOCSourceRegistry:
    """Registry maintaining active threat intelligence source adapters."""

    def __init__(self):
        self._sources: List[IOCSource] = []

    def register(self, source: IOCSource) -> None:
        """Registers a new threat intelligence source adapter."""
        self._sources.append(source)

    def get_sources(self) -> List[IOCSource]:
        """Returns all registered source adapters."""
        return list(self._sources)

    def clear(self) -> None:
        """Clears registered sources (used in testing)."""
        self._sources.clear()


# Default global registry initialized with LocalFeedAdapter
_default_registry: Optional[IOCSourceRegistry] = None


def get_ioc_registry() -> IOCSourceRegistry:
    """Returns the singleton IOCSourceRegistry instance."""
    global _default_registry
    if _default_registry is None:
        _default_registry = IOCSourceRegistry()
        _default_registry.register(LocalFeedAdapter())
    return _default_registry
