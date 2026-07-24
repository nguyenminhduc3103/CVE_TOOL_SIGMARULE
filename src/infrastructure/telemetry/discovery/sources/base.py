"""
Base interface for telemetry discovery sources.

Each source implements two-phase discovery:
1. Phase A - Discovery: List candidate sources that might have telemetry
2. Phase B - Verification: Verify actual telemetry artifacts exist
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from src.domain.models.telemetry_discovery import (
    CandidateSource,
    TelemetryArtifact,
)

if TYPE_CHECKING:
    from src.infrastructure.telemetry.discovery.service import DiscoveryContext


class TelemetrySourceBase(ABC):
    """Abstract base class for telemetry discovery sources.

    Two-phase approach:
    - Phase A: Return list of candidate sources
    - Phase B: Return verified telemetry artifacts
    """

    name: str  # Human-readable name
    source_type: str  # Source category

    def __init__(self) -> None:
        self._enabled: bool = True

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value

    @abstractmethod
    async def discover(
        self,
        cve_id: str,
        context: DiscoveryContext,
    ) -> tuple[list[CandidateSource], list[TelemetryArtifact]]:
        """Two-phase discovery.

        Args:
            cve_id: CVE ID to search for
            context: Discovery context with additional info

        Returns:
            Tuple of (candidates, artifacts):
            - candidates: List of candidate sources (Phase A)
            - artifacts: List of verified telemetry artifacts (Phase B)
        """
        ...

    async def health_check(self) -> bool:
        """Check if the source is accessible."""
        return self._enabled

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name} enabled={self._enabled}>"
