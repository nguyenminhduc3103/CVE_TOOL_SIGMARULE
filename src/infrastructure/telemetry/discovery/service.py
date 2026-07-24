"""
Telemetry Discovery Service - Step 1.3

Two-phase approach:
1. Phase A - Discovery: List candidate sources that MIGHT have telemetry
2. Phase B - Verification: Fetch and verify actual telemetry artifacts exist
3. Gate: Only PASS if verified artifacts exist
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

from src.domain.models.telemetry_discovery import (
    AssessmentDecision,
    CandidateSource,
    SourceConfidence,
    TelemetryArtifact,
    TelemetryArtifactType,
    TelemetryDiscovery,
    TelemetryDiscoveryResult,
    TelemetrySourceAssessment,
    TelemetrySourceType,
    VerificationStatus,
)
from src.infrastructure.telemetry.discovery.sources.base import TelemetrySourceBase
from src.infrastructure.telemetry.discovery.sources.poc_extractor import PoCExtractorSource
from src.infrastructure.telemetry.discovery.sources.vendor_advisory import VendorAdvisorySource
from src.infrastructure.telemetry.discovery.sources.public_dataset import PublicDatasetSource
from src.infrastructure.telemetry.discovery.sources.security_writeup import SecurityWriteupSource
from src.infrastructure.telemetry.discovery.sources.github_raw_source import GitHubRawSource
from config.logging import get_logger

if TYPE_CHECKING:
    from config.settings import Settings

logger = get_logger(__name__)


class DiscoveryContext(dict):
    """Context passed to discovery sources."""

    def __init__(
        self,
        cve_id: str,
        poc_references: list[str] | None = None,
        description: str | None = None,
        vendor: str | None = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.cve_id = cve_id
        self.poc_references = poc_references or []
        self.description = description
        self.vendor = vendor

    def get(self, key: str, default=None):
        if hasattr(self, key):
            return getattr(self, key)
        return super().get(key, default)


class TelemetryDiscoveryService:
    """Main service for two-phase telemetry discovery.

    Phase A: Discover candidate sources (might have telemetry)
    Phase B: Verify actual artifacts exist
    Gate: Only PASS if verified artifacts exist
    """

    def __init__(
        self,
        sources: list[TelemetrySourceBase] | None = None,
        max_concurrent: int = 5,
        timeout_per_source: int = 30,
    ) -> None:
        self._sources: list[TelemetrySourceBase] = sources or self._default_sources()
        self._max_concurrent = max_concurrent
        self._timeout_per_source = timeout_per_source

    @staticmethod
    def _default_sources() -> list[TelemetrySourceBase]:
        return [
            PoCExtractorSource(),
            GitHubRawSource(),  # NEW: Search GitHub for raw telemetry files
            VendorAdvisorySource(),
            PublicDatasetSource(),
            SecurityWriteupSource(),
        ]

    @property
    def sources(self) -> list[TelemetrySourceBase]:
        return [s for s in self._sources if s.enabled]

    async def discover(
        self,
        cve_id: str,
        context: DiscoveryContext | None = None,
    ) -> TelemetryDiscoveryResult:
        """Run two-phase telemetry discovery.

        Phase A: Collect candidate sources
        Phase B: Verify actual artifacts exist
        """
        start_time = time.monotonic()
        context = context or DiscoveryContext(cve_id=cve_id)

        # Two-phase discovery
        discovery = TelemetryDiscovery(cve_id=cve_id)
        result = TelemetryDiscoveryResult(discovery=discovery)

        enabled_sources = self.sources
        result.sources_queried = len(enabled_sources)

        if not enabled_sources:
            logger.warning("[Discovery] No enabled sources", cve_id=cve_id)
            return result

        logger.info(
            "[Discovery] Starting two-phase discovery",
            cve_id=cve_id,
            sources=[s.name for s in enabled_sources],
        )

        # Phase A + B: Each source returns both candidates AND verified artifacts
        semaphore = asyncio.Semaphore(self._max_concurrent)

        async def run_source(source: TelemetrySourceBase) -> tuple:
            async with semaphore:
                try:
                    return await asyncio.wait_for(
                        source.discover(cve_id, context),
                        timeout=self._timeout_per_source,
                    )
                except asyncio.TimeoutError:
                    logger.warning("[Discovery] Source timeout", source=source.name, cve_id=cve_id)
                    return [], []
                except Exception as exc:
                    logger.warning("[Discovery] Source error", source=source.name, cve_id=cve_id, error=str(exc))
                    return [], []

        # Execute all sources concurrently
        source_results = await asyncio.gather(*[run_source(s) for s in enabled_sources])

        # Process results
        for source, (candidates, artifacts) in zip(enabled_sources, source_results):
            # Add candidates (Phase A)
            for candidate in candidates:
                discovery.add_candidate(candidate)
                result.sources_with_candidates += 1

            # Add verified artifacts (Phase B)
            for artifact in artifacts:
                discovery.add_verified_artifact(artifact)
                result.sources_verified += 1

        result.duration_ms = int((time.monotonic() - start_time) * 1000)

        logger.info(
            "[Discovery] Completed",
            cve_id=cve_id,
            candidates=len(discovery.candidate_sources),
            verified=discovery.get_verified_count(),
            duration_ms=result.duration_ms,
        )

        return result
