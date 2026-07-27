"""
Stage wrapper for Step 1.3: Telemetry Discovery.

Two-phase discovery:
1. Phase A - Discovery: List candidate sources (might have telemetry)
2. Phase B - Verification: Verify actual telemetry artifacts exist
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from src.domain.models.telemetry_discovery import TelemetryDiscoveryResult
from src.infrastructure.telemetry.discovery.service import (
    DiscoveryContext,
    TelemetryDiscoveryService,
)
from config.logging import get_logger

if TYPE_CHECKING:
    from src.domain.models.triage import TriageContext

logger = get_logger(__name__)

_discovery_service: TelemetryDiscoveryService | None = None


def get_discovery_service() -> TelemetryDiscoveryService:
    global _discovery_service
    if _discovery_service is None:
        _discovery_service = TelemetryDiscoveryService()
    return _discovery_service


def set_discovery_service(service: TelemetryDiscoveryService | None) -> None:
    global _discovery_service
    _discovery_service = service


async def run_telemetry_discovery_stage(
    cve_id: str,
    triage: TriageContext,
    description: str | None = None,
    vendor: str | None = None,
) -> TelemetryDiscoveryResult:
    """Run Step 1.3: Two-phase Telemetry Discovery.

    Phase A: Discover candidate sources (might have telemetry)
    Phase B: Verify actual telemetry artifacts exist

    Args:
        cve_id: CVE ID to discover telemetry for
        triage: TriageContext with poc_references
        description: CVE description for context
        vendor: Vendor name if known

    Returns:
        TelemetryDiscoveryResult with candidates and verified artifacts
    """
    logger.info("[Stage-1.3] Starting two-phase telemetry discovery", cve_id=cve_id)

    context = DiscoveryContext(
        cve_id=cve_id,
        poc_references=triage.poc_references or [],
        description=description,
        vendor=vendor,
    )

    service = get_discovery_service()
    result = await service.discover(cve_id, context)

    discovery = result.discovery
    logger.info(
        "[Stage-1.3] Discovery complete",
        cve_id=cve_id,
        candidates=len(discovery.candidate_sources),
        verified=discovery.get_verified_count(),
        artifact_types=discovery.get_artifact_types(),
    )

    return result
