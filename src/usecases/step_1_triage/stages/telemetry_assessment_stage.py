"""
Stage wrapper for Step 1.4: Telemetry Assessment (GATE).

Only PASSES if verified telemetry artifacts exist.
Having candidate sources is NOT enough.
"""

from __future__ import annotations

from src.domain.models.telemetry_discovery import (
    TelemetryDiscovery,
    TelemetrySourceAssessment,
)
from config.logging import get_logger

logger = get_logger(__name__)


async def run_telemetry_assessment_stage(
    discovery: TelemetryDiscovery,
) -> TelemetrySourceAssessment:
    """Run Step 1.4: Telemetry Assessment (GATE).

    Gate decision matrix:
    - 0 verified artifacts → STOP_GATE (blocking=True)
    - 1+ verified artifacts → CONTINUE
    - 3+ verified artifacts → HIGH confidence

    IMPORTANT: Having candidate sources is NOT enough.
    Gate only PASSES when actual telemetry artifacts are verified.

    Args:
        discovery: TelemetryDiscovery from Step 1.3

    Returns:
        TelemetrySourceAssessment with GATE decision
    """
    logger.info(
        "[Stage-1.4] Assessing telemetry",
        cve_id=discovery.cve_id,
        candidates=len(discovery.candidate_sources),
        verified=discovery.get_verified_count(),
    )

    assessment = TelemetrySourceAssessment.from_discovery(discovery)

    logger.info(
        "[Stage-1.4] Assessment complete",
        cve_id=discovery.cve_id,
        decision=assessment.decision.value,
        blocking=assessment.blocking,
        verified_count=assessment.verified_count,
        confidence=assessment.confidence.value if hasattr(assessment.confidence, 'value') else assessment.confidence,
    )

    return assessment
