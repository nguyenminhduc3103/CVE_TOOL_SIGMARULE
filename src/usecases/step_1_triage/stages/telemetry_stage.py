# Step 4 telemetry stage — AI-only TelemetryPlan dispatch. Fails loudly if AI disabled.
from __future__ import annotations

import logging

from config.settings import settings
from src.domain.models.enriched import EnrichedCVEContext
from src.infrastructure.ai.core import BaseAIClient
from src.usecases.step_4_telemetry.models.telemetry_plan import TelemetryPlan
from src.usecases.step_4_telemetry.services.ai_telemetry_service import TelemetryPlanAI

logger = logging.getLogger(__name__)


async def run_telemetry_stage(enriched: EnrichedCVEContext) -> TelemetryPlan:
    """Run Step 4 AI service. Raises RuntimeError if AI disabled or Step 2 missing."""
    if not bool(getattr(settings, "ai_enabled", False)):
        raise RuntimeError(
            "Step 4 requires AI — settings.ai_enabled is False. "
            "Set STEP4_AI_KEYS / STEP4_AI_BASE_URL / STEP4_AI_MODEL in env."
        )
    if enriched.analysis is None:
        raise RuntimeError(
            "Step 4 requires Step 2 analysis — enriched.analysis is None. "
            "Step 2 must run and produce a TechnicalAnalysis before Step 4."
        )

    client = BaseAIClient(
        api_keys=settings.get_step4_api_keys(),
        base_url=settings.get_step4_base_url(),
    )
    plan = await TelemetryPlanAI(client).plan(enriched)
    logger.info(
        "[telemetry_stage] AI plan produced cve_id=%s primary=%s confidence=%.2f",
        plan.cve_id,
        plan.detection_axis.primary,
        plan.telemetry_confidence,
    )
    return plan