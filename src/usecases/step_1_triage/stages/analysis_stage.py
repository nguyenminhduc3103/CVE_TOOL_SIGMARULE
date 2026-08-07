from __future__ import annotations

import logging
from src.domain.models.attack import AttackMapping, TechnicalAnalysis
from src.domain.models.enriched import EnrichedCVEContext
from src.domain.services.capability import CapabilityClassification
from src.infrastructure.ai.core import BaseAIClient
from src.usecases.step_2_analysis.services.phase2a_service import AIBehaviorService
from src.usecases.step_2_analysis.orchestrator import run_step2_tech_analysis

logger = logging.getLogger(__name__)


async def run_analysis_stage(
    context: EnrichedCVEContext,
    capability: CapabilityClassification | None = None,
) -> tuple[TechnicalAnalysis, AttackMapping]:
    """Run Step 2 Technical Analysis & ATT&CK Mapping."""
    client = BaseAIClient()
    ai_service = AIBehaviorService(client)

    poc_desc = getattr(context.intel, "poc_description", None) if context.intel else None
    poc_req = (
        context.intel.poc_network_payloads[0]
        if context.intel and context.intel.poc_network_payloads
        else None
    )

    analysis, attack, _ = await run_step2_tech_analysis(
        ai_service=ai_service,
        base_client=client,
        cve_id=context.core.cve_id,
        description=context.core.description if isinstance(context.core.description, str) else str(context.core.description or ""),
        cvss_score=context.core.cvss_score or 0.0,
        cvss_vector=context.core.cvss_vector or "",
        cwe_ids=context.core.cwe_ids or [],
        poc_description=poc_desc,
        poc_request_info=poc_req,
    )

    return analysis or TechnicalAnalysis(), attack or AttackMapping()
