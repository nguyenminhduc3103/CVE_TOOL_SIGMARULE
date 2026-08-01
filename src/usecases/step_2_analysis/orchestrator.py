"""Orchestrator cho Step 2 — Technical & ATT&CK Analyzer (2-phase AI flow).

Phase 1: Behavior Analysis - execution_surface, delivery_vector, behaviors
Phase 2A: ATT&CK Extraction - tactics, techniques, subtechniques
Phase 2B: Chain Reasoning - is_attack_chain, confidence
"""
from __future__ import annotations

import logging
from typing import Any

from src.domain.models.attack import (
    AttackMapping,
    TechnicalAnalysis,
)
from src.infrastructure.ai.core import BaseAIClient
from src.usecases.step_2_analysis.services.phase2a_service import (
    AIBehaviorService,
)
from src.usecases.step_2_analysis.data_flow import (
    _ai_dict_to_pydantic,
    _normalize_none_placeholders,
)

logger = logging.getLogger(__name__)


async def run_step2_tech_analysis(
    ai_service: AIBehaviorService,
    base_client: BaseAIClient,
    cve_id: str,
    description: str,
    cvss_score: float,
    cvss_vector: str,
    cwe_ids: list[str],
    poc_description: str | None = None,
    poc_request_info: dict | None = None,
) -> tuple[TechnicalAnalysis | None, AttackMapping | None, dict[str, Any]]:
    """Run Step 2 bằng 2-phase AI flow."""
    return await _run_step2_two_phase(
        ai_service=ai_service,
        base_client=base_client,
        cve_id=cve_id,
        description=description,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        cwe_ids=cwe_ids,
        poc_description=poc_description,
        poc_request_info=poc_request_info,
    )


async def _run_step2_two_phase(
    ai_service: AIBehaviorService,
    base_client: BaseAIClient,
    cve_id: str,
    description: str,
    cvss_score: float,
    cvss_vector: str,
    cwe_ids: list[str],
    poc_description: str | None = None,
    poc_request_info: dict | None = None,
) -> tuple[TechnicalAnalysis | None, AttackMapping | None, dict[str, Any]]:
    """Three-phase AI flow: Phase 1 → Phase 2A → Phase 2B."""
    from src.usecases.step_2_analysis.services.phase1_service import AIPhase1Service
    from src.usecases.step_2_analysis.services.phase2b_service import AIPhase2BService
    from src.usecases.step_2_analysis.rule_based.exploit_classifier import classify_exploit_vector
    from src.usecases.step_2_analysis.rule_based.attack_validator import validate_attack_mapping

    # Fill CVSS-deterministic fields
    cvss_deterministic = classify_exploit_vector(cvss_vector)

    # PHASE 1: Behavior Analysis
    phase1_service = AIPhase1Service(base_client)
    phase1_dict = await phase1_service.fetch_behavior(
        cve_id=cve_id,
        description=description,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        cwe_ids=cwe_ids,
        poc_description=poc_description,
        poc_request_info=poc_request_info,
    )
    phase1_dict["exploit_vector"] = cvss_deterministic.get("exploit_vector")
    phase1_dict["pre_auth"] = cvss_deterministic.get("pre_auth")
    phase1_dict["remote_exploitable"] = cvss_deterministic.get("remote_exploitable")
    phase1_dict["exploit_complexity"] = cvss_deterministic.get("exploit_complexity")
    phase1_dict["user_interaction_required"] = cvss_deterministic.get("user_interaction_required")
    phase1_dict = _normalize_none_placeholders(phase1_dict)

    # PHASE 2A: ATT&CK Extraction
    logger.info("[Phase 2A] Starting...")
    phase2a_dict = await ai_service.fetch_attack_mapping(
        cve_id=cve_id,
        description=description,
        phase1_output=phase1_dict,
    )
    logger.info("[Phase 2A] Got: %s", phase2a_dict)

    # Validate TTPs (log invalid only, don't modify)
    invalid_ttps = validate_attack_mapping(
        phase2a_dict.get("tactics"),
        phase2a_dict.get("techniques"),
        phase2a_dict.get("subtechniques"),
    )
    if invalid_ttps:
        logger.warning("[Step 2] Invalid TTPs detected: %s", invalid_ttps)

    # Build Step 1 output dict for Phase 2B
    step1_dict = {
        "description": description,
        "poc_description": poc_description,
        "poc_request_info": poc_request_info,
    }

    # PHASE 2B: Chain Reasoning
    logger.info("[Phase 2B] Starting with Phase 2A: %s", phase2a_dict)
    phase2b_service = AIPhase2BService(base_client)
    phase2b_dict = await phase2b_service.reason_chain(
        step1_output=step1_dict,
        phase1_output=phase1_dict,
        phase2a_output=phase2a_dict,
        cve_id=cve_id,
    )
    logger.info("[Phase 2B] Got result: %s", phase2b_dict)
    print(f"[DEBUG orch] phase2b_dict keys: {phase2b_dict.keys()}")
    print(f"[DEBUG orch] confidence: {phase2b_dict.get('confidence')}")
    print(f"[DEBUG orch] is_attack_chain: {phase2b_dict.get('is_attack_chain')}")

    # Normalize Phase 2A output
    phase2a_normalized = _normalize_phase2a_dict(phase2a_dict)

    # Normalize Phase 2B output
    phase2b_normalized = _normalize_phase2b_dict(phase2b_dict)

    # Combine all phases
    # Phase 1 → technical_analysis
    # Phase 2A + 2B → attack_mapping
    tech_fields = {k: phase1_dict.pop(k) for k in [
        "exploit_vector", "pre_auth", "remote_exploitable",
        "exploit_complexity", "confidence", "execution_surface",
        "delivery_vector", "user_interaction_required",
        "mandatory_behaviors", "evasive_indicators",
        "exploit_requirements", "reasoning",
    ] if k in phase1_dict}

    combined_dict = {
        **phase1_dict,  # remaining Phase 1 fields
        "technical_analysis": tech_fields,
        "attack_mapping": {
            **phase2a_normalized,  # tactics, techniques, subtechniques
            **phase2b_normalized,  # is_attack_chain, attack_chain, chain_reasoning, confidence_level, mapping_reasons
        }
    }

    # Track AI models
    phase1_model = phase1_service._MODEL
    phase2_model = ai_service._MODEL
    phase2b_model = phase2b_service._MODEL
    models_used: list[str] = []
    for m in (phase1_model, phase2_model, phase2b_model):
        if m and m not in models_used:
            models_used.append(m)

    base_tech = TechnicalAnalysis(
        exploit_vector=phase1_dict.get("exploit_vector"),
        pre_auth=phase1_dict.get("pre_auth"),
        remote_exploitable=phase1_dict.get("remote_exploitable"),
        exploit_complexity=phase1_dict.get("exploit_complexity"),
        user_interaction_required=phase1_dict.get("user_interaction_required"),
        confidence=phase1_dict.get("confidence") or 0.85,
        ai_used=True,
        ai_model=phase2_model,
        ai_models_used=models_used,
    )
    base_attack = AttackMapping(
        ai_used=True,
        ai_model=phase2_model,
        ai_models_used=models_used,
    )
    final_tech, final_attack = _ai_dict_to_pydantic(
        combined_dict, base_tech, base_attack
    )
    return final_tech, final_attack, {
        "validation": {"valid": True},
        "verdict": "PASS_THREE_PHASE",
        "phase1_execution_surface": phase1_dict.get("execution_surface"),
        "phase1_delivery_vector": phase1_dict.get("delivery_vector"),
        "invalid_ttps": invalid_ttps,
    }


def _normalize_phase2a_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize Phase 2A dict - just extract TTPs."""
    if not isinstance(data, dict):
        return {}
    return {
        "techniques": data.get("techniques") or [],
        "subtechniques": data.get("subtechniques") or [],
        "tactics": data.get("tactics") or [],
    }


def _normalize_phase2b_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize Phase 2B dict - chain reasoning + mapping_reasoning."""
    if not isinstance(data, dict):
        return {}
    return {
        "mapping_reasoning": data.get("mapping_reasoning") or data.get("mapping_reasons") or [],
        "is_attack_chain": data.get("is_attack_chain"),
        "attack_chain": data.get("attack_chain"),
        "chain_reasoning": data.get("chain_reasoning"),
        "confidence_level": data.get("confidence"),
    }


def _combine_phase_outputs(
    phase1: dict[str, Any],
    phase2a: dict[str, Any],
    phase2b: dict[str, Any],
) -> dict[str, Any]:
    """Combine Phase 1 + Phase 2A + Phase 2B."""
    combined = {**phase1, **phase2a, **phase2b}
    if "technical_analysis" not in combined:
        tech_fields = {
            k: combined.pop(k) for k in [
                "exploit_vector", "pre_auth", "remote_exploitable",
                "exploit_complexity", "confidence", "execution_surface",
                "delivery_vector", "user_interaction_required",
                "mandatory_behaviors", "evasive_indicators",
                "exploit_requirements", "reasoning",
            ] if k in combined
        }
        combined["technical_analysis"] = tech_fields
    return combined
