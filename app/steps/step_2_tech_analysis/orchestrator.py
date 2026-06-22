"""Orchestrator cho Step 2 - Technical & ATT&CK Analyzer.

SINGLE RESPONSIBILITY: Điều phối luồng (theo CVE-2-Sigma.md Bước 2):

  HAPPY PATH (AI OK):
    1. AI attempt 1 → dict
    2. Normalize + sanitize None/"none" placeholders
    3. Validate field-level (9 fields: ATT&CK techniques/tactics/
       subtechniques/mapping_reasons, mandatory_behaviors, evasive_indicators,
       entry_vector, execution_mechanism, observable_side_effects)
    4. Nếu có field invalid → partial-fill retry (giữ field valid,
       AI chỉ điền field invalid)
    5. Rebuild Pydantic từ dict cuối → return

  FALLBACK PATH (AI fail hoàn toàn - rule-based chỉ chạy khi AI fail):
    - AIServiceError attempt 1, HOẶC
    - Sau MAX_RETRIES vẫn còn field invalid
    → Build Pydantic trực tiếp từ rule-based engines
      (analyze_behavior + map_attack + classify_exploit_vector)

2 LỚP VALIDATION (không có lớp 3):
  - Lớp 1: format + whitelist (validate_ttp_list)
  - Lớp 2: semantic (validate_against_cve_context - 3 rule)

LƯU Ý: KHÔNG có lớp 3 "Sigma rule validation" ở step 2 - đó là việc step 3.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from app.shared.models.attack import (
    AttackMapping,
    TechnicalAnalysis,
)
from app.shared.ai.core import AIServiceError, BaseAIClient
from app.steps.step_2_tech_analysis.services.ai_service import (
    AIBehaviorService,
)
from app.steps.step_2_tech_analysis.data_flow import (
    _ai_dict_to_pydantic,
    _apply_3_tier_fallback,
    _normalize_ai_dict,
    _normalize_none_placeholders,
)
from app.steps.step_2_tech_analysis.retry import (
    _build_retry_payload,
)
from app.steps.step_2_tech_analysis.constants import MAX_RETRIES
from app.steps.step_2_tech_analysis._validation import (
    _apply_partial_fill,
    validate_field_level,
)

logger = logging.getLogger(__name__)


_RETRY_SYSTEM_PROMPT = (
    Path(__file__).parent / "prompts" / "retry_behavior.system.txt"
).read_text(encoding="utf-8").replace(
    "{{SHARED_MITRE_RULES}}",
    (Path(__file__).parent / "prompts" / "_shared_mitre_rules.md").read_text(
        encoding="utf-8"
    ),
)


# ==============================================================
# AI retry helpers
# ==============================================================

async def _call_ai_retry(
    base_client: BaseAIClient,
    ai_service: AIBehaviorService,
    user_prompt: str,
) -> dict[str, Any] | None:
    """Gọi AI retry + parse JSON robust. Trả về None nếu fail hoàn toàn.

    Robust JSON parse:
      - Strip ```json ``` fences (đầu + cuối)
      - Trim whitespace, BOM, smart quotes
      - Nếu vẫn fail → trả None (không raise để caller fallback rule-based)
    """
    try:
        ai_service.record_retry_model()
        from app.core.config import settings as _settings
        _retry_key = getattr(_settings, "retry_ai_api_key", None) or None
        _retry_url = getattr(_settings, "retry_ai_base_url", None) or None
        response_text = await base_client.call_llm(
            system_prompt=_RETRY_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            model=ai_service._RETRY_MODEL,
            override_api_key=_retry_key,
            override_base_url=_retry_url,
        )
    except Exception as exc:
        logger.warning("[Step 2 - Retry] LLM call failed: %s", exc)
        return None

    # Robust JSON parse
    text = (response_text or "").lstrip("﻿").strip()
    # Strip markdown fences (any combo)
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()

    # Thử parse trực tiếp trước
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Fallback: tìm JSON object đầu tiên (cho trường hợp LLM chèn text thừa)
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass

    logger.warning("[Step 2 - Retry] Could not parse JSON: %r", response_text[:200])
    return None


# ==============================================================
# Rule-based fallback (chỉ chạy khi AI fail hoàn toàn)
# ==============================================================

def _build_rule_based_pydantic(
    *,
    cve_id: str,
    description: str,
    references: list[str],
    cpes: list[str],
    cvss_vector: str,
    cwe_ids: list[str],
    ai_model: str | None,
    ai_retry_count: int,
) -> tuple[TechnicalAnalysis, AttackMapping]:
    """Build Pydantic trực tiếp từ rule-based engines (NO dict intermediate).

    Spec CVE-2-Sigma.md: "AI có dự phòng" → rule-based chỉ chạy khi AI
    fail. Output ở đây là FINAL, không cần validate lại, không qua
    `_ai_dict_to_pydantic`.
    """
    from app.steps.step_2_tech_analysis.rule_based.behavior_analyzer import analyze_behavior
    from app.steps.step_2_tech_analysis.rule_based.attack_mapper import map_attack
    from app.steps.step_2_tech_analysis.rule_based.cwe_mapper import map_cwe_profiles
    from app.steps.step_2_tech_analysis.rule_based.exploit_classifier import classify_exploit_vector

    cwe_profiles_list = map_cwe_profiles(cwe_ids) or []
    classifier_real = classify_exploit_vector(cvss_vector)
    classifier = {
        "exploit_vector": None,
        "pre_auth": classifier_real.get("pre_auth"),
        "remote_exploitable": classifier_real.get("remote_exploitable"),
        "exploit_complexity": classifier_real.get("exploit_complexity"),
    }

    try:
        behavior = analyze_behavior(
            cve_id=cve_id,
            description=description,
            references=references,
            cpes=cpes,
            cwe_ids=cwe_ids,
            cvss_vector=cvss_vector,
            cwe_profiles=cwe_profiles_list,
            classifier=classifier,
        )
        attack_rb = map_attack(
            ontology_behaviors=behavior.get("mandatory_behaviors", []),
            vulnerability_class=behavior.get("vulnerability_class"),
            cwe_profiles=cwe_profiles_list,
            classifier=classifier,
            ontology_confidence=behavior.get("ontology_confidence") if isinstance(behavior.get("ontology_confidence"), float) else None,
            cve_id=cve_id,
            description=description,
            cvss_vector=cvss_vector,
        )
    except Exception as exc:
        logger.warning("Rule-based fallback failed: %s", exc)
        behavior = {}
        attack_rb = {}

    tech = TechnicalAnalysis(
        family=behavior.get("family"),
        signature=behavior.get("signature"),
        vulnerability_type=behavior.get("vulnerability_type"),
        vulnerability_class=behavior.get("vulnerability_class"),
        exploit_vector=behavior.get("exploit_vector"),
        pre_auth=classifier.get("pre_auth"),
        remote_exploitable=classifier.get("remote_exploitable"),
        exploit_complexity=behavior.get("exploit_complexity") or classifier.get("exploit_complexity"),
        confidence=behavior.get("analysis_confidence") or 0.85,
        likely_outcome=behavior.get("likely_outcome"),
        mandatory_behaviors=behavior.get("mandatory_behaviors"),
        evasive_indicators=behavior.get("evasive_indicators"),
        exploit_requirements=behavior.get("exploit_requirements"),
        cwe_metadata=behavior.get("cwe_metadata"),
        attack_flow=None,
        ai_used=False,
        ai_retry_count=ai_retry_count,
        ai_model=ai_model,
    )

    # subtechniques: rule-based fallback cũng dùng ["none"] sentinel để
    # đồng bộ với AI happy-path (_validation.py:272 + data_flow.py:189).
    # Nếu attack_rb không trả subtechnique nào → fill ["none"] thay vì []/None
    # để downstream consumer biết "không tìm được sub" (không phải lỗi).
    _rb_sub = attack_rb.get("subtechniques") or []
    attack_rb_sub: list[str] = _rb_sub if _rb_sub else ["none"]

    attack = AttackMapping(
        tactics=attack_rb.get("tactics"),
        techniques=attack_rb.get("techniques"),
        subtechniques=attack_rb_sub,
        confidence=attack_rb.get("confidence"),
        mapping_reasons=attack_rb.get("mapping_reasons"),
        ai_used=False,
        ai_retry_count=ai_retry_count,
        ai_model=ai_model,
    )

    return tech, attack


# ==============================================================
# Main entry point
# ==============================================================

async def run_step2_tech_analysis(
    ai_service: AIBehaviorService,
    base_client: BaseAIClient,
    cve_id: str,
    description: str,
    cvss_score: float,
    cvss_vector: str,
    cwe_ids: list[str],
    cpes: list[str],
    references: list[str],
    published_at: str,
    modified_at: str,
    poc_references: list[str] | None = None,
    threat_actors: list[str] | None = None,
) -> tuple[TechnicalAnalysis | None, AttackMapping | None, dict[str, Any]]:
    """Run Step 2 với field-level validation + partial-fill retry + rule-based fallback.

    TWO-PHASE REFACTOR (CVE_TI_STEP2_TWO_PHASE env):
      Default = False (1-shot, backward compat)
      True = Phase 1 (behavior) → Phase 2 (ATT&CK), with execution_surface
             as canonical anchor to avoid the AV:N→T1190 bias.

    Args:
        ... (giữ nguyên 9 field gốc cho backward compat) ...
        poc_references: Optional list of public PoC URLs (from Step 1 PoC
            provider). Helps AI see actual exploit mechanism, especially for
            CVEs with vague descriptions.
        threat_actors: Optional list of threat actor names (from Step 1 OTX
            provider). Helps AI identify adversary profile and likely scale.

    Returns:
        (TechnicalAnalysis | None, AttackMapping | None, validation_dict)
        None nếu cả AI và rule-based đều fail.
    """
    # Read two-phase flag from Settings (pydantic-settings) — NOT os.getenv,
    # because pydantic-settings does not auto-inject env vars into os.environ.
    from app.core.config import settings
    two_phase = settings.get_two_phase_enabled()

    if two_phase:
        return await _run_step2_two_phase(
            ai_service=ai_service,
            base_client=base_client,
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cwe_ids=cwe_ids,
            cpes=cpes,
            references=references,
            published_at=published_at,
            modified_at=modified_at,
            poc_references=poc_references,
            threat_actors=threat_actors,
        )

    # === LEGACY 1-SHOT FLOW (backward compat) ===
    # Query CAPEC hints per CWE (INSPIRATION ONLY, not ground truth).
    # Local import để tránh load CAPEC bundle (~4.3MB) khi import orchestrator.
    capec_hints_by_cwe: dict[str, list[dict]] = {}
    if cwe_ids:
        try:
            from app.shared.mitre.capec_hint import query_capec_for_cwe
            for cwe_id in cwe_ids:
                if not cwe_id or cwe_id.startswith("NVD-CWE"):
                    continue
                hints = query_capec_for_cwe(cwe_id, max_results=3)
                if hints:
                    capec_hints_by_cwe[cwe_id] = hints
        except Exception as exc:
            logger.debug("[Step 2] CAPEC hint query skipped: %s", exc)

    # Bước 1: AI attempt 1 → dict
    try:
        ai_dict = await ai_service.fetch_raw_response(
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cwe_ids=cwe_ids,
            cpes=cpes,
            references=references,
            published_at=published_at,
            modified_at=modified_at,
            poc_references=poc_references,
            threat_actors=threat_actors,
            capec_hints_by_cwe=capec_hints_by_cwe,
        )
    except AIServiceError as exc:
        logger.warning("AI attempt 1 failed for %s: %s", cve_id, exc)
        # FALLBACK PATH: rule-based (AI fail ngay từ attempt 1)
        tech, attack = _build_rule_based_pydantic(
            cve_id=cve_id,
            description=description,
            references=references,
            cpes=cpes,
            cvss_vector=cvss_vector,
            cwe_ids=cwe_ids,
            ai_model=None,
            ai_retry_count=0,
        )
        return tech, attack, {
            "overall_coverage": 0.0,
            "verdict": "RULE_BASED_FALLBACK",
            "reason": "ai_service_error",
        }

    # Bước 2: Normalize + sanitize
    current_output = _normalize_ai_dict(ai_dict, cve_id, cwe_ids)
    current_output = _normalize_none_placeholders(current_output)
    attempt_1_output = current_output  # giữ snapshot cho partial-fill

    # Bước 3: 3-tier fallback cho 3 MANDATORY attack_flow fields
    current_output = _apply_3_tier_fallback(
        data=current_output,
        exploit_vector=current_output.get("technical_analysis", {}).get("exploit_vector"),
        vulnerability_class=current_output.get("technical_analysis", {}).get("vulnerability_class"),
        mandatory_behaviors=current_output.get("technical_analysis", {}).get("mandatory_behaviors", []),
    )

    # Bước 4: Validate field-level
    validation = validate_field_level(
        data=current_output,
        cvss_vector=cvss_vector,
        description=description,
    )
    logger.debug(
        "[Step 2 - Validation] %s: valid=%s, invalid_fields=%s",
        cve_id, validation["valid"], list(validation["invalid_fields"].keys()),
    )

    # Bước 5: Partial-fill retry loop
    retries_used: int = 0
    if not validation["valid"]:
        logger.debug(
            "[Step 2 - Retry] %s entering partial-fill loop (invalid=%d, max=%d)",
            cve_id, len(validation["invalid_fields"]), MAX_RETRIES,
        )
        for retry_num in range(1, MAX_RETRIES + 1):
            invalid_snapshot = dict(validation["invalid_fields"])
            user_prompt = _build_retry_payload(
                description=description,
                cvss_vector=cvss_vector,
                cwe_ids=cwe_ids,
                attempt_1_output=attempt_1_output,
                invalid_fields=invalid_snapshot,
                retry_num=retry_num,
                cve_id=cve_id,
            )
            retry_data = await _call_ai_retry(base_client, ai_service, user_prompt)
            retries_used = retry_num

            if retry_data is None:
                logger.warning(
                    "[Step 2 - Retry] %s retry %d returned None, aborting",
                    cve_id, retry_num,
                )
                break

            # Normalize + sanitize retry output
            retry_normalized = _normalize_ai_dict(retry_data, cve_id, cwe_ids)
            retry_normalized = _normalize_none_placeholders(retry_normalized)

            # Partial-fill: giữ field valid, chỉ điền field invalid từ retry
            current_output = _apply_partial_fill(
                base=current_output,
                fill=retry_normalized,
                invalid_paths=invalid_snapshot,
            )
            current_output = _apply_3_tier_fallback(
                data=current_output,
                exploit_vector=current_output.get("technical_analysis", {}).get("exploit_vector"),
                vulnerability_class=current_output.get("technical_analysis", {}).get("vulnerability_class"),
                mandatory_behaviors=current_output.get("technical_analysis", {}).get("mandatory_behaviors", []),
            )

            new_validation = validate_field_level(
                data=current_output,
                cvss_vector=cvss_vector,
                description=description,
            )
            validation = new_validation

            if validation["valid"]:
                logger.debug(
                    "[Step 2 - Retry] %s all fields valid after retry %d",
                    cve_id, retry_num,
                )
                break

    # Bước 6: Quyết định path
    if validation["valid"]:
        # HAPPY PATH: AI OK → build Pydantic từ dict
        ai_model = ai_service._MODEL
        # ai_models_used includes analyze + retry (if fired) for visibility.
        ai_models_used = ai_service.get_models_used() or ([ai_model] if ai_model else [])
        base_tech = TechnicalAnalysis(
            confidence=0.85,
            ai_used=True,
            ai_retry_count=retries_used,
            ai_model=ai_model,
            ai_models_used=ai_models_used,
        )
        base_attack = AttackMapping(
            ai_used=True,
            ai_retry_count=retries_used,
            ai_model=ai_model,
            ai_models_used=ai_models_used,
        )
        final_tech, final_attack = _ai_dict_to_pydantic(
            current_output, base_tech, base_attack
        )
        coverage_dict = {
            "validation": validation,
            "retries_used": retries_used,
            "verdict": "PASS" if retries_used == 0 else "PASS_AFTER_RETRY",
        }
        return final_tech, final_attack, coverage_dict

    # FALLBACK PATH: AI fail hết retry → rule-based
    logger.warning(
        "[Step 2 - Fallback] %s AI exhausted (%d retries, still invalid=%s), "
        "falling back to rule-based",
        cve_id, retries_used, list(validation["invalid_fields"].keys()),
    )
    tech, attack = _build_rule_based_pydantic(
        cve_id=cve_id,
        description=description,
        references=references,
        cpes=cpes,
        cvss_vector=cvss_vector,
        cwe_ids=cwe_ids,
        ai_model=ai_service._MODEL,
        ai_retry_count=retries_used,
    )
    return tech, attack, {
        "validation": validation,
        "retries_used": retries_used,
        "verdict": "RULE_BASED_FALLBACK",
        "reason": "ai_exhausted_retries",
    }


async def _run_step2_two_phase(
    ai_service: AIBehaviorService,
    base_client: BaseAIClient,
    cve_id: str,
    description: str,
    cvss_score: float,
    cvss_vector: str,
    cwe_ids: list[str],
    cpes: list[str],
    references: list[str],
    published_at: str,
    modified_at: str,
    poc_references: list[str] | None = None,
    threat_actors: list[str] | None = None,
) -> tuple[TechnicalAnalysis | None, AttackMapping | None, dict[str, Any]]:
    """Two-phase flow: Phase 1 behavior → Phase 2 ATT&CK.

    See run_step2_tech_analysis() docstring for two-phase motivation.
    Key change: Phase 1 output (execution_surface, delivery_vector,
    user_interaction_required) is passed to Phase 2 as canonical anchor,
    preventing the AV:N→T1190 bias that affected single-shot prompts.

    Backward compat: returns same tuple shape as legacy flow.
    """
    from app.steps.step_2_tech_analysis.services.phase1_service import AIPhase1Service
    from app.shared.types.execution_surface import DeliveryVector, ExecutionSurface

    # Query CAPEC hints (chi can cho Phase 2)
    capec_hints_by_cwe: dict[str, list[dict]] = {}
    if cwe_ids:
        try:
            from app.shared.mitre.capec_hint import query_capec_for_cwe
            for cwe_id in cwe_ids:
                if not cwe_id or cwe_id.startswith("NVD-CWE"):
                    continue
                hints = query_capec_for_cwe(cwe_id, max_results=3)
                if hints:
                    capec_hints_by_cwe[cwe_id] = hints
        except Exception as exc:
            logger.debug("[Step 2 - Two-Phase] CAPEC hint query skipped: %s", exc)

    # ===== PHASE 1: Behavior Analysis (FACTS only) =====
    phase1_service = AIPhase1Service(base_client)
    try:
        phase1_dict = await phase1_service.fetch_behavior(
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cwe_ids=cwe_ids,
            cpes=cpes,
            references=references,
            published_at=published_at,
            modified_at=modified_at,
            poc_references=poc_references,
            threat_actors=threat_actors,
        )
    except AIServiceError as exc:
        logger.warning(
            "[Step 2 - Two-Phase] Phase 1 failed for %s: %s → rule-based fallback",
            cve_id, exc,
        )
        # Phase 1 fail → fallback rule-based cho toàn bo (cung cap execution_surface
        # qua classify_execution_surface de Phase 2 downstream consumer có data).
        tech, attack = _build_rule_based_pydantic(
            cve_id=cve_id,
            description=description,
            references=references,
            cpes=cpes,
            cvss_vector=cvss_vector,
            cwe_ids=cwe_ids,
            ai_model=None,
            ai_retry_count=0,
        )
        return tech, attack, {
            "overall_coverage": 0.0,
            "verdict": "RULE_BASED_FALLBACK",
            "reason": "phase1_ai_service_error",
        }

    # Phase 1 SUCCESS - chuan hoa dict + apply rule-based fallback cho 3 field moi
    phase1_dict = _normalize_phase1_dict(phase1_dict, cve_id, cwe_ids)
    phase1_dict = _normalize_none_placeholders(phase1_dict)

    # ===== PHASE 2: ATT&CK Mapping (using Phase 1 anchor) =====
    retries_used: int = 0
    try:
        phase2_dict = await ai_service.fetch_attack_mapping(
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cwe_ids=cwe_ids,
            cpes=cpes,
            references=references,
            published_at=published_at,
            modified_at=modified_at,
            poc_references=poc_references,
            threat_actors=threat_actors,
            capec_hints_by_cwe=capec_hints_by_cwe,
            phase1_output=phase1_dict,
        )
    except AIServiceError as exc:
        logger.warning(
            "[Step 2 - Two-Phase] Phase 2 attempt 1 failed for %s: %s",
            cve_id, exc,
        )
        # Retry Phase 2 only (Phase 1 da OK)
        retries_used = 1
        try:
            phase2_dict = await ai_service.fetch_attack_mapping(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cwe_ids=cwe_ids,
                cpes=cpes,
                references=references,
                published_at=published_at,
                modified_at=modified_at,
                poc_references=poc_references,
                threat_actors=threat_actors,
                capec_hints_by_cwe=capec_hints_by_cwe,
                phase1_output=phase1_dict,
            )
        except AIServiceError as exc2:
            logger.warning(
                "[Step 2 - Two-Phase] Phase 2 retry %d failed for %s: %s → rule-based fallback",
                1, cve_id, exc2,
            )
            tech, attack = _build_rule_based_pydantic(
                cve_id=cve_id,
                description=description,
                references=references,
                cpes=cpes,
                cvss_vector=cvss_vector,
                cwe_ids=cwe_ids,
                ai_model=ai_service._MODEL,
                ai_retry_count=retries_used,
            )
            return tech, attack, {
                "validation": {},
                "retries_used": retries_used,
                "verdict": "RULE_BASED_FALLBACK",
                "reason": "phase2_ai_service_error",
            }

    phase2_dict = _normalize_phase2_dict(phase2_dict, cve_id)

    # ===== Combine Phase 1 + Phase 2 =====
    combined_dict = _combine_phase_outputs(phase1_dict, phase2_dict)

    # Track BOTH Phase 1 + Phase 2 models so reports surface which provider
    # ran each phase (e.g. Phase 1 = OpenRouter, Phase 2 = Groq). Dedup
    # preserves order: Phase 1 first, Phase 2 second.
    phase1_model = phase1_service._MODEL
    phase2_model = ai_service._MODEL
    models_used: list[str] = []
    for m in (phase1_model, phase2_model):
        if m and m not in models_used:
            models_used.append(m)
    ai_model = phase2_model  # legacy field = Phase 2 (primary analyze call)
    base_tech = TechnicalAnalysis(
        confidence=phase1_dict.get("confidence") or 0.85,
        ai_used=True,
        ai_retry_count=retries_used,
        ai_model=ai_model,
        ai_models_used=models_used,
    )
    base_attack = AttackMapping(
        ai_used=True,
        ai_retry_count=retries_used,
        ai_model=ai_model,
        ai_models_used=models_used,
    )
    final_tech, final_attack = _ai_dict_to_pydantic(
        combined_dict, base_tech, base_attack
    )
    return final_tech, final_attack, {
        "validation": {"valid": True},
        "retries_used": retries_used,
        "verdict": "PASS_TWO_PHASE" if retries_used == 0 else "PASS_TWO_PHASE_AFTER_RETRY",
        "phase1_execution_surface": phase1_dict.get("execution_surface"),
        "phase1_delivery_vector": phase1_dict.get("delivery_vector"),
        "phase1_user_interaction_required": phase1_dict.get("user_interaction_required"),
    }


def _normalize_phase1_dict(
    data: dict[str, Any], cve_id: str, cwe_ids: list[str]
) -> dict[str, Any]:
    """Normalize Phase 1 dict: clean key names, fill rule-based fallback cho
    execution_surface/delivery_vector neu AI de unknown.

    Phase 1 dict structure khac Phase 2 (flat, khong co technical_analysis/attack_mapping
    wrapper). Phase 1 la "behavior only" nen dict shape giong cu, nhung them 3
    field moi o top level.
    """
    if not isinstance(data, dict):
        data = {}

    # Rule-based fallback cho execution_surface / delivery_vector / user_interaction
    desc = data.get("attack_flow", {}).get("entry_vector", "") if isinstance(data.get("attack_flow"), dict) else ""
    # Lay description goc tu data neu co, neu khong lay tu attack_flow
    rule_explanation_desc = data.get("description") or desc
    cvss_vector = data.get("cvss_vector")

    # Neu AI khong set execution_surface, su dung rule-based fallback
    from app.steps.step_2_tech_analysis.rule_based.exploit_classifier import (
        classify_delivery_vector,
        classify_execution_surface,
    )
    if not data.get("execution_surface") or data.get("execution_surface") == "unknown":
        rule_surface = classify_execution_surface(cvss_vector, rule_explanation_desc, cwe_ids)
        if rule_surface.value != "unknown":
            data["execution_surface"] = rule_surface.value
            logger.debug(
                "[Step 2 - Two-Phase] %s execution_surface filled by rule-based: %s",
                cve_id, rule_surface.value,
            )

    # Tuong tu cho delivery_vector (can execution_surface da co)
    if data.get("execution_surface"):
        from app.shared.types.execution_surface import ExecutionSurface
        if not data.get("delivery_vector") or data.get("delivery_vector") == "unknown":
            rule_delivery = classify_delivery_vector(
                cvss_vector, rule_explanation_desc, ExecutionSurface(data["execution_surface"])
            )
            if rule_delivery.value != "unknown":
                data["delivery_vector"] = rule_delivery.value
                logger.debug(
                    "[Step 2 - Two-Phase] %s delivery_vector filled by rule-based: %s",
                    cve_id, rule_delivery.value,
                )

    return data


def _normalize_phase2_dict(
    data: dict[str, Any], cve_id: str
) -> dict[str, Any]:
    """Normalize Phase 2 dict: wrap trong attack_mapping cho _ai_dict_to_pydantic.

    Phase 2 output tu AI la flat dict {tactics, techniques, subtechniques,
    mapping_reasons, attack_confidence}. _ai_dict_to_pydantic expect shape:
    {"attack_mapping": {tactics, techniques, ...}}. Wrap no lai.
    """
    if not isinstance(data, dict):
        data = {}

    # Phase 2 chi chua ATT&CK fields
    attack_mapping_block = {
        "tactics": data.get("tactics") or [],
        "techniques": data.get("techniques") or [],
        "subtechniques": data.get("subtechniques") or [],
        "mapping_reasons": data.get("mapping_reasons") or [],
        "confidence": data.get("attack_confidence"),
    }
    return {"attack_mapping": attack_mapping_block}


def _combine_phase_outputs(
    phase1: dict[str, Any], phase2: dict[str, Any]
) -> dict[str, Any]:
    """Combine Phase 1 (behavior) + Phase 2 (attack_mapping) thanh dict giong
    legacy 1-shot output, de _ai_dict_to_pydantic parse duoc.

    Phase 1 dict hien o top level (family, vulnerability_type, attack_flow, ...).
    Phase 2 dict da duoc wrap trong `attack_mapping` boi _normalize_phase2_dict.
    """
    combined = {**phase1, **phase2}
    # Move Phase 1 fields vao technical_analysis wrapper neu can
    # (existing _ai_dict_to_pydantic expects {technical_analysis: {...},
    # attack_mapping: {...}}). Phase 1 fields co the o top level hoac
    # trong technical_analysis - tuy vao implementation. Kiem tra va chuan hoa.
    if "technical_analysis" not in combined:
        # Phase 1 dict co the o flat shape (khong co technical_analysis wrapper)
        # Extract va wrap
        tech_fields = {
            k: combined.pop(k) for k in [
                "family", "vulnerability_type", "vulnerability_class",
                "exploit_vector", "pre_auth", "remote_exploitable",
                "exploit_complexity", "confidence", "execution_surface",
                "delivery_vector", "user_interaction_required",
                "attack_flow", "mandatory_behaviors", "evasive_indicators",
                "exploit_requirements", "cwe_metadata", "reasoning",
            ] if k in combined
        }
        combined["technical_analysis"] = tech_fields
    return combined
