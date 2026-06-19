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

    attack = AttackMapping(
        tactics=attack_rb.get("tactics"),
        techniques=attack_rb.get("techniques"),
        subtechniques=attack_rb.get("subtechniques"),
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
) -> tuple[TechnicalAnalysis | None, AttackMapping | None, dict[str, Any]]:
    """Run Step 2 với field-level validation + partial-fill retry + rule-based fallback.

    Returns:
        (TechnicalAnalysis | None, AttackMapping | None, validation_dict)
        None nếu cả AI và rule-based đều fail.
    """
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
        base_tech = TechnicalAnalysis(
            confidence=0.85,
            ai_used=True,
            ai_retry_count=retries_used,
            ai_model=ai_model,
        )
        base_attack = AttackMapping(
            ai_used=True,
            ai_retry_count=retries_used,
            ai_model=ai_model,
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
