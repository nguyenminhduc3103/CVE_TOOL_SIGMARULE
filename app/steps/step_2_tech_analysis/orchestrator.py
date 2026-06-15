"""Orchestrator cho Step 2 - Technical & ATT&CK Analyzer.

SINGLE RESPONSIBILITY: Điều phối luồng:
1. AI lần 1 → dict thuần
2. Coverage check (gap_analysis)
3. Retry với gap report (nếu 40-99%)
4. Merge old + new
5. Fallback 3-tier cho 3 MANDATORY fields
6. REBUILD Pydantic CHỈ ở đây (cuối cùng)

DATA FLOW: dict-only cho mọi xử lý trung gian. CHỈ parse lại Pydantic
trước khi return.

Đây là fix bug cốt lõi: trước đây data flow bị mix giữa Pydantic + Dict +
nested + top-level, gây mất dữ liệu ở 3 fields attack_flow.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from app.shared.models.attack import (
    AttackFlow,
    AttackMapping,
    CWEMetadata,
    TechnicalAnalysis,
)
from app.shared.ai.core import AIServiceError, BaseAIClient
from app.steps.step_2_tech_analysis.fallbacks.attack_flow import (
    apply_attack_flow_fallback,
)
from app.steps.step_2_tech_analysis.gap_analysis import (
    build_gap_report,
    compute_coverage,
    compute_ground_truth,
)
from app.steps.step_2_tech_analysis.services.ai_service import (
    AIBehaviorService,
)
from app.shared.types.vulnerability_class import VulnerabilityClass

logger = logging.getLogger(__name__)

# Ngưỡng retry
THRESHOLD_FULL_PASS = 1.0
THRESHOLD_RETRY_FALLBACK = 0.4
MAX_RETRIES = 2

_RETRY_SYSTEM_PROMPT = (
    Path(__file__).parent / "prompts" / "retry_behavior.system.txt"
).read_text(encoding="utf-8")


# ==============================================================
# Data Flow Helpers - thao tác trên DICT thuần (không Pydantic)
# ==============================================================

def _vulnerability_class_to_str(vc) -> str | None:
    """Convert Pydantic enum hoặc str sang string (None nếu rỗng)."""
    if vc is None:
        return None
    if hasattr(vc, "value"):
        return str(vc.value)
    return str(vc).strip() or None


def _ai_pydantic_to_dict(tech_analysis: TechnicalAnalysis, attack_mapping: AttackMapping, cve_id: str, cwe_ids: list[str] | None) -> dict[str, Any]:
    """Convert Pydantic sang dict (CHO DATA FLOW TRUNG GIAN).

    QUAN TRỌNG: cả 2 fields entry_vector + execution_mechanism được
    lưu ở CẢ top-level + nested attack_flow (để serializer format target
    đọc top-level, Pydantic AttackFlow đọc nested).
    """
    # CẢ 2 nguồn (top-level + nested)
    af = tech_analysis.attack_flow
    entry_vector = af.entry_vector if af else None
    execution_mechanism = af.execution_mechanism if af else None
    obs_effects = af.observable_side_effects if af else None

    return {
        "cve_id": cve_id,
        "cwe_ids": cwe_ids or [],
        "pre_auth": getattr(tech_analysis, "pre_auth", None),
        "remote_exploitable": getattr(tech_analysis, "remote_exploitable", None),
        "technical_analysis": {
            "family": getattr(tech_analysis, "family", None),
            "vulnerability_type": getattr(tech_analysis, "vulnerability_type", None),
            "vulnerability_class": _vulnerability_class_to_str(
                getattr(tech_analysis, "vulnerability_class", None)
            ),
            "exploit_vector": getattr(tech_analysis, "exploit_vector", None),
            "exploit_complexity": getattr(tech_analysis, "exploit_complexity", None),
            "entry_vector": entry_vector,                # TOP-LEVEL (cho serializer)
            "execution_mechanism": execution_mechanism, # TOP-LEVEL
            "cwe_metadata": (
                tech_analysis.cwe_metadata.model_dump(exclude_none=True)
                if getattr(tech_analysis, "cwe_metadata", None) is not None
                else None
            ),
            "attack_flow": {
                "entry_vector": entry_vector,            # NESTED (cho Pydantic)
                "execution_mechanism": execution_mechanism,
                "observable_side_effects": obs_effects or [],
            },
            "mandatory_behaviors": getattr(tech_analysis, "mandatory_behaviors", None) or [],
            "exploit_requirements": getattr(tech_analysis, "exploit_requirements", None) or [],
        },
        "attack_mapping": {
            "tactics": getattr(attack_mapping, "tactics", None) or [],
            "techniques": getattr(attack_mapping, "techniques", None) or [],
            "subtechniques": getattr(attack_mapping, "subtechniques", None) or [],
            "confidence": getattr(attack_mapping, "confidence", None),
            "mapping_reasons": getattr(attack_mapping, "mapping_reasons", None) or [],
        },
        "metadata": {
            "ai_used": True,
            "ai_model": getattr(tech_analysis, "ai_model", None),
        },
    }


def _ai_dict_to_pydantic(
    data: dict[str, Any], base_tech: TechnicalAnalysis, base_attack: AttackMapping
) -> tuple[TechnicalAnalysis, AttackMapping]:
    """Convert dict (data flow trung gian) sang Pydantic.

    Đây là CHỖ DUY NHẤT build Pydantic từ dict (cuối pipeline).
    """
    tech_dict = data.get("technical_analysis") or {}
    atk_dict = data.get("attack_mapping") or {}

    # CWE metadata
    cwe_meta_raw = tech_dict.get("cwe_metadata")
    cwe_meta = None
    if isinstance(cwe_meta_raw, dict):
        # Normalize cwe_id (singular) -> cwe_ids (list)
        if "cwe_id" in cwe_meta_raw and "cwe_ids" not in cwe_meta_raw:
            single = cwe_meta_raw.pop("cwe_id")
            cwe_meta_raw["cwe_ids"] = [single] if single else []
        if "cwe_name" in cwe_meta_raw and "cwe_names" not in cwe_meta_raw:
            single_name = cwe_meta_raw.pop("cwe_name")
            cwe_meta_raw["cwe_names"] = [single_name] if single_name else []
        cwe_meta = CWEMetadata(**cwe_meta_raw)

    # AttackFlow: ưu tiên nested (Pydantic AttackFlow), fallback top-level
    flow_dict = tech_dict.get("attack_flow") or {}
    attack_flow = AttackFlow(
        entry_vector=flow_dict.get("entry_vector") or tech_dict.get("entry_vector"),
        execution_mechanism=flow_dict.get("execution_mechanism") or tech_dict.get("execution_mechanism"),
        observable_side_effects=flow_dict.get("observable_side_effects") or [],
    )

    # Coerce vulnerability_class
    vc_raw = tech_dict.get("vulnerability_class")
    vc = None
    if vc_raw:
        text = str(vc_raw).strip().lower()
        if text.startswith("vulnerabilityclass."):
            text = text[len("vulnerabilityclass."):]
        text = text.replace(" ", "_").replace("-", "_").strip("_")
        try:
            vc = VulnerabilityClass(text)
        except ValueError:
            for candidate in VulnerabilityClass:
                if candidate.value == text or text in candidate.value:
                    vc = candidate
                    break
            if vc is None:
                vc = VulnerabilityClass.UNKNOWN

    # Resolve ai_model once, before constructing the Pydantic models (the
    # `tech_analysis` / `attack_mapping` locals can't be referenced inside
    # their own initializer — that would raise UnboundLocalError).
    metadata_raw = tech_dict.get("metadata")
    ai_model = (
        metadata_raw.get("ai_model")
        if isinstance(metadata_raw, dict)
        else None
    ) or getattr(base_tech, "ai_model", None) or getattr(base_attack, "ai_model", None)

    tech_analysis = TechnicalAnalysis(
        family=tech_dict.get("family") or getattr(base_tech, "family", None),
        signature=tech_dict.get("signature") or getattr(base_tech, "signature", None),
        vulnerability_type=tech_dict.get("vulnerability_type"),
        vulnerability_class=vc,
        exploit_vector=tech_dict.get("exploit_vector"),
        pre_auth=getattr(base_tech, "pre_auth", None),
        remote_exploitable=getattr(base_tech, "remote_exploitable", None),
        exploit_complexity=tech_dict.get("exploit_complexity"),
        confidence=tech_dict.get("confidence") or getattr(base_tech, "confidence", None),
        likely_outcome=tech_dict.get("likely_outcome") or getattr(base_tech, "likely_outcome", None),
        mandatory_behaviors=tech_dict.get("mandatory_behaviors") or None,
        evasive_indicators=tech_dict.get("evasive_indicators") or None,
        exploit_requirements=tech_dict.get("exploit_requirements") or None,
        cwe_metadata=cwe_meta,
        attack_flow=attack_flow,
        ai_used=True,
        ai_model=ai_model,
    )

    attack_mapping = AttackMapping(
        tactics=atk_dict.get("tactics") or None,
        techniques=atk_dict.get("techniques") or None,
        subtechniques=atk_dict.get("subtechniques") or None,
        confidence=atk_dict.get("confidence") or getattr(base_attack, "confidence", None),
        mapping_reasons=atk_dict.get("mapping_reasons") or None,
        ai_used=True,
        ai_model=ai_model,
    )
    return tech_analysis, attack_mapping


def _apply_3_tier_fallback(
    data: dict[str, Any],
    exploit_vector: str | None,
    vulnerability_class: str | None,
    mandatory_behaviors: list[str],
) -> dict[str, Any]:
    """Apply 3-tier fallback cho 3 MANDATORY fields TRONG DICT.

    Tier 1: dùng giá trị từ data hiện tại (top-level + nested)
    Tier 2: derive rule-based từ exploit_vector + vulnerability_class + behaviors
    Set CẢ 2 chỗ (top-level + nested) để atomic.
    """
    tech = data.setdefault("technical_analysis", {})
    flow = tech.setdefault("attack_flow", {})

    # Tier 1: lấy giá trị từ cả 2 chỗ
    current = {
        "entry_vector": tech.get("entry_vector") or flow.get("entry_vector"),
        "execution_mechanism": tech.get("execution_mechanism") or flow.get("execution_mechanism"),
        "observable_side_effects": flow.get("observable_side_effects") or [],
    }

    # Tier 2: fill missing
    filled = apply_attack_flow_fallback(
        current=current,
        exploit_vector=exploit_vector,
        vulnerability_class=vulnerability_class,
        mandatory_behaviors=mandatory_behaviors,
    )

    # Set CẢ 2 chỗ atomic
    tech["entry_vector"] = filled["entry_vector"]
    tech["execution_mechanism"] = filled["execution_mechanism"]
    flow["entry_vector"] = filled["entry_vector"]
    flow["execution_mechanism"] = filled["execution_mechanism"]
    flow["observable_side_effects"] = filled["observable_side_effects"]

    return data


# ==============================================================
# Retry logic (với gap report)
# ==============================================================

def _merge_old_new(old: dict, new: dict) -> dict:
    """Merge old + new dicts (set union cho lists, prefer new cho scalars)."""
    merged = {**old, **new}

    # Gộp lists
    for key in ("tactics", "techniques", "subtechniques", "mapping_reasons",
                "mandatory_behaviors", "exploit_requirements"):
        in_attack = key in ("tactics", "techniques", "subtechniques", "mapping_reasons")
        if in_attack:
            old_list = (old.get("attack_mapping") or {}).get(key) or []
            new_list = (new.get("attack_mapping") or {}).get(key) or []
        else:
            old_list = (old.get("technical_analysis") or {}).get(key) or []
            new_list = (new.get("technical_analysis") or {}).get(key) or []
        # Guard: AI may return scalar/None for fields it didn't generate.
        old_list = old_list if isinstance(old_list, list) else []
        new_list = new_list if isinstance(new_list, list) else []
        merged_list = sorted(set(old_list + new_list))
        if key in ("tactics", "techniques", "subtechniques", "mapping_reasons"):
            (merged.setdefault("attack_mapping", {}))[key] = merged_list
        else:
            (merged.setdefault("technical_analysis", {}))[key] = merged_list

    # Gộp observable_side_effects
    old_obs = ((old.get("technical_analysis") or {}).get("attack_flow") or {}).get("observable_side_effects") or []
    new_obs = ((new.get("technical_analysis") or {}).get("attack_flow") or {}).get("observable_side_effects") or []
    old_obs = old_obs if isinstance(old_obs, list) else []
    new_obs = new_obs if isinstance(new_obs, list) else []
    merged_obs = sorted(set(old_obs + new_obs))
    (merged.setdefault("technical_analysis", {}).setdefault("attack_flow", {}))["observable_side_effects"] = merged_obs

    return merged


def _build_retry_payload(
    description: str,
    cvss_vector: str,
    cwe_ids: list[str],
    previous_output: dict,
    gap_analysis: dict,
    retry_num: int,
) -> str:
    """Build user prompt cho retry call (JSON)."""
    payload = {
        "step1_context": {
            "description": description,
            "cvss_vector": cvss_vector,
            "cwe_ids": cwe_ids,
        },
        "previous_ai_output": previous_output,
        "system_gap_report": gap_analysis,
        "retry_count": retry_num,
        "max_retries": MAX_RETRIES,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


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
    """Run Step 2 với Gap Analysis & Feedback Loop.

    Data flow:
    1. AI lần 1 → dict (raw)
    2. Convert Pydantic → dict (cho xử lý trung gian)
    3. Coverage check
    4. Retry nếu cần (dict-only)
    5. Merge old + new (dict)
    6. 3-tier fallback (dict)
    7. REBUILD Pydantic từ dict cuối (CHỖ DUY NHẤT build Pydantic)

    Returns:
        (TechnicalAnalysis | None, AttackMapping | None, coverage_dict)
        None nếu AI fail hoàn toàn → caller fallback rule-based.
    """
    # Bước 1: AI lần 1 → dict
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
        return None, None, {"overall_coverage": 0.0, "verdict": "FAIL"}

    # Bước 2: Normalize AI dict (move attack_flow fields từ top-level xuống nested nếu có)
    current_output = _normalize_ai_dict(ai_dict, cve_id, cwe_ids)

    # Bước 3: Apply 3-tier fallback cho 3 MANDATORY fields (sau AI lần 1)
    current_output = _apply_3_tier_fallback(
        data=current_output,
        exploit_vector=current_output.get("technical_analysis", {}).get("exploit_vector"),
        vulnerability_class=current_output.get("technical_analysis", {}).get("vulnerability_class"),
        mandatory_behaviors=current_output.get("technical_analysis", {}).get("mandatory_behaviors", []),
    )

    # Bước 4: Coverage check
    ground_truth = compute_ground_truth(cve_id, description, cwe_ids, cvss_vector)
    coverage = compute_coverage(current_output, ground_truth)
    logger.info(
        "[Step 2 - Gap Analysis] %s attempt 1: coverage=%.0f%% verdict=%s",
        cve_id, coverage["overall_coverage"] * 100, coverage["verdict"],
    )

    # Track how many gap-analysis retries were used to reach the final output.
    # 0 = success on first AI attempt (no retry needed).
    retries_used: int = 0

    # Bước 5: Retry loop nếu coverage 40-99%
    if THRESHOLD_RETRY_FALLBACK <= coverage["overall_coverage"] < THRESHOLD_FULL_PASS:
        for retry_num in range(1, MAX_RETRIES + 1):
            gap_report = build_gap_report(current_output, ground_truth, coverage)
            logger.info(
                "[Step 2 - Gap Retry] %s retry %d/%d: missing_behaviors=%s missing_techniques=%s",
                cve_id, retry_num, MAX_RETRIES,
                gap_report["gap_analysis"]["missing_behaviors"],
                gap_report["gap_analysis"]["missing_techniques"],
            )

            retry_user_prompt = _build_retry_payload(
                description=description,
                cvss_vector=cvss_vector,
                cwe_ids=cwe_ids,
                previous_output=current_output,
                gap_analysis=gap_report["gap_analysis"],
                retry_num=retry_num,
            )

            try:
                response_text = await base_client.call_llm(
                    system_prompt=_RETRY_SYSTEM_PROMPT,
                    user_prompt=retry_user_prompt,
                    model=ai_service._MODEL,
                )
                # Clean + parse (dùng helper của ai_service)
                cleaned = ai_service._clean_json(response_text)
                retry_data = json.loads(cleaned)
            except (json.JSONDecodeError, AIServiceError, Exception) as exc:
                logger.warning(
                    "[Step 2 - Gap Retry] %s retry %d failed: %s",
                    cve_id, retry_num, exc,
                )
                break

            # Normalize + merge
            retry_normalized = _normalize_ai_dict(retry_data, cve_id, cwe_ids)
            merged = _merge_old_new(current_output, retry_normalized)

            # Apply 3-tier fallback cho merged
            merged = _apply_3_tier_fallback(
                data=merged,
                exploit_vector=merged.get("technical_analysis", {}).get("exploit_vector"),
                vulnerability_class=merged.get("technical_analysis", {}).get("vulnerability_class"),
                mandatory_behaviors=merged.get("technical_analysis", {}).get("mandatory_behaviors", []),
            )

            # Re-check coverage
            new_coverage = compute_coverage(merged, ground_truth)
            logger.info(
                "[Step 2 - Gap Retry] %s after retry %d: coverage=%.0f%% (was %.0f%%)",
                cve_id, retry_num, new_coverage["overall_coverage"] * 100,
                coverage["overall_coverage"] * 100,
            )

            if new_coverage["overall_coverage"] > coverage["overall_coverage"]:
                current_output = merged
                coverage = new_coverage
                retries_used = retry_num
                if coverage["overall_coverage"] >= THRESHOLD_FULL_PASS:
                    logger.info(
                        "[Step 2 - Gap Retry] %s reached 100%% after retry %d",
                        cve_id, retry_num,
                    )
                    break
            else:
                logger.info(
                    "[Step 2 - Gap Retry] %s retry %d no improvement, stop",
                    cve_id, retry_num,
                )
                retries_used = retry_num
                break

    # Bước 6: REBUILD Pydantic từ dict cuối (CHỖ DUY NHẤT)
    # Tạo dummy base_tech/base_attack để giữ các field không có trong data flow
    # (vd: pre_auth, remote_exploitable, analysis_confidence - được set bởi rule-based)
    from app.steps.step_2_tech_analysis._shared_engines.behavior_analyzer import analyze_behavior
    from app.steps.step_2_tech_analysis._shared_engines.attack_mapper import map_attack

    cwe_profiles_list = []
    from app.steps.step_2_tech_analysis._shared_engines.cwe_mapper import map_cwe_profiles
    cwe_profiles_list = map_cwe_profiles(cwe_ids) or []
    ontology_result = None
    from app.steps.step_2_tech_analysis._shared_engines.exploit_ontology import infer_exploit_ontology
    ontology_result = infer_exploit_ontology(cwe_ids, description, cvss_vector, references)
    classifier = {
        "exploit_vector": current_output.get("technical_analysis", {}).get("exploit_vector"),
        "pre_auth": None,  # Set by rule-based only
        "remote_exploitable": None,
        "exploit_complexity": current_output.get("technical_analysis", {}).get("exploit_complexity"),
    }

    # Gọi rule-based để lấy pre_auth, remote_exploitable (vì AI có thể null)
    from app.steps.step_2_tech_analysis._shared_engines.exploit_classifier import classify_exploit_vector
    classifier_real = classify_exploit_vector(cvss_vector)
    classifier["pre_auth"] = classifier_real.get("pre_auth")
    classifier["remote_exploitable"] = classifier_real.get("remote_exploitable")

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
        )
    except Exception as exc:
        logger.warning("Rule-based fallback failed: %s", exc)
        behavior = {}
        attack_rb = {}

    # Tạo base_tech từ rule-based (giữ pre_auth, remote_exploitable)
    base_tech = TechnicalAnalysis(
        family=behavior.get("family"),
        signature=behavior.get("signature"),
        vulnerability_type=behavior.get("vulnerability_type"),
        vulnerability_class=behavior.get("vulnerability_class"),
        exploit_vector=classifier.get("exploit_vector"),
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
        ai_used=True,
        ai_retry_count=retries_used,
        ai_model=ai_service._MODEL,
    )

    base_attack = AttackMapping(
        tactics=attack_rb.get("tactics"),
        techniques=attack_rb.get("techniques"),
        subtechniques=attack_rb.get("subtechniques"),
        confidence=attack_rb.get("confidence"),
        mapping_reasons=attack_rb.get("mapping_reasons"),
        ai_used=True,
        ai_retry_count=retries_used,
        ai_model=ai_service._MODEL,
    )

    # REBUILD Pydantic từ dict cuối
    final_tech, final_attack = _ai_dict_to_pydantic(current_output, base_tech, base_attack)

    return final_tech, final_attack, coverage


def _normalize_ai_dict(
    ai_data: dict[str, Any], cve_id: str, cwe_ids: list[str] | None
) -> dict[str, Any]:
    """Normalize AI dict: chuẩn hoá format, đảm bảo các field ở đúng chỗ.

    AI có thể trả:
    - attack_flow ở nested (đúng chuẩn)
    - attack_flow fields ở top-level (AI Groq quirk)
    → Normalize: copy top-level vào nested nếu nested thiếu.
    """
    tech = ai_data.get("technical_analysis") or {}
    if not tech and "family" in ai_data:
        # AI trả thẳng ở root (không có wrapper technical_analysis)
        tech = {k: v for k, v in ai_data.items() if k not in (
            "attack_mapping", "metadata", "cve_id", "pre_auth", "remote_exploitable"
        )}
        ai_data = {"technical_analysis": tech, "attack_mapping": ai_data.get("attack_mapping", {}), "metadata": ai_data.get("metadata", {})}

    # Chuẩn hoá: copy top-level attack_flow fields xuống nested nếu nested thiếu
    flow = tech.setdefault("attack_flow", {})
    for field in ("entry_vector", "execution_mechanism"):
        if not flow.get(field) and tech.get(field):
            flow[field] = tech[field]

    # Đảm bảo cve_id, cwe_ids, pre_auth, remote_exploitable ở root
    ai_data.setdefault("cve_id", cve_id)
    ai_data.setdefault("cwe_ids", cwe_ids or [])

    return ai_data
