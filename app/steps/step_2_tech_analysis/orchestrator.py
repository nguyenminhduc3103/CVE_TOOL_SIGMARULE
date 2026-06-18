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

Helpers được tách ra các module:
- _data_flow.py: Pydantic <-> dict conversion + normalize
- _merge_strategy.py: _merge_old_new + _apply_3_tier_fallback
- _retry.py: _build_retry_payload (retry loop body vẫn ở đây)
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
from app.steps.step_2_tech_analysis.gap_analysis import (
    build_gap_report,
    compute_coverage,
    compute_ground_truth,
)
from app.steps.step_2_tech_analysis.services.ai_service import (
    AIBehaviorService,
)
from app.steps.step_2_tech_analysis._data_flow import (
    _ai_dict_to_pydantic,
    _normalize_ai_dict,
)
from app.steps.step_2_tech_analysis._merge_strategy import (
    _apply_3_tier_fallback,
    _merge_old_new,
)
from app.steps.step_2_tech_analysis._retry import (
    _build_retry_payload,
)

logger = logging.getLogger(__name__)

# Ngưỡng retry
THRESHOLD_FULL_PASS = 1.0
# Retry cho MỌI case chưa full pass (kể cả 0%). MAX_RETRIES=3 chặn runaway.
# Với gap report mạnh (REMOVE extras + ADD missing), AI có cơ hội sửa lỗi
# kể cả khi lần 1 trả rất tệ (vd DoS thuần, coverage 33% do thiếu ATT&CK).
THRESHOLD_RETRY_FALLBACK = 0.0
MAX_RETRIES = 3

_RETRY_SYSTEM_PROMPT = (
    Path(__file__).parent / "prompts" / "retry_behavior.system.txt"
).read_text(encoding="utf-8").replace(
    "{{SHARED_MITRE_RULES}}",
    (Path(__file__).parent / "prompts" / "_shared_mitre_rules.md").read_text(
        encoding="utf-8"
    ),
)


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

    # PHASE 4: Warn khi ground truth UNKNOWN hoặc coverage None
    if coverage.get("ground_truth_quality") == "UNKNOWN":
        logger.warning(
            "[Step 2 - Gap Analysis] %s: NO ground truth available "
            "(CWE=%s, CVSS=%s). Verdict=UNKNOWN - skipping retry loop.",
            cve_id, cwe_ids, cvss_vector,
        )
    if coverage["overall_coverage"] is None:
        logger.warning(
            "[Step 2 - Gap Analysis] %s: coverage=None (verdict=UNKNOWN). "
            "Skip retry.",
            cve_id,
        )

    # Format coverage cho log - xử lý None
    cov_pct = (
        f"{coverage['overall_coverage'] * 100:.0f}%"
        if coverage["overall_coverage"] is not None
        else "N/A"
    )
    logger.debug(
        "[Step 2 - Gap Analysis] %s attempt 1: coverage=%s verdict=%s",
        cve_id, cov_pct, coverage["verdict"],
    )

    # Track how many gap-analysis retries were used to reach the final output.
    # 0 = success on first AI attempt (no retry needed).
    retries_used: int = 0

    # Bước 5: Retry loop
    # PHASE 4: None-safe retry decision
    # Retry khi:
    #   (a) coverage ở vùng 40-99% (thiếu items), HOẶC
    #   (b) coverage cao NHƯNG AI vẫn bịa extras (needs_retry=True), HOẶC
    #   (c) AI output có quality_gaps (evasive_indicators/reasoning/mapping_reasons rỗng).
    # Nếu overall_coverage = None (UNKNOWN verdict) → KHÔNG retry
    # (không biết đúng/sai thì không thể feedback AI).
    # LƯU Ý: quality_gaps detection đã được centralize trong compute_coverage()
    # (gap_analysis.py) - ở đây chỉ cần đọc coverage["needs_retry"] đã bao gồm.
    overall_for_retry = coverage["overall_coverage"]
    quality_gaps = coverage.get("quality_gaps", [])

    if overall_for_retry is None:
        should_retry = False
    else:
        should_retry = coverage.get("needs_retry", False) or (
            THRESHOLD_RETRY_FALLBACK <= overall_for_retry < THRESHOLD_FULL_PASS
        )
        if quality_gaps:
            logger.debug(
                "[Step 2 - Gap Retry] %s: AI quality gaps: %s - forcing retry",
                cve_id, quality_gaps,
            )

    if should_retry:
        retry_reason = "needs_retry (AI bịa extras)" if coverage.get("needs_retry") else "partial coverage"
        logger.debug(
            "[Step 2 - Gap Retry] %s entering retry loop (reason=%s, coverage=%.0f%%, max=%d)",
            cve_id, retry_reason, overall_for_retry * 100, MAX_RETRIES,
        )

        for retry_num in range(1, MAX_RETRIES + 1):
            gap_report = build_gap_report(current_output, ground_truth, coverage)
            logger.debug(
                "[Step 2 - Gap Retry] %s retry %d/%d: missing_behaviors=%s missing_techniques=%s extra_techniques=%s",
                cve_id, retry_num, MAX_RETRIES,
                gap_report["gap_analysis"]["missing_behaviors"],
                gap_report["gap_analysis"]["missing_techniques"],
                coverage.get("extra_techniques", []),
            )

            # Merge extras từ coverage vào gap_analysis để feedback prompt
            # có thể truy cập (build_gap_report không trả extra_techniques
            # ở top level - chỉ compute_coverage mới có).
            gap_for_payload = dict(gap_report["gap_analysis"])
            gap_for_payload["extra_techniques"] = coverage.get("extra_techniques", [])

            retry_user_prompt = _build_retry_payload(
                description=description,
                cvss_vector=cvss_vector,
                cwe_ids=cwe_ids,
                previous_output=current_output,
                gap_analysis=gap_for_payload,
                retry_num=retry_num,
                cve_id=cve_id,
            )

            try:
                # Mark retry model BEFORE the call so it's recorded even if
                # the call raises (e.g. rate-limit). The analyze model was
                # already recorded inside fetch_raw_response().
                ai_service.record_retry_model()
                # Switch to retry override endpoint if configured (e.g. Gemini
                # 1M TPM to dodge Groq's 6K TPM ceiling on large retry
                # payloads). Falls back to primary client if not set.
                from app.core.config import settings as _settings
                _retry_key = getattr(_settings, "retry_ai_api_key", None) or None
                _retry_url = getattr(_settings, "retry_ai_base_url", None) or None
                response_text = await base_client.call_llm(
                    system_prompt=_RETRY_SYSTEM_PROMPT,
                    user_prompt=retry_user_prompt,
                    model=ai_service._RETRY_MODEL,
                    override_api_key=_retry_key,
                    override_base_url=_retry_url,
                )
                # Parse trực tiếp response_text (KHÔNG gọi _clean_json private
                # method vì không tồn tại trên ai_service - bug cũ làm
                # retry loop crash silently sau attempt 1)
                try:
                    retry_data = json.loads(response_text)
                except json.JSONDecodeError:
                    # Thử clean thủ công nếu AI trả markdown wrapper
                    text = response_text.strip()
                    if text.startswith("```json"):
                        text = text[7:]
                    if text.startswith("```"):
                        text = text[3:]
                    if text.endswith("```"):
                        text = text[:-3]
                    retry_data = json.loads(text.strip())
            except Exception as exc:
                # Catch TẤT CẢ exceptions - bao gồm AIServiceError, JSONDecodeError,
                # httpx errors, rate limit (429), network, etc.
                logger.warning(
                    "[Step 2 - Gap Retry] %s retry %d failed: %s",
                    cve_id, retry_num, exc,
                )
                # Track retry đã chạy dù fail
                retries_used = retry_num
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
            new_overall = new_coverage["overall_coverage"]
            old_overall = coverage["overall_coverage"]

            # Format None thành "N/A" cho log
            new_pct = f"{new_overall * 100:.0f}%" if new_overall is not None else "N/A"
            old_pct = f"{old_overall * 100:.0f}%" if old_overall is not None else "N/A"
            logger.debug(
                "[Step 2 - Gap Retry] %s after retry %d: coverage=%s (was %s), extras=%s",
                cve_id, retry_num, new_pct, old_pct,
                new_coverage.get("extra_techniques", []),
            )

            # Track retry đã chạy (LOGIC MỚI: luôn update bên ngoài if)
            retries_used = retry_num

            # PHASE 4: None-safe comparison - treat None as 0.0 cho numeric
            # compare (preserve None ở final output metadata)
            new_for_compare = new_overall if new_overall is not None else 0.0
            old_for_compare = old_overall if old_overall is not None else 0.0

            # LUÔN cập nhật current_output + coverage sau mỗi retry.
            # Lý do: _merge_old_new() dùng REPLACE strategy cho ATT&CK →
            # extras cũ bị cắt, output mới luôn "tốt hơn" previous attempt
            # về mặt factual (kể cả khi coverage score không tăng).
            current_output = merged
            coverage = new_coverage

            # CHỈ break khi full pass + không còn extras (đạt mục tiêu)
            # Nếu chưa full pass → tiếp tục retry cho đến MAX_RETRIES
            # để AI có cơ hội thử lại với feedback mới (gap report khác).
            if (
                new_overall is not None
                and new_overall >= THRESHOLD_FULL_PASS
                and not coverage.get("needs_retry", False)
            ):
                logger.debug(
                    "[Step 2 - Gap Retry] %s reached 100%% clean after retry %d",
                    cve_id, retry_num,
                )
                break

        # Khi loop kết thúc do exhausted (retry_num == MAX_RETRIES mà vẫn
        # chưa clean pass), current_output + coverage là kết quả lần cuối.
        # Đây là behavior theo Option A: giữ best-effort kết quả, đánh dấu
        # retries_used=MAX_RETRIES để caller biết AI fail correction.
        if retries_used == 0 and should_retry:
            # Defensive: nếu loop không chạy lần nào (vd exception trước loop)
            # → đánh dấu MAX_RETRIES để log.
            retries_used = MAX_RETRIES
            logger.warning(
                "[Step 2 - Gap Retry] %s loop did not execute; forced retries_used=%d",
                cve_id, MAX_RETRIES,
            )

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
            cve_id=cve_id,
            description=description,
            cvss_vector=cvss_vector,
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
