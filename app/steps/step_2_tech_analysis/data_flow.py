"""Data Flow Helpers - thao tác trên DICT thuần (không Pydantic).

Các helper này được orchestrator dùng để:
- Convert Pydantic -> dict (cho data flow trung gian)
- Convert dict -> Pydantic (CHỖ DUY NHẤT build Pydantic ở cuối pipeline)
- Normalize AI dict (move attack_flow fields từ top-level xuống nested)
- Merge old + new dicts theo UNION/REPLACE strategy
- Apply 3-tier fallback cho entry_vector, execution_mechanism, observable_side_effects

CHÚ Ý: 4 hàm này được gộp từ _data_flow.py + _merge_strategy.py (cùng context,
dùng chung intermediate dict) để orchestrator.py dễ đọc hơn.
"""
from __future__ import annotations

from typing import Any

from app.shared.models.attack import (
    AttackFlow,
    AttackMapping,
    CWEMetadata,
    TechnicalAnalysis,
)
from app.shared.types.vulnerability_class import VulnerabilityClass
from app.steps.step_2_tech_analysis.fallbacks.attack_flow import (
    apply_attack_flow_fallback,
)


# ==============================================================
# Pydantic <-> dict conversions
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

    # Resolve ai_models_used: prefer base_tech's value (set by orchestrator
    # via ai_service.get_models_used()) → fallback to base_attack's.
    ai_models_used = (
        getattr(base_tech, "ai_models_used", None)
        or getattr(base_attack, "ai_models_used", None)
    )

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
        reasoning=tech_dict.get("reasoning") or None,
        cwe_metadata=cwe_meta,
        attack_flow=attack_flow,
        ai_used=True,
        ai_retry_count=getattr(base_tech, "ai_retry_count", 0),  # PASS THROUGH
        ai_model=ai_model,
        ai_models_used=ai_models_used,
    )

    attack_mapping = AttackMapping(
        tactics=atk_dict.get("tactics") or None,
        techniques=atk_dict.get("techniques") or None,
        subtechniques=atk_dict.get("subtechniques") or None,
        confidence=atk_dict.get("confidence") or getattr(base_attack, "confidence", None),
        mapping_reasons=atk_dict.get("mapping_reasons") or None,
        ai_used=True,
        ai_retry_count=getattr(base_attack, "ai_retry_count", 0),  # PASS THROUGH
        ai_model=ai_model,
        ai_models_used=ai_models_used,
    )
    return tech_analysis, attack_mapping


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
        # AI trả thẳng ở root (không có wrapper technical_analysis).
        # ATT&CK fields phải đi vào `attack_mapping`, không bị nuốt vào
        # `technical_analysis` (bug "AI output wipeout to 0" CVE-2023-22515).
        _ATTACK_ROOT_KEYS = {
            "tactics", "techniques", "subtechniques", "mapping_reasons",
            "attack_confidence",
        }
        existing_atk = dict(ai_data.get("attack_mapping") or {})
        recovered_atk = {
            k: ai_data[k] for k in _ATTACK_ROOT_KEYS if k in ai_data
        }
        tech = {
            k: v for k, v in ai_data.items()
            if k not in (
                "attack_mapping", "metadata", "cve_id",
                "pre_auth", "remote_exploitable",
            ) and k not in _ATTACK_ROOT_KEYS
        }
        ai_data = {
            "technical_analysis": tech,
            "attack_mapping": {**existing_atk, **recovered_atk},
            "metadata": ai_data.get("metadata", {}),
        }

    # Chuẩn hoá: copy top-level attack_flow fields xuống nested nếu nested thiếu
    flow = tech.setdefault("attack_flow", {})
    for field in ("entry_vector", "execution_mechanism"):
        if not flow.get(field) and tech.get(field):
            flow[field] = tech[field]

    # Đảm bảo cve_id, cwe_ids, pre_auth, remote_exploitable ở root
    ai_data.setdefault("cve_id", cve_id)
    ai_data.setdefault("cwe_ids", cwe_ids or [])

    return ai_data


# ==============================================================
# Sanitize None / "none" placeholders từ AI output
# ==============================================================

def _normalize_none_placeholders(ai_data: dict[str, Any]) -> dict[str, Any]:
    """Convert None / ["none"] placeholders từ AI thành giá trị an toàn.

    AI Groq đôi khi trả:
      - techniques = null  (thay vì [])
      - techniques = []
      - evasive_indicators = ["none"]  (placeholder AI)
      - mapping_reasons = ["none"]

    Hàm này normalize thành empty list / None để Pydantic build không crash,
    và downstream filter "none" placeholder không bị sót.

    Returns:
        ai_data (modified in-place, cũng return để chain).
    """
    tech = ai_data.get("technical_analysis") or {}
    atk = ai_data.get("attack_mapping") or {}
    flow = tech.get("attack_flow") or {}

    # AI trả null cho list field → empty list (an toàn hơn None)
    for key in ("techniques", "subtechniques", "tactics"):
        if atk.get(key) is None:
            atk[key] = []
        if not isinstance(atk.get(key), list):
            atk[key] = [atk[key]] if atk.get(key) else []

    # Filter "none" placeholder cho behavioral fields
    for key in ("evasive_indicators", "mandatory_behaviors", "exploit_requirements"):
        raw = tech.get(key) or []
        if isinstance(raw, list):
            tech[key] = [x for x in raw if str(x).lower().strip() not in ("none", "n/a", "unknown")]
        elif raw and str(raw).lower().strip() in ("none", "n/a", "unknown"):
            tech[key] = []

    for key in ("mapping_reasons",):
        raw = atk.get(key) or []
        if isinstance(raw, list):
            atk[key] = [x for x in raw if str(x).lower().strip() not in ("none", "n/a", "unknown")]
        elif raw and str(raw).lower().strip() in ("none", "n/a", "unknown"):
            atk[key] = []

    # Reasoning - cùng pattern
    raw_reasoning = tech.get("reasoning")
    if isinstance(raw_reasoning, list):
        tech["reasoning"] = [x for x in raw_reasoning if str(x).lower().strip() not in ("none", "n/a", "unknown")]
    elif raw_reasoning and str(raw_reasoning).lower().strip() in ("none", "n/a", "unknown"):
        tech["reasoning"] = []

    # observable_side_effects - list field, không filter "none" vì có thể legitimate
    if flow.get("observable_side_effects") is None:
        flow["observable_side_effects"] = []

    return ai_data


# ==============================================================
# 3-tier fallback cho 3 MANDATORY attack_flow fields
# ==============================================================

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
# (Removed) _merge_old_new — root cause of wipeout bug CVE-2023-22515
# ==============================================================
# Hàm này đã được thay thế bằng partial-fill retry (retry.py + orchestrator.py).
# Lý do xóa:
#   - Khi AI retry trả output gần như rỗng, _merge_old_new REPLACE cho
#     ATT&CK fields (techniques, tactics, subtechniques) dùng "new rỗng
#     → fallback về old" - nhưng nếu old cũng bị _apply_3_tier_fallback
#     wipe sau khi filter dropped → mất hết entries.
#   - UNION cho descriptive fields (mandatory_behaviors, mapping_reasons)
#     với nhau vẫn ổn, nhưng vì AI retry trả scalar/None thay vì list,
#     sort+set cũng produce output mong manh.
#
# Cách mới (partial-fill):
#   - Attempt 1 dict giữ nguyên các field valid.
#   - Retry dict chỉ điền vào field invalid.
#   - Orchestrator merge per-field (xem _partial_fill_attempt trong
#     orchestrator.py) — đơn giản, không touch field valid, không có
#     nhánh logic phức tạp để sinh bug.

