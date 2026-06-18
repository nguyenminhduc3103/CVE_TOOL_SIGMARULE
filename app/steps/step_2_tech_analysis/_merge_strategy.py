"""Merge strategy + 3-tier fallback cho 3 MANDATORY fields.

Hai helpers này tách riêng để orchestrator.py gọn hơn:
- _merge_old_new: hợp nhất 2 dicts theo UNION/REPLACE strategy
- _apply_3_tier_fallback: fallback cho entry_vector, execution_mechanism, observable_side_effects
"""
from __future__ import annotations

from typing import Any

from app.steps.step_2_tech_analysis.fallbacks.attack_flow import (
    apply_attack_flow_fallback,
)


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


def _merge_old_new(old: dict, new: dict) -> dict:
    """Merge old + new dicts theo split strategy:

    UNION (set old + new, dedup, sort):
      - mandatory_behaviors:        behaviors thường bổ sung cho nhau
      - exploit_requirements:        điều kiện khai thác - giữ tất cả
      - mapping_reasons:             lý do mapping - giữ tất cả
      - observable_side_effects:     side effects - giữ tất cả
      - evasive_indicators:          kỹ thuật né tránh detection - giữ tất cả
      - reasoning:                   phân tích narrative - giữ tất cả

    REPLACE (new đè old, KHÔNG union):
      - tactics, techniques, subtechniques: ATT&CK rất dễ bị AI bịa.
        Lấy bản mới làm authoritative để extras cũ được loại bỏ tự nhiên.
        Fallback về old nếu new trả rỗng (an toàn hơn xoá trắng).
      - entry_vector, execution_mechanism (top-level + nested):
        Replace nếu new có giá trị. Đây là 2 field MANDATORY cho Sigma
        generation, cần lấy giá trị cuối cùng từ retry.
    """
    merged = {**old, **new}

    # --- Group A: UNION ---
    # Fields where additive union is correct (descriptive content, not
    # authoritative claims about the exploit). For `evasive_indicators` and
    # `reasoning`, we also filter out the literal "none" placeholder that
    # the LLM emits as a default - this is critical because if both attempts
    # return ["none"], the union would still be ["none"], but the field is
    # semantically empty.
    NONE_PLACEHOLDER_FIELDS = {"evasive_indicators", "reasoning"}
    UNION_FIELDS = {
        # key: (path_to_dict, source_subkey)
        "mandatory_behaviors": ("technical_analysis", "technical_analysis"),
        "exploit_requirements": ("technical_analysis", "technical_analysis"),
        "mapping_reasons": ("attack_mapping", "attack_mapping"),
        "evasive_indicators": ("technical_analysis", "technical_analysis"),
        "reasoning": ("technical_analysis", "technical_analysis"),
    }
    for key, (_, source) in UNION_FIELDS.items():
        if source == "technical_analysis":
            old_list = (old.get("technical_analysis") or {}).get(key) or []
            new_list = (new.get("technical_analysis") or {}).get(key) or []
            target = merged.setdefault("technical_analysis", {})
        else:  # attack_mapping
            old_list = (old.get("attack_mapping") or {}).get(key) or []
            new_list = (new.get("attack_mapping") or {}).get(key) or []
            target = merged.setdefault("attack_mapping", {})
        # Guard: AI có thể trả scalar/None thay vì list
        old_list = old_list if isinstance(old_list, list) else []
        new_list = new_list if isinstance(new_list, list) else []
        combined = sorted(set(old_list + new_list))
        # Filter literal "none" placeholder for fields where it is semantically empty
        if key in NONE_PLACEHOLDER_FIELDS:
            combined = [x for x in combined if str(x).lower().strip() != "none"]
        target[key] = combined

    # --- Group B: REPLACE (ATT&CK) ---
    REPLACE_ATTACK_FIELDS = ("tactics", "techniques", "subtechniques")
    for key in REPLACE_ATTACK_FIELDS:
        new_list = (new.get("attack_mapping") or {}).get(key)
        old_list = (old.get("attack_mapping") or {}).get(key)
        # Chỉ replace nếu new trả list hợp lệ + có ít nhất 1 item.
        # Nếu new rỗng/None → fallback về old (không xoá trắng).
        if isinstance(new_list, list) and new_list:
            merged.setdefault("attack_mapping", {})[key] = sorted(set(new_list))
        elif isinstance(old_list, list) and old_list:
            # new rỗng → giữ old (an toàn)
            merged.setdefault("attack_mapping", {})[key] = sorted(set(old_list))
        # else: cả 2 đều rỗng → không set key (giữ nguyên)

    # --- observable_side_effects: UNION ---
    old_obs = ((old.get("technical_analysis") or {}).get("attack_flow") or {}).get("observable_side_effects") or []
    new_obs = ((new.get("technical_analysis") or {}).get("attack_flow") or {}).get("observable_side_effects") or []
    old_obs = old_obs if isinstance(old_obs, list) else []
    new_obs = new_obs if isinstance(new_obs, list) else []
    merged_obs = sorted(set(old_obs + new_obs))
    (merged.setdefault("technical_analysis", {}).setdefault("attack_flow", {}))["observable_side_effects"] = merged_obs

    # --- entry_vector / execution_mechanism: REPLACE nếu new có giá trị ---
    for field in ("entry_vector", "execution_mechanism"):
        new_val = (new.get("technical_analysis") or {}).get(field)
        if new_val:
            tech_target = merged.setdefault("technical_analysis", {})
            flow_target = tech_target.setdefault("attack_flow", {})
            tech_target[field] = new_val
            flow_target[field] = new_val

    return merged
