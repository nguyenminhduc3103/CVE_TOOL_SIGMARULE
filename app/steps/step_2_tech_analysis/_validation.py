"""Field-level validation cho Step 2 orchestrator.

So với _validate_ai_output (cũ chỉ check ATT&CK techniques), helper này
validate TỪNG FIELD trong dict AI output:
  - TTP existence (whitelist) + semantic match với CVSS / description
  - List field không None / không ["none"]
  - String field không None / không rỗng
  - Per-field reason cho partial-fill retry

Step 2 có 2 lớp validation (format + semantic). KHÔNG có lớp 3 "Sigma rule
validation" - đó là việc step 3.
"""
from __future__ import annotations

import logging
from typing import Any

from app.steps.step_2_tech_analysis.rule_based.attack_validator import (
    filter_attack_mapping,
    is_known_ttp,
    validate_against_cve_context,
    validate_ttp_list,
)

logger = logging.getLogger(__name__)


# Sentinel "none"/"unknown" placeholders AI hay trả về.
_PLACEHOLDER_TOKENS: frozenset[str] = frozenset({
    "none", "n/a", "unknown", "null", "tbd", "todo",
})


def _is_placeholder(value: Any) -> bool:
    """Check value có phải placeholder 'none'/'unknown' không."""
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip().lower() in _PLACEHOLDER_TOKENS
    return False


def _list_has_only_placeholders(value: Any) -> bool:
    """Check list chỉ chứa placeholder strings (or empty)."""
    if not isinstance(value, list) or not value:
        return True
    return all(_is_placeholder(x) for x in value)


def _validate_ttp_field(
    techniques: list[str] | None,
    tactics: list[str] | None,
    subtechniques: list[str] | None,
    cvss_vector: str | None,
    description: str | None,
) -> dict[str, Any]:
    """Validate ATT&CK fields (lớp 1 format + whitelist + lớp 2 semantic).

    Returns:
        {
            "valid": bool,
            "valid_techniques": [...],
            "valid_tactics": [...],
            "valid_subtechniques": [...],
            "invalid_techniques": [...],
            "dropped_semantic": [...],
            "reason": str | None,  # lý do invalid (None nếu valid)
        }
    """
    # Lớp 1: format + whitelist
    ttp_result = validate_ttp_list(tactics, techniques, subtechniques)
    valid_tactics = ttp_result["valid_tactics"]
    valid_techniques_pre = ttp_result["valid_techniques"]
    valid_subtechniques = ttp_result["valid_subtechniques"]
    invalid_techniques = ttp_result["invalid_techniques"]
    invalid_tactics = ttp_result["invalid_tactics"]

    # Lớp 2: semantic (mâu thuẫn context CVE)
    sem = validate_against_cve_context(
        techniques=valid_techniques_pre,
        cvss_vector=cvss_vector,
        description=description,
    )
    valid_techniques = sem["kept"]
    dropped_semantic = sem["dropped"]

    # Quyết định valid: có ít nhất 1 technique còn lại sau cả 2 lớp
    has_valid = bool(valid_techniques)
    reason: str | None = None
    if not has_valid:
        if invalid_techniques:
            reason = (
                f"all techniques invalid (whitelist): {invalid_techniques}. "
                f"Use valid MITRE IDs from the whitelist."
            )
        elif dropped_semantic:
            reason = (
                f"all techniques dropped by semantic validation: "
                f"{dropped_semantic}. Reason: {sem.get('dropped_reasons', {})}. "
                f"Match techniques to CVE context (CVSS vector + description)."
            )
        else:
            reason = (
                "techniques field is empty or None. Provide at least 1 valid "
                "MITRE ATT&CK technique (e.g. T1190, T1059) supported by the CVE."
            )

    return {
        "valid": has_valid,
        "valid_techniques": valid_techniques,
        "valid_tactics": valid_tactics,
        "valid_subtechniques": valid_subtechniques,
        "invalid_techniques": invalid_techniques,
        "invalid_tactics": invalid_tactics,
        "dropped_semantic": dropped_semantic,
        "reason": reason,
    }


def _validate_list_field(value: Any, field_name: str, *, allow_empty: bool = False) -> dict[str, Any]:
    """Validate 1 list field chung (mapping_reasons, mandatory_behaviors, ...).

    Args:
        value: giá trị AI trả (có thể None, list, scalar).
        field_name: tên field (cho error message).
        allow_empty: True nếu empty list OK (vd observable_side_effects).

    Returns:
        {"valid": bool, "value": [...], "reason": str | None}
    """
    if value is None:
        if allow_empty:
            return {"valid": True, "value": [], "reason": None}
        return {
            "valid": False, "value": [],
            "reason": f"{field_name} is None. Provide at least 1 meaningful item.",
        }
    if not isinstance(value, list):
        return {
            "valid": False, "value": [],
            "reason": f"{field_name} must be a list, got {type(value).__name__}.",
        }
    cleaned = [x for x in value if not _is_placeholder(x)]
    if not cleaned and not allow_empty:
        return {
            "valid": False, "value": [],
            "reason": (
                f"{field_name} contains only placeholder values ('none'/'unknown'). "
                f"Provide at least 1 concrete item."
            ),
        }
    return {"valid": True, "value": cleaned, "reason": None}


def _validate_string_field(value: Any, field_name: str) -> dict[str, Any]:
    """Validate 1 string field (entry_vector, execution_mechanism).

    Returns:
        {"valid": bool, "value": str | None, "reason": str | None}
    """
    if _is_placeholder(value):
        return {
            "valid": False, "value": None,
            "reason": (
                f"{field_name} is missing or placeholder. Describe how the "
                f"attacker reaches/runs the exploit."
            ),
        }
    if not isinstance(value, str):
        return {
            "valid": False, "value": None,
            "reason": f"{field_name} must be a string.",
        }
    text = value.strip()
    if not text:
        return {
            "valid": False, "value": None,
            "reason": f"{field_name} is empty.",
        }
    return {"valid": True, "value": text, "reason": None}


def validate_field_level(
    data: dict[str, Any],
    cvss_vector: str | None,
    description: str | None,
) -> dict[str, Any]:
    """Validate TỪNG FIELD trong dict AI output (per-field, partial-fill ready).

    Mỗi field được đánh giá độc lập:
      - valid=True  → giữ nguyên
      - valid=False → set None + ghi reason cho retry feedback

    Returns:
        {
            "valid": bool,                # True nếu TẤT CẢ field valid
            "invalid_fields": {           # dict field_path → reason
                "attack_mapping.techniques": "...",
                "technical_analysis.entry_vector": "...",
                ...
            },
            "validated_data": dict,       # data với field invalid đã set None,
                                          # field valid đã được clean/normalize
            "ttp_validation": {...},      # chi tiết TTP validation
        }
    """
    atk = data.get("attack_mapping") or {}
    tech = data.get("technical_analysis") or {}
    flow = tech.get("attack_flow") or {}

    invalid_fields: dict[str, str] = {}

    # --- ATT&CK fields ---
    ttp = _validate_ttp_field(
        techniques=atk.get("techniques"),
        tactics=atk.get("tactics"),
        subtechniques=atk.get("subtechniques"),
        cvss_vector=cvss_vector,
        description=description,
    )
    if not ttp["valid"]:
        invalid_fields["attack_mapping.techniques"] = ttp["reason"] or "invalid"

    # --- mapping_reasons ---
    mr = _validate_list_field(atk.get("mapping_reasons"), "mapping_reasons")
    if not mr["valid"]:
        invalid_fields["attack_mapping.mapping_reasons"] = mr["reason"]

    # --- mandatory_behaviors ---
    mb = _validate_list_field(
        tech.get("mandatory_behaviors"), "mandatory_behaviors"
    )
    if not mb["valid"]:
        invalid_fields["technical_analysis.mandatory_behaviors"] = mb["reason"]

    # --- evasive_indicators (optional: empty list OK) ---
    ei = _validate_list_field(
        tech.get("evasive_indicators"), "evasive_indicators", allow_empty=True
    )
    if not ei["valid"]:
        invalid_fields["technical_analysis.evasive_indicators"] = ei["reason"]

    # --- entry_vector (string, MANDATORY cho Sigma generation) ---
    ev = _validate_string_field(tech.get("entry_vector"), "entry_vector")
    if not ev["valid"]:
        invalid_fields["technical_analysis.entry_vector"] = ev["reason"]

    # --- execution_mechanism (string, MANDATORY cho Sigma generation) ---
    em = _validate_string_field(tech.get("execution_mechanism"), "execution_mechanism")
    if not em["valid"]:
        invalid_fields["technical_analysis.execution_mechanism"] = em["reason"]

    # --- observable_side_effects (list, optional) ---
    ose = _validate_list_field(
        flow.get("observable_side_effects"), "observable_side_effects", allow_empty=True
    )
    if not ose["valid"]:
        invalid_fields["technical_analysis.attack_flow.observable_side_effects"] = ose["reason"]

    # --- reasoning (list, optional) ---
    rs = _validate_list_field(tech.get("reasoning"), "reasoning", allow_empty=True)
    if not rs["valid"]:
        invalid_fields["technical_analysis.reasoning"] = rs["reason"]

    # Build validated_data (giữ nguyên cấu trúc, chỉ clean value)
    validated_data = {
        **data,
        "attack_mapping": {
            **atk,
            "tactics": ttp["valid_tactics"] or None,
            "techniques": ttp["valid_techniques"] or None,
            "subtechniques": ttp["valid_subtechniques"] or None,
            "mapping_reasons": mr["value"] if mr["valid"] else None,
        },
        "technical_analysis": {
            **tech,
            "mandatory_behaviors": mb["value"] if mb["valid"] else None,
            "evasive_indicators": ei["value"] if ei["valid"] else None,
            "entry_vector": ev["value"] if ev["valid"] else None,
            "execution_mechanism": em["value"] if em["valid"] else None,
            "reasoning": rs["value"] if rs["valid"] else None,
            "attack_flow": {
                **flow,
                "entry_vector": ev["value"] if ev["valid"] else None,
                "execution_mechanism": em["value"] if em["valid"] else None,
                "observable_side_effects": ose["value"] if ose["valid"] else [],
            },
        },
    }

    return {
        "valid": not invalid_fields,
        "invalid_fields": invalid_fields,
        "validated_data": validated_data,
        "ttp_validation": ttp,
    }


def _apply_partial_fill(base: dict[str, Any], fill: dict[str, Any], invalid_paths: dict[str, str]) -> dict[str, Any]:
    """Partial-fill: với mỗi field invalid trong base, lấy từ fill.

    Field nào valid trong base → giữ nguyên, KHÔNG động vào.
    Field nào invalid → lấy từ fill (nếu fill có).

    KHÔNG merge dict-style (Union/Replace). Chỉ pointwise replacement
    theo path. Đây là fix cho wipeout bug CVE-2023-22515.
    """
    if not invalid_paths:
        return base

    result = _deep_copy_dict(base)

    for field_path in invalid_paths.keys():
        base_val = _get_path(base, field_path)
        fill_val = _get_path(fill, field_path)
        if fill_val is not None:
            _set_path(result, field_path, fill_val)

    return result


def _get_path(data: dict[str, Any], path: str) -> Any:
    """Get giá trị tại dotted path (vd 'attack_mapping.techniques')."""
    parts = path.split(".")
    cur: Any = data
    for p in parts:
        if isinstance(cur, dict):
            cur = cur.get(p)
        else:
            return None
    return cur


def _set_path(data: dict[str, Any], path: str, value: Any) -> None:
    """Set giá trị tại dotted path, tạo intermediate dicts nếu thiếu."""
    parts = path.split(".")
    cur = data
    for p in parts[:-1]:
        if not isinstance(cur.get(p), dict):
            cur[p] = {}
        cur = cur[p]
    cur[parts[-1]] = value


def _deep_copy_dict(d: dict[str, Any]) -> dict[str, Any]:
    """Shallow copy đủ sâu cho nested dict structure của AI output.

    Chỉ copy dict layer, các value (list/str/int) dùng reference — vì
    validated_data đã clean placeholder, không cần deep copy cho value.
    """
    out: dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out[k] = _deep_copy_dict(v)
        else:
            out[k] = v
    return out
