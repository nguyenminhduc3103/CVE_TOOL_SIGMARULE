"""Data flow helpers - thao tác trên dict thuần (không Pydantic). Dùng bởi orchestrator để convert dict → Pydantic, sanitize placeholder."""
from __future__ import annotations

from typing import Any

from src.domain.models.attack import (
    AttackMapping,
    TechnicalAnalysis,
)


# Canonical CWE family sets — dùng bởi exploit_classifier (server-side heuristic).
_CODE_INJECTION_CWES = frozenset({
    "CWE-94", "CWE-95", "CWE-96", "CWE-917", "CWE-1336",
})


def _ai_dict_to_pydantic(
    data: dict[str, Any], base_tech: TechnicalAnalysis, base_attack: AttackMapping
) -> tuple[TechnicalAnalysis, AttackMapping]:
    """Convert dict (intermediate AI output) → Pydantic. Chỗ duy nhất build Pydantic từ dict."""
    tech_dict = data.get("technical_analysis") or {}
    atk_dict = data.get("attack_mapping") or {}

    # Resolve ai_model — phải resolve trước khi construct Pydantic locals
    # (tech_analysis/attack_mapping không self-reference được trong initializer).
    metadata_raw = tech_dict.get("metadata")
    ai_model = (
        metadata_raw.get("ai_model")
        if isinstance(metadata_raw, dict)
        else None
    ) or getattr(base_tech, "ai_model", None) or getattr(base_attack, "ai_model", None)

    ai_models_used = (
        getattr(base_tech, "ai_models_used", None)
        or getattr(base_attack, "ai_models_used", None)
    )

    tech_analysis = TechnicalAnalysis(
        exploit_vector=tech_dict.get("exploit_vector") or getattr(base_tech, "exploit_vector", None),
        pre_auth=tech_dict.get("pre_auth")
        if "pre_auth" in tech_dict
        else getattr(base_tech, "pre_auth", None),
        remote_exploitable=tech_dict.get("remote_exploitable")
        if "remote_exploitable" in tech_dict
        else getattr(base_tech, "remote_exploitable", None),
        exploit_complexity=tech_dict.get("exploit_complexity") or getattr(base_tech, "exploit_complexity", None),
        confidence=tech_dict.get("confidence") or getattr(base_tech, "confidence", None),
        mandatory_behaviors=tech_dict.get("mandatory_behaviors") or None,
        evasive_indicators=tech_dict.get("evasive_indicators") or None,
        exploit_requirements=tech_dict.get("exploit_requirements") or None,
        reasoning=tech_dict.get("reasoning") or None,
        # Two-phase fields (Phase 1 output)
        execution_surface=tech_dict.get("execution_surface"),
        delivery_vector=tech_dict.get("delivery_vector"),
        user_interaction_required=tech_dict.get("user_interaction_required"),
        ai_used=True,
        ai_retry_count=getattr(base_tech, "ai_retry_count", 0),
        ai_model=ai_model,
        ai_models_used=ai_models_used,
    )

    attack_mapping = AttackMapping(
        tactics=atk_dict.get("tactics") or None,
        techniques=atk_dict.get("techniques") or None,
        subtechniques=atk_dict.get("subtechniques") or None,
        mapping_reasons=atk_dict.get("mapping_reasoning") or atk_dict.get("mapping_reasons") or None,
        # Phase 2B fields
        is_attack_chain=atk_dict.get("is_attack_chain"),
        attack_chain=atk_dict.get("attack_chain") or None,
        chain_reasoning=atk_dict.get("chain_reasoning") or None,
        confidence_level=atk_dict.get("confidence_level"),
        ai_used=True,
        ai_retry_count=getattr(base_attack, "ai_retry_count", 0),
        ai_model=ai_model,
        ai_models_used=ai_models_used,
    )
    return tech_analysis, attack_mapping


# Sanitize placeholder tokens từ AI output
_PLACEHOLDER_TOKENS = frozenset({"none", "n/a", "unknown"})


def _normalize_none_placeholders(ai_data: dict[str, Any]) -> dict[str, Any]:
    """Convert None / ["none"] placeholders từ AI thành empty list / None để Pydantic build không crash và downstream filter không sót."""
    tech = ai_data.get("technical_analysis") or {}
    atk = ai_data.get("attack_mapping") or {}

    # List field null → empty list (Phase 2 ATT&CK)
    for key in ("techniques", "subtechniques", "tactics"):
        if atk.get(key) is None:
            atk[key] = []
        if not isinstance(atk.get(key), list):
            atk[key] = [atk[key]] if atk.get(key) else []
        atk[key] = [x for x in atk[key] if str(x).lower().strip() not in _PLACEHOLDER_TOKENS]

    # Filter "none" placeholder cho behavioral fields (Phase 1)
    for key in ("evasive_indicators", "mandatory_behaviors", "exploit_requirements"):
        raw = tech.get(key) or []
        if isinstance(raw, list):
            tech[key] = [x for x in raw if str(x).lower().strip() not in _PLACEHOLDER_TOKENS]
        elif raw and str(raw).lower().strip() in _PLACEHOLDER_TOKENS:
            tech[key] = []

    # Filter "none" placeholder cho reasoning (Phase 1)
    raw = tech.get("reasoning")
    if isinstance(raw, list):
        tech["reasoning"] = [x for x in raw if str(x).lower().strip() not in _PLACEHOLDER_TOKENS]
    elif raw and str(raw).lower().strip() in _PLACEHOLDER_TOKENS:
        tech["reasoning"] = []

    raw = atk.get("mapping_reasons")
    if isinstance(raw, list):
        atk["mapping_reasons"] = [x for x in raw if str(x).lower().strip() not in _PLACEHOLDER_TOKENS]
    elif raw and str(raw).lower().strip() in _PLACEHOLDER_TOKENS:
        atk["mapping_reasons"] = []

    return ai_data