"""Data flow helpers - thao tác trên dict thuần (không Pydantic).

Dùng bởi orchestrator để: convert dict → Pydantic, sanitize placeholder
("none"/"n/a"/"unknown") trong AI output, backfill `evasive_indicators`
theo CWE family khi AI trống.
"""
from __future__ import annotations

from typing import Any

from src.domain.models.attack import (
    AttackFlow,
    AttackMapping,
    CWEMetadata,
    TechnicalAnalysis,
)
from src.domain.models.vulnerability_class import VulnerabilityClass


# Pydantic <-> dict conversions
def _ai_dict_to_pydantic(
    data: dict[str, Any], base_tech: TechnicalAnalysis, base_attack: AttackMapping
) -> tuple[TechnicalAnalysis, AttackMapping]:
    """Convert dict (intermediate AI output) → Pydantic. Chỗ duy nhất build Pydantic từ dict."""
    tech_dict = data.get("technical_analysis") or {}
    atk_dict = data.get("attack_mapping") or {}

    # CWE metadata
    cwe_meta_raw = tech_dict.get("cwe_metadata")
    cwe_meta = None
    if isinstance(cwe_meta_raw, dict):
        # Normalize cwe_id (singular) -> cwe_ids (list) — AI đôi khi trả sai dạng
        if "cwe_id" in cwe_meta_raw and "cwe_ids" not in cwe_meta_raw:
            single = cwe_meta_raw.pop("cwe_id")
            cwe_meta_raw["cwe_ids"] = [single] if single else []
        if "cwe_name" in cwe_meta_raw and "cwe_names" not in cwe_meta_raw:
            single_name = cwe_meta_raw.pop("cwe_name")
            cwe_meta_raw["cwe_names"] = [single_name] if single_name else []
        cwe_meta = CWEMetadata(**cwe_meta_raw)

    # AttackFlow: ưu tiên nested, fallback top-level
    flow_dict = tech_dict.get("attack_flow") or {}
    attack_flow = AttackFlow(
        entry_vector=flow_dict.get("entry_vector") or tech_dict.get("entry_vector"),
        execution_mechanism=flow_dict.get("execution_mechanism") or tech_dict.get("execution_mechanism"),
        observable_side_effects=flow_dict.get("observable_side_effects") or [],
    )

    # Coerce vulnerability_class — AI có thể trả "VulnerabilityClass.X" hoặc typo
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
        family=tech_dict.get("family") or getattr(base_tech, "family", None),
        signature=tech_dict.get("signature") or getattr(base_tech, "signature", None),
        extracted_keywords=tech_dict.get("extracted_keywords")
        or getattr(base_tech, "extracted_keywords", None),
        vulnerability_type=tech_dict.get("vulnerability_type"),
        vulnerability_class=vc,
        exploit_vector=tech_dict.get("exploit_vector"),
        pre_auth=tech_dict.get("pre_auth")
        if "pre_auth" in tech_dict
        else getattr(base_tech, "pre_auth", None),
        remote_exploitable=tech_dict.get("remote_exploitable")
        if "remote_exploitable" in tech_dict
        else getattr(base_tech, "remote_exploitable", None),
        exploit_complexity=tech_dict.get("exploit_complexity"),
        confidence=tech_dict.get("confidence") or getattr(base_tech, "confidence", None),
        likely_outcome=tech_dict.get("likely_outcome") or getattr(base_tech, "likely_outcome", None),
        mandatory_behaviors=tech_dict.get("mandatory_behaviors") or None,
        evasive_indicators=tech_dict.get("evasive_indicators") or None,
        exploit_requirements=tech_dict.get("exploit_requirements") or None,
        reasoning=tech_dict.get("reasoning") or None,
        analysis_confidence=tech_dict.get("analysis_confidence")
        or getattr(base_tech, "analysis_confidence", None),
        classification_reason=tech_dict.get("classification_reason")
        or getattr(base_tech, "classification_reason", None),
        behavior_reason=tech_dict.get("behavior_reason")
        or getattr(base_tech, "behavior_reason", None),
        cwe_metadata=cwe_meta,
        attack_flow=attack_flow,
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
        confidence=atk_dict.get("confidence") or getattr(base_attack, "confidence", None),
        mapping_reasons=atk_dict.get("mapping_reasons") or None,
        attack_mapping_confidence=atk_dict.get("attack_mapping_confidence")
        or atk_dict.get("confidence")
        or getattr(base_attack, "attack_mapping_confidence", None),
        validation_warnings=atk_dict.get("validation_warnings") or None,
        dropped_tactics=atk_dict.get("dropped_tactics") or None,
        dropped_techniques=atk_dict.get("dropped_techniques") or None,
        dropped_subtechniques=atk_dict.get("dropped_subtechniques") or None,
        ai_used=True,
        ai_retry_count=getattr(base_attack, "ai_retry_count", 0),
        ai_model=ai_model,
        ai_models_used=ai_models_used,
    )
    return tech_analysis, attack_mapping


# Sanitize placeholder tokens từ AI output
_PLACEHOLDER_TOKENS = frozenset({"none", "n/a", "unknown"})


def _normalize_none_placeholders(ai_data: dict[str, Any]) -> dict[str, Any]:
    """Convert None / ["none"] placeholders từ AI thành empty list / None.

    Groq đôi khi trả `techniques = null`, `evasive_indicators = ["none"]`,
    `mapping_reasons = ["none"]`. Normalize để Pydantic build không crash
    và downstream filter không sót.
    """
    tech = ai_data.get("technical_analysis") or {}
    atk = ai_data.get("attack_mapping") or {}
    flow = tech.get("attack_flow") or {}

    # List field null → empty list
    for key in ("techniques", "subtechniques", "tactics"):
        if atk.get(key) is None:
            atk[key] = []
        if not isinstance(atk.get(key), list):
            atk[key] = [atk[key]] if atk.get(key) else []
        atk[key] = [x for x in atk[key] if str(x).lower().strip() not in _PLACEHOLDER_TOKENS]

    # Filter "none" placeholder cho behavioral fields
    for key in ("evasive_indicators", "mandatory_behaviors", "exploit_requirements"):
        raw = tech.get(key) or []
        if isinstance(raw, list):
            tech[key] = [x for x in raw if str(x).lower().strip() not in _PLACEHOLDER_TOKENS]
        elif raw and str(raw).lower().strip() in _PLACEHOLDER_TOKENS:
            tech[key] = []

    for key in ("reasoning", "classification_reason", "behavior_reason", "extracted_keywords"):
        raw = tech.get(key)
        if isinstance(raw, list):
            tech[key] = [x for x in raw if str(x).lower().strip() not in _PLACEHOLDER_TOKENS]
        elif raw and str(raw).lower().strip() in _PLACEHOLDER_TOKENS:
            tech[key] = []

    # Backfill evasive_indicators cho memory-corruption / code-injection CWE khi AI trống
    cwe_meta = tech.get("cwe_metadata") or {}
    cwe_ids = cwe_meta.get("cwe_ids") or []
    if not tech.get("evasive_indicators"):
        tech["evasive_indicators"] = _default_evasive_indicators_for_cwe(cwe_ids)

    raw = atk.get("mapping_reasons")
    if isinstance(raw, list):
        atk["mapping_reasons"] = [x for x in raw if str(x).lower().strip() not in _PLACEHOLDER_TOKENS]
    elif raw and str(raw).lower().strip() in _PLACEHOLDER_TOKENS:
        atk["mapping_reasons"] = []

    # observable_side_effects: không filter "none" (có thể legitimate)
    if flow.get("observable_side_effects") is None:
        flow["observable_side_effects"] = []

    return ai_data


# Backfill evasive_indicators theo CWE family khi AI trống

_EVASIVE_DEFAULTS_BY_CWE: dict[str, list[str]] = {
    "CWE-787": ["ROP chains to bypass DEP", "ASLR bypass via info leak",
                "heap spraying for shellcode placement"],
    "CWE-125": ["ROP chains", "ASLR bypass", "info leak via OOB read"],
    "CWE-416": ["heap grooming / feng shui", "UAF race condition timing"],
    "CWE-119": ["ROP chains", "stack pivoting", "shellcode encoding"],
    "CWE-190": ["integer overflow edge case probing"],
    "CWE-94": [
        "string obfuscation (e.g. eval(StrReverse(...)))",
        "base64/URL encoding of payload bytes",
        "comment insertion to break regex WAF signatures",
    ],
    "CWE-917": [
        "Unicode escape encoding (\\u00XX) of special chars to bypass string-based WAF",
        "OGNL/SpEL sandbox bypass via context manipulation (e.g. allowStaticMethodAccess=true)",
        "nested expression expansion to evade parser-differential detection",
    ],
    "CWE-1336": [
        "template syntax variations (${...}, {{...}}, <%...%>) to bypass WAF signatures",
        "comment/sandbox escape via #{...} or {% raw %} tricks",
        "encoding/obfuscation of template directives to evade static analysis",
    ],
    "_web_default": [
        "HTTP chunked transfer encoding to bypass length-based WAF",
        "URL/hex encoding of payload bytes",
        "header obfuscation / parser differential",
    ],
    "_code_injection_default": [
        "HTTP parameter encoding to bypass WAF signature",
        "case manipulation of keywords (e.g. oGnL vs OGNL)",
        "string concatenation / char-code obfuscation of payload",
    ],
}

# Canonical CWE family sets — dùng bởi exploit_classifier + Step 2 validation.
_MEMORY_CORRUPTION_CWES = frozenset({"CWE-787", "CWE-125", "CWE-416", "CWE-119", "CWE-190"})

# Code-injection: generic (94/95/96) + EL injection (917) + template (1336)
_CODE_INJECTION_CWES = frozenset({
    "CWE-94", "CWE-95", "CWE-96", "CWE-917", "CWE-1336",
})


def _default_evasive_indicators_for_cwe(cwe_ids: list[str] | None) -> list[str]:
    if not cwe_ids:
        return []
    cwe_set = set(cwe_ids)
    out: list[str] = []
    for cwe in cwe_ids:
        out.extend(_EVASIVE_DEFAULTS_BY_CWE.get(cwe, []))
    if cwe_set & _MEMORY_CORRUPTION_CWES:
        out.extend(_EVASIVE_DEFAULTS_BY_CWE["_web_default"])
    if cwe_set & _CODE_INJECTION_CWES:
        out.extend(_EVASIVE_DEFAULTS_BY_CWE["_code_injection_default"])
    return out
