"""Validate AI-emitted domains against KB whitelist.

L2 — kiểm tra domain có nằm trong 18 canonical domains không. Term không match
→ invalid + warning. AI emit alias (vd 'authentication') → resolve về canonical
('identity').

Refactor 2026-07: thay vì silently drop free-form terms (như `_SERVICE_TO_LOGSOURCE`
cũ), validator trả về warnings để reviewer thấy AI đoán sai ở đâu.
"""
from __future__ import annotations

from src.usecases.step_4_telemetry._knowledge import loader


def _build_alias_map(kb_domains: list[dict]) -> dict[str, str]:
    """Build {alias_lower: canonical_id}."""
    alias_map: dict[str, str] = {}
    for d in kb_domains:
        domain_id = d["id"]
        alias_map[domain_id.lower()] = domain_id
        for alias in d.get("aliases", []):
            alias_map[alias.lower()] = domain_id
    return alias_map


def validate_domains(
    domains: list[str] | None,
    semantic_tags: list[str] | None = None,
) -> tuple[list[str], list[str], list[str]]:
    """Validate AI-emitted domains.

    Args:
        domains: AI-emitted list of domain terms (canonical ID or alias).
        semantic_tags: Free-form tags (vd ['Netlogon', 'MachineAccount']). Tags
            không validate — chỉ warning nếu rỗng. Resolver dùng cho context.

    Returns:
        (valid_domains, invalid_domains, warnings)
        - valid_domains: list of canonical domain IDs (deduplicated, preserving order).
        - invalid_domains: terms không match bất kỳ canonical nào.
        - warnings: human-readable strings cho reviewer.
    """
    kb = loader.load_telemetry_domains()
    kb_domains = kb.get("domains", [])
    if not kb_domains:
        # KB rỗng / load fail → pass through mọi domain
        return list(domains or []), [], ["kb_empty:telemetry_domains"]

    alias_map = _build_alias_map(kb_domains)

    valid: list[str] = []
    invalid: list[str] = []
    warnings: list[str] = []

    for term in domains or []:
        normalized = term.strip().lower()
        if not normalized:
            continue
        resolved = alias_map.get(normalized)
        if resolved is None:
            invalid.append(term)
            warnings.append(f"unknown_domain:{term}")
            continue
        if resolved not in valid:
            valid.append(resolved)

    if domains and not valid:
        warnings.append("no_valid_domains:all_rejected")

    if semantic_tags is not None and len(semantic_tags) == 0:
        warnings.append("empty_semantic_tags")

    return valid, invalid, warnings