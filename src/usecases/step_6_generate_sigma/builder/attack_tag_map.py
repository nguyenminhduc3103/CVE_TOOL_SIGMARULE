"""ATT&CK tag map for Sigma rules.

Canonical tactic tags use dash form per the official Sigma Taxonomy Appendix
(https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-taxonomy-appendix.md):
"lowercase + replace spaces with dashes + prefix attack."
"""
from __future__ import annotations

# TA-id -> Sigma tactic tag slug (dash form).
TACTIC_SLUG_MAP: dict[str, str] = {
    "TA0043": "reconnaissance",
    "TA0042": "resource-development",
    "TA0001": "initial-access",
    "TA0002": "execution",
    "TA0003": "persistence",
    "TA0004": "privilege-escalation",
    "TA0005": "defense-evasion",
    "TA0006": "credential-access",
    "TA0007": "discovery",
    "TA0008": "lateral-movement",
    "TA0009": "collection",
    "TA0010": "exfiltration",
    "TA0011": "command-and-control",
    "TA0040": "impact",
}


def build_attack_tags(tactics: list[str], techniques: list[str]) -> list[str]:
    """Build Sigma attack tags from tactic + technique IDs.

    Tags are returned in insertion order, deduped:
      1. attack.<tactic_slug> for each tactic
      2. attack.t<NNNN> for each technique (lowercase t + digits)
    """
    tags: list[str] = []
    seen: set[str] = set()
    for tac in tactics or []:
        slug = TACTIC_SLUG_MAP.get(tac)
        if slug:
            tag = f"attack.{slug}"
            if tag not in seen:
                tags.append(tag)
                seen.add(tag)
    for tech in techniques or []:
        tag = f"attack.{str(tech).lower()}"
        if tag not in seen:
            tags.append(tag)
            seen.add(tag)
    return tags


__all__ = ["TACTIC_SLUG_MAP", "build_attack_tags"]
