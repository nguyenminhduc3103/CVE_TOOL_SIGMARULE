from __future__ import annotations


def decide_coverage(
    coverage_score: float,
    attack_overlap: float,
    logsource_overlap: float,
    behavior_overlap: float,
    cve_overlap: float,
) -> tuple[str, str]:
    if cve_overlap >= 1.0 and attack_overlap >= 0.8 and logsource_overlap >= 0.6 and behavior_overlap >= 0.6:
        return "OBSOLETE", "Existing rule already fully covers this CVE and behavior profile."
    if coverage_score >= 0.72 and (attack_overlap >= 0.5 or behavior_overlap >= 0.5):
        return "EXTEND", "Strong overlap indicates extending existing rule logic is sufficient."
    if coverage_score >= 0.35:
        return "SIMILAR", "Partial overlap found; use as similar baseline, but tune detection details."
    return "NEW", "Insufficient overlap; create a new Sigma rule."
