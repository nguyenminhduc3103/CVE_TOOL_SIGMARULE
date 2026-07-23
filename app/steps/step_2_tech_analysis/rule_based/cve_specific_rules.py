"""CVE-specific rules for major vulnerabilities (Hybrid approach).

These rules are evidence-based: they only apply when the CVE description
or Phase 1 output contains specific indicators.

Usage:
    from app.steps.step_2_tech_analysis.rule_based.cve_specific_rules import (
        CVE_ATTACK_CHAIN_RULES,
        apply_cve_specific_rules,
    )
"""

from __future__ import annotations

from typing import TypedDict


class CVEAttackChainRule(TypedDict):
    """Structured attack chain rule for a specific CVE."""
    indicators: list[str]
    primary: list[str]
    secondary: dict[str, list[str]]


CVE_ATTACK_CHAIN_RULES: dict[str, CVEAttackChainRule] = {
    # =====================================
    # Log4j / JNDI Injection Family
    # =====================================
    "CVE-2021-44228": {
        "indicators": ["jndi", "log4j", "log4shell", "ldap", "remote lookup", "java"],
        "primary": ["T1190"],
        "secondary": {
            "execution": ["T1203"],
            "c2": ["T1105", "T1071.001"],
            "impact": [],
        },
    },
    "CVE-2021-45046": {
        "indicators": ["jndi", "log4j", "dos", "denial", "service"],
        "primary": ["T1190"],
        "secondary": {
            "execution": ["T1203"],
            "c2": ["T1105"],
            "impact": ["T1499.004"],
        },
    },
    "CVE-2021-45105": {
        "indicators": ["log4j", "dos", "denial", "infinite loop"],
        "primary": ["T1190"],
        "secondary": {
            "execution": [],
            "c2": [],
            "impact": ["T1499.004"],
        },
    },
    # =====================================
    # EternalBlue / SMB Exploitation Family
    # =====================================
    "CVE-2017-0144": {
        "indicators": ["smb", "eternalblue", "ransomware", "wannacry", "windows"],
        "primary": ["T1210"],
        "secondary": {
            "execution": ["T1059.003"],
            "c2": [],
            "impact": ["T1486"],
        },
    },
    "CVE-2017-0145": {
        "indicators": ["smb", "eternalromance", "exploit", "windows"],
        "primary": ["T1210"],
        "secondary": {
            "execution": ["T1059.003"],
            "c2": [],
            "impact": [],
        },
    },
    "CVE-2017-0146": {
        "indicators": ["smb", "exploit", "doublepulsar", "backdoor"],
        "primary": ["T1210"],
        "secondary": {
            "execution": ["T1059.003"],
            "c2": [],
            "impact": [],
        },
    },
    # =====================================
    # Exchange / ProxyLogon Family
    # =====================================
    "CVE-2021-26855": {
        "indicators": ["exchange", "proxylogon", "ssrf", "microsoft"],
        "primary": ["T1190"],
        "secondary": {
            "execution": ["T1059.003"],
            "c2": ["T1071.001"],
            "impact": [],
        },
    },
    "CVE-2021-26857": {
        "indicators": ["exchange", "insecure", "deserialization", "microsoft"],
        "primary": ["T1190"],
        "secondary": {
            "execution": ["T1203"],
            "c2": ["T1071.001"],
            "impact": [],
        },
    },
    "CVE-2021-27065": {
        "indicators": ["exchange", "webshell", "remote code", "microsoft"],
        "primary": ["T1190"],
        "secondary": {
            "execution": ["T1059.003"],
            "c2": [],
            "impact": [],
        },
    },
    # =====================================
    # ProxyShell Family
    # =====================================
    "CVE-2021-34473": {
        "indicators": ["exchange", "proxyshell", "ssrf", "microsoft"],
        "primary": ["T1190"],
        "secondary": {
            "execution": [],
            "c2": ["T1071.001"],
            "impact": [],
        },
    },
    # =====================================
    # Heartbleed / OpenSSL
    # =====================================
    "CVE-2014-0160": {
        "indicators": ["heartbleed", "openssl", "tls", "memory disclosure"],
        "primary": ["T1190"],
        "secondary": {
            "execution": [],
            "c2": [],
            "impact": [],
        },
    },
    # =====================================
    # Shellshock / Bash
    # =====================================
    "CVE-2014-6271": {
        "indicators": ["shellshock", "bash", "cgi", "environment variable"],
        "primary": ["T1190"],
        "secondary": {
            "execution": ["T1059.004"],
            "c2": [],
            "impact": [],
        },
    },
    # =====================================
    # Struts OGNL Injection
    # =====================================
    "CVE-2017-5638": {
        "indicators": ["struts", "ognl", " Jakarta", "rce"],
        "primary": ["T1190"],
        "secondary": {
            "execution": ["T1059.004"],
            "c2": [],
            "impact": [],
        },
    },
    # =====================================
    # Drupalgeddon
    # =====================================
    "CVE-2018-7600": {
        "indicators": ["drupal", "drupalgeddon", "php", "rce"],
        "primary": ["T1190"],
        "secondary": {
            "execution": ["T1059.004"],
            "c2": [],
            "impact": [],
        },
    },
    # =====================================
    # Spring4Shell
    # =====================================
    "CVE-2022-22965": {
        "indicators": ["spring4shell", "spring", "class", "databinding", "rce"],
        "primary": ["T1190"],
        "secondary": {
            "execution": ["T1203"],
            "c2": ["T1105"],
            "impact": [],
        },
    },
    # =====================================
    # Atlassian Confluence (CVE-2022-26134)
    # =====================================
    "CVE-2022-26134": {
        "indicators": ["confluence", "ognl", "atlassian", "rce"],
        "primary": ["T1190"],
        "secondary": {
            "execution": ["T1203"],
            "c2": [],
            "impact": [],
        },
    },
}


def apply_cve_specific_rules(
    cve_id: str,
    description: str,
    phase1_indicators: list[str],
) -> CVEAttackChainRule | None:
    """Apply CVE-specific rules if indicators match.

    Args:
        cve_id: CVE identifier (e.g., "CVE-2021-44228")
        description: CVE description from NVD
        phase1_indicators: List of indicators from Phase 1 output
                          (e.g., from mandatory_behaviors, evasive_indicators)

    Returns:
        CVEAttackChainRule if at least 2 indicators match, None otherwise.
    """
    if not cve_id:
        return None

    cve_id_lower = cve_id.lower()
    desc_lower = description.lower() if description else ""
    indicators_text = " ".join(phase1_indicators).lower() if phase1_indicators else ""
    combined = f"{desc_lower} {indicators_text}"

    for rule_cve, rule_data in CVE_ATTACK_CHAIN_RULES.items():
        rule_cve_lower = rule_cve.lower()
        # Check if CVE ID matches (handle CVE-YYYY-NNNNN patterns)
        if rule_cve_lower.replace("-", "") in cve_id_lower.replace("-", ""):
            # Check if indicators match
            matches = sum(
                1
                for indicator in rule_data["indicators"]
                if indicator in combined
            )
            # At least 2 indicators must match
            if matches >= 2:
                return rule_data

    return None


def flatten_two_tier_to_legacy(
    rule: CVEAttackChainRule,
) -> dict[str, list[str]]:
    """Flatten CVE-specific rule to legacy flat format for backward compatibility.

    Args:
        rule: CVEAttackChainRule from CVE_ATTACK_CHAIN_RULES

    Returns:
        Dict with legacy format: {tactics, techniques, subtechniques}
    """
    # Technique to Tactic mapping (MITRE ATT&CK v15)
    TECHNIQUE_TO_TACTICS: dict[str, list[str]] = {
        "T1190": ["TA0001"],
        "T1210": ["TA0008"],
        "T1133": ["TA0001"],
        "T1204": ["TA0002"],
        "T1068": ["TA0004"],
        "T1195": ["TA0001"],
        "T1611": ["TA0004", "TA0005"],
        "T1203": ["TA0002"],
        "T1059": ["TA0002"],
        "T1059.001": ["TA0002"],
        "T1059.003": ["TA0002"],
        "T1059.004": ["TA0002"],
        "T1059.006": ["TA0002"],
        "T1059.007": ["TA0002"],
        "T1071": ["TA0011"],
        "T1071.001": ["TA0011"],
        "T1105": ["TA0011"],
        "T1499": ["TA0040"],
        "T1499.004": ["TA0040"],
        "T1486": ["TA0040"],
        "T1489": ["TA0040"],
        "T1566": ["TA0001"],
        "T1189": ["TA0001"],
    }

    techniques: list[str] = list(rule["primary"])
    subtechniques: list[str] = []
    tactics: list[str] = []

    # Add secondary techniques
    secondary = rule.get("secondary", {})
    for exec_tech in secondary.get("execution", []):
        if exec_tech not in techniques:
            techniques.append(exec_tech)
    for c2_tech in secondary.get("c2", []):
        if c2_tech not in techniques:
            techniques.append(c2_tech)
    for impact_tech in secondary.get("impact", []):
        if impact_tech not in techniques:
            techniques.append(impact_tech)

    # Derive tactics from techniques
    for tech in techniques:
        mapped_tactics = TECHNIQUE_TO_TACTICS.get(tech, [])
        for t in mapped_tactics:
            if t not in tactics:
                tactics.append(t)

    return {
        "tactics": tactics,
        "techniques": techniques,
        "subtechniques": subtechniques,
    }
