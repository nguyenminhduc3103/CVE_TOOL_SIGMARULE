from __future__ import annotations

from app.analysis.cwe_mapper import CWEProfile
from app.types.vulnerability_class import VulnerabilityClass


BEHAVIOR_ATTACK_GRAPH: dict[str, dict[str, tuple[str, ...]]] = {
    "process_creation": {
        "tactics": ("TA0002",),
        "techniques": ("T1059",),
        "subtechniques": ("T1059.004",),
    },
    "privilege_escalation": {
        "tactics": ("TA0004",),
        "techniques": ("T1068",),
        "subtechniques": (),
    },
    "webshell_drop": {
        "tactics": ("TA0003", "TA0002"),
        "techniques": ("T1505.003", "T1059"),
        "subtechniques": ("T1505.003",),
    },
    "network_callback": {
        "tactics": ("TA0011",),
        "techniques": ("T1071",),
        "subtechniques": ("T1071.001",),
    },
    "tool_download": {
        "tactics": ("TA0011",),
        "techniques": ("T1105",),
        "subtechniques": (),
    },
    "public_facing_exploit": {
        "tactics": ("TA0001",),
        "techniques": ("T1190",),
        "subtechniques": (),
    },
    "image_load": {
        "tactics": ("TA0004",),
        "techniques": ("T1574",),
        "subtechniques": ("T1574.001",),
    },
    "web_request": {
        "tactics": ("TA0001",),
        "techniques": ("T1190",),
        "subtechniques": (),
    },
    "network_connection": {
        "tactics": ("TA0011",),
        "techniques": ("T1046",),
        "subtechniques": (),
    },
}

ATTACK_TECHNIQUE_MAP = BEHAVIOR_ATTACK_GRAPH


VULNERABILITY_CLASS_ATTACK_GRAPH: dict[VulnerabilityClass, tuple[str, ...]] = {
    VulnerabilityClass.DESERIALIZATION: ("T1059", "T1190"),
    VulnerabilityClass.COMMAND_INJECTION: ("T1059",),
    VulnerabilityClass.PATH_TRAVERSAL: ("T1190",),
    VulnerabilityClass.FILE_UPLOAD: ("T1505.003",),
    VulnerabilityClass.SSRF: ("T1046", "T1071"),
    VulnerabilityClass.AUTH_BYPASS: ("T1190",),
    VulnerabilityClass.PRIVILEGE_ESCALATION: ("T1068",),
    VulnerabilityClass.CODE_INJECTION: ("T1059",),
    VulnerabilityClass.WEBSHELL_DROP: ("T1505.003", "T1059"),
    VulnerabilityClass.INFORMATION_DISCLOSURE: ("T1190",),
    VulnerabilityClass.REMOTE_CODE_EXECUTION: ("T1059", "T1190"),
    VulnerabilityClass.SQL_INJECTION: ("T1190",),
}


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def map_attack(
    ontology_behaviors: list[str],
    vulnerability_class: VulnerabilityClass | None,
    cwe_profiles: list[CWEProfile],
    classifier: dict[str, str | bool | None],
    ontology_confidence: float | None = None,
) -> dict[str, list[str] | float]:
    tactics: list[str] = []
    techniques: list[str] = []
    subtechniques: list[str] = []
    mapping_reasons: list[str] = []

    behaviors = ontology_behaviors or []

    if vulnerability_class and vulnerability_class in VULNERABILITY_CLASS_ATTACK_GRAPH:
        for technique in VULNERABILITY_CLASS_ATTACK_GRAPH[vulnerability_class]:
            if technique not in techniques:
                techniques.append(technique)
        mapping_reasons.append(f"vulnerability_class:{vulnerability_class.value}")

    if behaviors:
        for behavior in behaviors:
            mapped = BEHAVIOR_ATTACK_GRAPH.get(behavior)
            if not mapped:
                continue
            tactics.extend(mapped["tactics"])
            techniques.extend(mapped["techniques"])
            subtechniques.extend(mapped["subtechniques"])
            mapping_reasons.append(f"behavior:{behavior}")
    else:
        fallback_map: dict[str, dict[str, tuple[str, ...]]] = {
            "CWE-78": {"tactics": ("TA0002",), "techniques": ("T1059",), "subtechniques": ("T1059.004",)},
            "CWE-89": {"tactics": ("TA0001",), "techniques": ("T1190",), "subtechniques": ()},
            "CWE-434": {"tactics": ("TA0003", "TA0002"), "techniques": ("T1505.003", "T1059"), "subtechniques": ("T1505.003",)},
            "CWE-502": {"tactics": ("TA0001", "TA0002"), "techniques": ("T1190", "T1059"), "subtechniques": ()},
            "CWE-918": {"tactics": ("TA0001", "TA0011"), "techniques": ("T1190", "T1046"), "subtechniques": ()},
        }
        for profile in cwe_profiles:
            mapped = fallback_map.get(profile.cwe_id)
            if not mapped:
                continue
            tactics.extend(mapped["tactics"])
            techniques.extend(mapped["techniques"])
            subtechniques.extend(mapped["subtechniques"])
            mapping_reasons.append(f"{profile.cwe_id} fallback ATT&CK mapping")

    if not techniques and classifier.get("remote_exploitable") and classifier.get("pre_auth"):
        if "T1190" not in techniques:
            techniques.append("T1190")
        mapping_reasons.append("CVSS indicates public-facing pre-auth exploitation")

    if "process_creation" in behaviors and "T1059" not in techniques:
        techniques.append("T1059")
    if "web_request" in behaviors and "T1190" not in techniques:
        techniques.append("T1190")
    if "privilege_escalation" in behaviors and "T1068" not in techniques:
        techniques.append("T1068")

    confidence = 0.2 if behaviors else 0.15
    confidence += 0.1 if vulnerability_class and vulnerability_class != VulnerabilityClass.UNKNOWN else 0.0
    confidence += 0.14 * len(set(behaviors))
    confidence += 0.06 * min(len(cwe_profiles), 2) if not behaviors else 0.0
    confidence += 0.1 if classifier.get("remote_exploitable") else 0.0
    confidence += 0.1 if classifier.get("pre_auth") else 0.0
    confidence = min(confidence, 0.95)
    if ontology_confidence is not None:
        confidence = min(0.95, round((confidence + ontology_confidence) / 2, 2))

    return {
        "tactics": _unique(tactics),
        "techniques": _unique(techniques),
        "subtechniques": _unique(subtechniques),
        "confidence": round(min(confidence, 0.95), 2),
        "mapping_reasons": _unique(mapping_reasons),
    }
