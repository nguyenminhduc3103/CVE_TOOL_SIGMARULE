from __future__ import annotations

import logging

from app.steps.step_2_tech_analysis._shared_engines.cwe_mapper import CWEProfile
from app.steps.step_2_tech_analysis._shared_engines.ontology_manager import (
    CveContext,
    OntologyManager,
)
from app.shared.types.vulnerability_class import VulnerabilityClass

logger = logging.getLogger(__name__)


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
        "techniques": ("T1071",),
        "subtechniques": ("T1071.001",),
    },
    "shell_spawn": {
        "tactics": ("TA0002",),  # Execution
        "techniques": ("T1059",),  # Command and Scripting Interpreter
        "subtechniques": ("T1059.004",),  # Unix Shell (most common CWE-78 target)
    },
    "file_read": {
        "tactics": ("TA0007",),  # Discovery
        "techniques": ("T1083",),  # File and Directory Discovery
        "subtechniques": (),
    },
    "data_exfiltration": {
        "tactics": ("TA0010",),  # Exfiltration
        "techniques": ("T1020", "T1114"),  # Automated Exfiltration + Email Collection
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
    cve_id: str | None = None,
    description: str | None = None,
    cvss_vector: str | None = None,
) -> dict[str, list[str] | float]:
    """Map CVE → ATT&CK tactics/techniques.

    PHASE 3 REFACTOR: Sử dụng OntologyManager (4-layer) làm SINGLE SOURCE
    OF TRUTH cho expected techniques.

    Trước: fallback_map hardcoded 5 CWE trong hàm này KHÁC với
    compute_ground_truth() → Source of Truth Mismatch.

    Sau: cả map_attack() và compute_ground_truth() đều dùng
    OntologyManager.resolve() → cùng expected techniques.

    Behavior/class mappings VẪN dùng (vì chúng capture rule-based
    inference ngoài ontology) nhưng giờ là BỔ SUNG, không phải
    thay thế.
    """
    tactics: list[str] = []
    techniques: list[str] = []
    subtechniques: list[str] = []
    mapping_reasons: list[str] = []

    behaviors = ontology_behaviors or []
    cwe_ids = tuple(p.cwe_id for p in cwe_profiles) if cwe_profiles else ()

    # ------------------------------------------------------------------
    # SINGLE SOURCE OF TRUTH: OntologyManager.resolve()
    # ------------------------------------------------------------------
    # Layer 1: CTID direct
    # Layer 2: CAPEC bridge (CWE → ATT&CK)
    # Layer 3: Whitelist fallback (8 core CWEs)
    # Layer 4: UNKNOWN → no techniques from this layer
    ctx = CveContext(
        cve_id=cve_id or "",
        description=description or "",
        cwe_ids=cwe_ids,
        cvss_vector=cvss_vector,
    )
    mgr = OntologyManager()
    expected = mgr.resolve(ctx)
    if expected.expected_techniques:
        for t in expected.expected_techniques:
            if t not in techniques:
                techniques.append(t)
        mapping_reasons.append(f"ontology:{expected.ground_truth_source}")
    if expected.is_unknown():
        logger.debug(
            "map_attack: %s → no ground truth from ontology (quality=UNKNOWN)",
            cve_id,
        )

    # ------------------------------------------------------------------
    # Rule-based: vulnerability_class mapping (bổ sung, không thay thế)
    # ------------------------------------------------------------------
    if vulnerability_class and vulnerability_class in VULNERABILITY_CLASS_ATTACK_GRAPH:
        for technique in VULNERABILITY_CLASS_ATTACK_GRAPH[vulnerability_class]:
            if technique not in techniques:
                techniques.append(technique)
        mapping_reasons.append(f"vulnerability_class:{vulnerability_class.value}")

    # ------------------------------------------------------------------
    # Rule-based: behaviors → techniques (bổ sung)
    # ------------------------------------------------------------------
    if behaviors:
        for behavior in behaviors:
            mapped = BEHAVIOR_ATTACK_GRAPH.get(behavior)
            if not mapped:
                continue
            for t in mapped["tactics"]:
                if t not in tactics:
                    tactics.append(t)
            for t in mapped["techniques"]:
                if t not in techniques:
                    techniques.append(t)
            for t in mapped["subtechniques"]:
                if t not in subtechniques:
                    subtechniques.append(t)
            mapping_reasons.append(f"behavior:{behavior}")

    # ------------------------------------------------------------------
    # Safety net: nếu rỗng HOẶC UNKNOWN + remote + pre_auth → T1190
    # ------------------------------------------------------------------
    if not techniques and classifier.get("remote_exploitable") and classifier.get("pre_auth"):
        techniques.append("T1190")
        mapping_reasons.append("CVSS indicates public-facing pre-auth exploitation")

    # ------------------------------------------------------------------
    # Behavior-technique coherence (bổ sung nếu behavior chỉ ra nhưng thiếu tech)
    # ------------------------------------------------------------------
    if "process_creation" in behaviors and "T1059" not in techniques:
        techniques.append("T1059")
    if "web_request" in behaviors and "T1190" not in techniques:
        techniques.append("T1190")
    if "privilege_escalation" in behaviors and "T1068" not in techniques:
        techniques.append("T1068")

    # Derive tactics từ techniques nếu behaviors không cung cấp
    # (Layer 2/3 có thể có techniques mà không có tactics rõ ràng)
    # _technique_to_tactic returns list[str] now (multi-tactic support)
    if techniques and not tactics:
        mgr = OntologyManager()
        for t in techniques:
            for mapped_tactic in mgr._technique_to_tactic(t):
                if mapped_tactic not in tactics:
                    tactics.append(mapped_tactic)

    # ------------------------------------------------------------------
    # Confidence scoring (giữ logic cũ)
    # ------------------------------------------------------------------
    confidence = 0.2 if behaviors else 0.15
    confidence += 0.1 if vulnerability_class and vulnerability_class != VulnerabilityClass.UNKNOWN else 0.0
    confidence += 0.14 * len(set(behaviors))
    confidence += 0.06 * min(len(cwe_profiles), 2) if not behaviors else 0.0
    confidence += 0.1 if classifier.get("remote_exploitable") else 0.0
    confidence += 0.1 if classifier.get("pre_auth") else 0.0
    # Tăng confidence nếu ontology có data
    if expected.ground_truth_quality == "HIGH":
        confidence += 0.1
    elif expected.ground_truth_quality == "PARTIAL":
        confidence += 0.05
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
