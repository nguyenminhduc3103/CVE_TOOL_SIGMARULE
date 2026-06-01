from __future__ import annotations

from dataclasses import dataclass

from app.types.vulnerability_class import VulnerabilityClass


@dataclass(frozen=True)
class CWEProfile:
    cwe_id: str
    cwe_name: str
    vulnerability_type: str
    vulnerability_class: VulnerabilityClass
    mapping_confidence: float
    mandatory_behaviors: tuple[str, ...]
    evasive_indicators: tuple[str, ...]
    exploit_requirements: tuple[str, ...]
    likely_outcome: str


CWE_BEHAVIOR_MAP: dict[str, CWEProfile] = {
    "CWE-78": CWEProfile(
        cwe_id="CWE-78",
        cwe_name="Improper Neutralization of Special Elements used in an OS Command",
        vulnerability_type="command_injection",
        vulnerability_class=VulnerabilityClass.COMMAND_INJECTION,
        mapping_confidence=0.95,
        mandatory_behaviors=("process_execution", "shell_spawn"),
        evasive_indicators=("encoded_command", "living_off_the_land"),
        exploit_requirements=("attacker_controlled_input", "reachable_service"),
        likely_outcome="remote_code_execution",
    ),
    "CWE-89": CWEProfile(
        cwe_id="CWE-89",
        cwe_name="Improper Neutralization of Special Elements used in an SQL Command",
        vulnerability_type="sql_injection",
        vulnerability_class=VulnerabilityClass.SQL_INJECTION,
        mapping_confidence=0.95,
        mandatory_behaviors=("database_query", "http_request"),
        evasive_indicators=("union_select_pattern",),
        exploit_requirements=("attacker_controlled_query_parameter",),
        likely_outcome="data_exfiltration",
    ),
    "CWE-22": CWEProfile(
        cwe_id="CWE-22",
        cwe_name="Improper Limitation of a Pathname to a Restricted Directory",
        vulnerability_type="path_traversal",
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        mapping_confidence=0.98,
        mandatory_behaviors=("file_read", "web_request"),
        evasive_indicators=("encoded_path_sequence",),
        exploit_requirements=("path_parameter_control",),
        likely_outcome="information_disclosure",
    ),
    "CWE-434": CWEProfile(
        cwe_id="CWE-434",
        cwe_name="Unrestricted Upload of File with Dangerous Type",
        vulnerability_type="file_upload",
        vulnerability_class=VulnerabilityClass.FILE_UPLOAD,
        mapping_confidence=0.95,
        mandatory_behaviors=("webshell", "process_execution"),
        evasive_indicators=("double_extension_filename",),
        exploit_requirements=("upload_endpoint_exposed",),
        likely_outcome="webshell_persistence",
    ),
    "CWE-502": CWEProfile(
        cwe_id="CWE-502",
        cwe_name="Deserialization of Untrusted Data",
        vulnerability_type="deserialization",
        vulnerability_class=VulnerabilityClass.DESERIALIZATION,
        mapping_confidence=0.97,
        mandatory_behaviors=("network_connection", "process_creation"),
        evasive_indicators=("serialized_payload",),
        exploit_requirements=("deserialization_sink_reachable",),
        likely_outcome="remote_code_execution",
    ),
    "CWE-918": CWEProfile(
        cwe_id="CWE-918",
        cwe_name="Server-Side Request Forgery",
        vulnerability_type="ssrf",
        vulnerability_class=VulnerabilityClass.SSRF,
        mapping_confidence=0.96,
        mandatory_behaviors=("network_connection", "http_request"),
        evasive_indicators=("internal_host_targeting",),
        exploit_requirements=("server_side_request_primitive",),
        likely_outcome="internal_service_reachability",
    ),
    "CWE-306": CWEProfile(
        cwe_id="CWE-306",
        cwe_name="Missing Authentication for Critical Function",
        vulnerability_type="auth_bypass",
        vulnerability_class=VulnerabilityClass.AUTH_BYPASS,
        mapping_confidence=0.95,
        mandatory_behaviors=("public_facing_exploit",),
        evasive_indicators=("missing_authentication_gate",),
        exploit_requirements=("reachable_service",),
        likely_outcome="unauthorized_access",
    ),
    "CWE-269": CWEProfile(
        cwe_id="CWE-269",
        cwe_name="Improper Privilege Management",
        vulnerability_type="privilege_escalation",
        vulnerability_class=VulnerabilityClass.PRIVILEGE_ESCALATION,
        mapping_confidence=0.97,
        mandatory_behaviors=("privilege_escalation", "process_creation", "image_load"),
        evasive_indicators=("service_abuse",),
        exploit_requirements=("privileged_execution_path",),
        likely_outcome="privilege_escalation",
    ),
}


def map_cwe_profiles(cwe_ids: list[str] | None) -> list[CWEProfile]:
    if not cwe_ids:
        return []

    profiles: list[CWEProfile] = []
    for cwe_id in cwe_ids:
        normalized = cwe_id.upper().strip()
        if normalized in CWE_BEHAVIOR_MAP:
            profiles.append(CWE_BEHAVIOR_MAP[normalized])
    return profiles
