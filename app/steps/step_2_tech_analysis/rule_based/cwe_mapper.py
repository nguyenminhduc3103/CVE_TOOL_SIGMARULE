from __future__ import annotations

from dataclasses import dataclass

from app.shared.types.vulnerability_class import VulnerabilityClass
from app.shared.types.vulnerability_family import VulnerabilityFamily


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
    family: VulnerabilityFamily | None = None


CWE_BEHAVIOR_MAP: dict[str, CWEProfile] = {
    "CWE-78": CWEProfile(
        cwe_id="CWE-78",
        cwe_name="Improper Neutralization of Special Elements used in an OS Command",
        vulnerability_type="command_injection",
        vulnerability_class=VulnerabilityClass.COMMAND_INJECTION,
        mapping_confidence=0.95,
        # process_creation: real CMDi RCE leads to subprocess spawn (sh -c, cmd.exe /c).
        # Without this, T1059 mapping missed because process_execution is internal-only.
        mandatory_behaviors=(
            "process_execution",
            "shell_spawn",
            "process_creation",
        ),
        evasive_indicators=("encoded_command", "living_off_the_land"),
        exploit_requirements=("attacker_controlled_input", "reachable_service"),
        likely_outcome="remote_code_execution",
        family=VulnerabilityFamily.CODE_INJECTION,
    ),
    # CWE-94: generic code injection (eval, exec, dynamic code generation).
    # Distinct from CWE-78 (OS command) và CWE-917 (expression language):
    # covers eval()-style sinks in interpreted languages.
    "CWE-94": CWEProfile(
        cwe_id="CWE-94",
        cwe_name="Improper Control of Generation of Code ('Code Injection')",
        vulnerability_type="code_injection",
        vulnerability_class=VulnerabilityClass.CODE_INJECTION,
        mapping_confidence=0.95,
        mandatory_behaviors=("process_creation", "shell_spawn"),
        evasive_indicators=("string_obfuscation", "encoding_bypass"),
        exploit_requirements=("attacker_controlled_input", "eval_or_exec_sink"),
        likely_outcome="remote_code_execution",
        family=VulnerabilityFamily.CODE_INJECTION,
    ),
    # CWE-917: Expression Language Injection (OGNL, SpEL, MVEL).
    # Sink = framework's expression evaluator (không phải eval() trực tiếp).
    "CWE-917": CWEProfile(
        cwe_id="CWE-917",
        cwe_name=(
            "Improper Neutralization of Special Elements used in an "
            "Expression Language Statement ('Expression Language Injection')"
        ),
        vulnerability_type="expression_language_injection",
        vulnerability_class=VulnerabilityClass.CODE_INJECTION,
        mapping_confidence=0.95,
        mandatory_behaviors=("process_creation", "expression_evaluation"),
        evasive_indicators=("unicode_escape_encoding", "sandbox_bypass"),
        exploit_requirements=(
            "expression_language_sink",
            "attacker_controlled_template_input",
        ),
        likely_outcome="remote_code_execution",
        family=VulnerabilityFamily.EXPRESSION_LANGUAGE_INJECTION,
    ),
    # CWE-1336: Server-Side Template Injection (SSTI).
    # Sink = template engine renderer (Jinja2, Twig, Freemarker, Smarty, Velocity).
    "CWE-1336": CWEProfile(
        cwe_id="CWE-1336",
        cwe_name=(
            "Improper Neutralization of Special Elements Used in a "
            "Template Engine ('Template Injection')"
        ),
        vulnerability_type="template_injection",
        vulnerability_class=VulnerabilityClass.CODE_INJECTION,
        mapping_confidence=0.95,
        mandatory_behaviors=("template_rendering", "process_creation"),
        evasive_indicators=("template_syntax_obfuscation", "sandbox_escape"),
        exploit_requirements=(
            "user_controlled_template_input",
            "server_side_template_engine",
        ),
        likely_outcome="remote_code_execution",
        family=VulnerabilityFamily.CODE_INJECTION,
    ),
    "CWE-89": CWEProfile(
        cwe_id="CWE-89",
        cwe_name="Improper Neutralization of Special Elements used in an SQL Command",
        vulnerability_type="sql_injection",
        vulnerability_class=VulnerabilityClass.SQL_INJECTION,
        mapping_confidence=0.95,
        # data_exfiltration: SQLi primary impact IS data theft → move from
        # likely_outcome (informational) sang mandatory_behaviors (actionable
        # MITRE mapping T1020/T1114 qua BEHAVIOR_ATTACK_GRAPH).
        mandatory_behaviors=(
            "database_query",
            "http_request",
            "data_exfiltration",
        ),
        evasive_indicators=("union_select_pattern",),
        exploit_requirements=("attacker_controlled_query_parameter",),
        likely_outcome="data_exfiltration",
        family=None,
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
        family=VulnerabilityFamily.PATH_TRAVERSAL,
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
        family=VulnerabilityFamily.FILE_UPLOAD,
    ),
    "CWE-502": CWEProfile(
        cwe_id="CWE-502",
        cwe_name="Deserialization of Untrusted Data",
        vulnerability_type="deserialization",
        vulnerability_class=VulnerabilityClass.DESERIALIZATION,
        mapping_confidence=0.97,
        # public_facing_exploit: CWE-502 exploit qua HTTP/API endpoint công khai
        # (Log4Shell, JSON deserialization). Chỉ network_connection/process_creation
        # không phản ánh attack surface đầu vào.
        # tool_download: deserialization thường fetch malicious class files
        # (Log4Shell .class via LDAP/HTTP, gadget chains) → T1105.
        mandatory_behaviors=(
            "network_connection",
            "process_creation",
            "public_facing_exploit",
            "tool_download",
        ),
        evasive_indicators=("serialized_payload",),
        exploit_requirements=("deserialization_sink_reachable",),
        likely_outcome="remote_code_execution",
        family=VulnerabilityFamily.DESERIALIZATION,
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
        family=VulnerabilityFamily.SSRF,
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
        family=None,
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
        family=VulnerabilityFamily.PRIVILEGE_ESCALATION,
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
