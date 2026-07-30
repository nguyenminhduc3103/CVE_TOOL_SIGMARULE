"""Rule-based behavior analyzer cho Phase 1/2 fallback path.

Đã đơn giản hóa: chỉ dựa vào CWE profiles (cwe_mapper.CWE_BEHAVIOR_MAP) và heuristic description keywords
để derive mandatory_behaviors / evasive_indicators / exploit_requirements. Đã bỏ các lookup AI-sinh
(signature, family, vulnerability_type) vì các trường này đã xóa khỏi Phase 1 output schema.
"""
from __future__ import annotations

from src.usecases.step_2_analysis.rule_based.cwe_mapper import CWEProfile


def analyze_behavior(
    cve_id: str | None,
    description: str | None,
    references: list[str] | None,
    cpes: list[str] | None,
    cwe_ids: list[str] | None,  # kept for API compat — currently unused (cwe_profiles has the lookup)
    cvss_vector: str | None,  # kept for API compat — currently unused (heuristic drives from description)
    cwe_profiles: list[CWEProfile],
    classifier: dict[str, str | bool | None],
) -> dict[str, list[str]]:
    """Build behavior dict thuần từ CWE profiles + description heuristics.

    Returns dict có các key mà caller (`orchestrator._build_rule_based_pydantic`,
    `analysis_stage.run_analysis_stage`) đọc:
      - mandatory_behaviors, evasive_indicators, exploit_requirements (list[str])
      - exploit_complexity (str | None)
    """
    # Start với behavior/indicator/requirement từ CWE_BEHAVIOR_MAP
    mandatory_behaviors: list[str] = list(dict.fromkeys(
        behavior for profile in cwe_profiles for behavior in profile.mandatory_behaviors
    ))
    evasive_indicators: list[str] = list(dict.fromkeys(
        indicator for profile in cwe_profiles for indicator in profile.evasive_indicators
    ))
    exploit_requirements: list[str] = list(dict.fromkeys(
        requirement for profile in cwe_profiles for requirement in profile.exploit_requirements
    ))

    # Heuristic description-based behaviors
    text = (description or "").lower()
    if "powershell" in text or "cmd.exe" in text:
        evasive_indicators.append("command_obfuscation")
    if "webshell" in text:
        mandatory_behaviors.append("webshell_drop")
    if "ldap" in text or "jndi" in text:
        mandatory_behaviors.append("network_callback")
    # File upload / arbitrary file write detection
    if ("upload" in text and "file" in text) or "arbitrary file" in text:
        mandatory_behaviors.append("file_write")
    if "place malicious file" in text or "place file" in text:
        mandatory_behaviors.append("file_write")
    if "write" in text and ("arbitrary" in text or "server" in text):
        mandatory_behaviors.append("file_write")

    # CVSS-derived requirements
    if classifier.get("remote_exploitable"):
        exploit_requirements.append("reachable_service")

    # Reference-based indicators (PoC/exploit tooling)
    if references:
        for reference in references:
            ref = reference.lower()
            if "poc" in ref or "exploit" in ref:
                exploit_requirements.append("public_exploit_artifact")
            if "github.com" in ref:
                evasive_indicators.append("commodity_exploitation_tooling")

    # CPE-based requirement
    if cpes and any(":a:" in cpe for cpe in cpes):
        exploit_requirements.append("application_runtime_present")

    # Default exploit_complexity: classifier (CVSS-derived) hoặc "medium"
    exploit_complexity = classifier.get("exploit_complexity") or "medium"

    return {
        "mandatory_behaviors": list(dict.fromkeys(mandatory_behaviors)),
        "evasive_indicators": list(dict.fromkeys(evasive_indicators)),
        "exploit_requirements": list(dict.fromkeys(exploit_requirements)),
        "exploit_complexity": exploit_complexity,
    }