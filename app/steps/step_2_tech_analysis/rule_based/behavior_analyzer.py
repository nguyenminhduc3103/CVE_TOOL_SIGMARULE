from __future__ import annotations

from app.steps.step_2_tech_analysis.rule_based.cwe_mapper import CWEProfile
from app.steps.step_2_tech_analysis.rule_based.exploit_ontology import (
    ExploitOntologyResult,
    infer_exploit_ontology,
    infer_exploit_ontology_family_scoped,
)
from app.steps.step_2_tech_analysis.rule_based.vulnerability_signature_engine import SignatureMatch, match_signature
from app.steps.step_2_tech_analysis.rule_based.family_classifier import classify_family
from app.shared.types.vulnerability_family import VulnerabilityFamily
from app.shared.types.vulnerability_class import VulnerabilityClass


def _derive_vulnerability_class(
    cve_id: str | None,
    description: str | None,
    profiles: list[CWEProfile],
    ontology: ExploitOntologyResult,
    signature_match: SignatureMatch | None,
) -> VulnerabilityClass:
    if signature_match is not None:
        return signature_match.signature.vulnerability_class

    normalized_cve = (cve_id or "").upper()
    known_overrides = {
        "CVE-2021-44228": VulnerabilityClass.DESERIALIZATION,
        "CVE-2021-34527": VulnerabilityClass.PRIVILEGE_ESCALATION,
        "CVE-2021-41773": VulnerabilityClass.PATH_TRAVERSAL,
        "CVE-2019-5418": VulnerabilityClass.INFORMATION_DISCLOSURE,
    }
    if normalized_cve in known_overrides:
        return known_overrides[normalized_cve]

    text = (description or "").lower()
    if "path traversal" in text or "directory traversal" in text or "../" in text:
        return VulnerabilityClass.PATH_TRAVERSAL
    if "file disclosure" in text or "information disclosure" in text:
        return VulnerabilityClass.INFORMATION_DISCLOSURE

    if profiles:
        return profiles[0].vulnerability_class
    if "deserial" in text:
        return VulnerabilityClass.DESERIALIZATION
    if "command" in text and "inject" in text:
        return VulnerabilityClass.COMMAND_INJECTION
    if "upload" in text and "file" in text:
        return VulnerabilityClass.FILE_UPLOAD
    if "server-side request forgery" in text or "ssrf" in text:
        return VulnerabilityClass.SSRF
    if "auth bypass" in text or "missing authentication" in text:
        return VulnerabilityClass.AUTH_BYPASS
    if "privilege" in text and "escalat" in text:
        return VulnerabilityClass.PRIVILEGE_ESCALATION

    if "privilege_escalation" in ontology.behaviors:
        return VulnerabilityClass.PRIVILEGE_ESCALATION
    if "webshell_drop" in ontology.behaviors:
        return VulnerabilityClass.WEBSHELL_DROP
    if "file_read" in ontology.behaviors and "web_request" in ontology.behaviors:
        return VulnerabilityClass.PATH_TRAVERSAL
    if "network_callback" in ontology.behaviors:
        return VulnerabilityClass.REMOTE_CODE_EXECUTION
    if "process_creation" in ontology.behaviors:
        return VulnerabilityClass.CODE_INJECTION
    return VulnerabilityClass.UNKNOWN


def _derive_likely_outcome(
    vulnerability_class: VulnerabilityClass,
    profiles: list[CWEProfile],
    classifier: dict[str, str | bool | None],
    ontology: ExploitOntologyResult,
) -> str:
    if vulnerability_class == VulnerabilityClass.PRIVILEGE_ESCALATION:
        return "privilege_escalation"
    if vulnerability_class == VulnerabilityClass.PATH_TRAVERSAL:
        return "information_disclosure"
    if vulnerability_class == VulnerabilityClass.INFORMATION_DISCLOSURE:
        return "information_disclosure"
    if vulnerability_class == VulnerabilityClass.WEBSHELL_DROP:
        return "webshell_persistence"
    if vulnerability_class == VulnerabilityClass.DESERIALIZATION:
        return "remote_code_execution"

    if "privilege_escalation" in ontology.behaviors:
        return "privilege_escalation"
    if "webshell_drop" in ontology.behaviors:
        return "webshell_persistence"
    if "network_callback" in ontology.behaviors:
        return "remote_code_execution"
    if profiles:
        return profiles[0].likely_outcome

    if classifier.get("remote_exploitable") and classifier.get("pre_auth"):
        return "unauthenticated_remote_compromise"
    return "limited_impact"


def _build_cwe_metadata(profiles: list[CWEProfile]) -> dict[str, str | float | None]:
    if not profiles:
        return {"cwe_id": None, "cwe_name": None, "mapping_confidence": None}
    profile = profiles[0]
    return {
        "cwe_id": profile.cwe_id,
        "cwe_name": profile.cwe_name,
        "mapping_confidence": profile.mapping_confidence,
    }


def _build_attack_flow(
    vulnerability_class: VulnerabilityClass,
    classifier: dict[str, str | bool | None],
    mandatory_behaviors: list[str],
) -> dict[str, str | list[str]]:
    entry_vector = classifier.get("exploit_vector") or "unknown"
    execution_mechanism = vulnerability_class.value
    observable = list(mandatory_behaviors)

    if vulnerability_class in {VulnerabilityClass.PATH_TRAVERSAL, VulnerabilityClass.INFORMATION_DISCLOSURE}:
        execution_mechanism = "path_resolution_bypass"
    elif vulnerability_class == VulnerabilityClass.PRIVILEGE_ESCALATION:
        execution_mechanism = "privilege_boundary_escape"
    elif vulnerability_class == VulnerabilityClass.DESERIALIZATION:
        execution_mechanism = "unsafe_object_materialization"

    return {
        "entry_vector": str(entry_vector),
        "execution_mechanism": execution_mechanism,
        "observable_side_effects": observable,
    }


def analyze_behavior(
    cve_id: str | None,
    description: str | None,
    references: list[str] | None,
    cpes: list[str] | None,
    cwe_ids: list[str] | None,
    cvss_vector: str | None,
    cwe_profiles: list[CWEProfile],
    classifier: dict[str, str | bool | None],
) -> dict[str, str | list[str]]:
    ontology = infer_exploit_ontology(cwe_ids, description, cvss_vector, references)
    signature_match = match_signature(cve_id=cve_id, description=description, cwe_ids=cwe_ids, cpes=cpes)

    # Classify family first to reduce ontology leakage
    family, fam_conf, fam_reasons = classify_family(cve_id=cve_id, description=description, cwe_ids=cwe_ids, cpes=cpes)
    family_reasons: list[str] = []

    # Start with ontology-derived behaviors and CWE profiles
    mandatory_behaviors = list(dict.fromkeys(ontology.behaviors + [behavior for profile in cwe_profiles for behavior in profile.mandatory_behaviors]))
    optional_behaviors: list[str] = []
    evasive_indicators = list(dict.fromkeys([indicator for profile in cwe_profiles for indicator in profile.evasive_indicators]))
    exploit_requirements = list(dict.fromkeys([requirement for profile in cwe_profiles for requirement in profile.exploit_requirements]))

    signature_name = signature_match.signature.name if signature_match is not None else None

    # Apply signature-enforced behaviors (signature has highest priority for behavior requirements)
    if signature_match is not None:
        mandatory_behaviors = list(dict.fromkeys(mandatory_behaviors + list(signature_match.signature.mandatory_behaviors)))

    # Family-scoped inference (authoritative for families like Spring4Shell)
    spring_override = False
    inferred_family = infer_exploit_ontology_family_scoped(family=family, description=description, cwe_ids=cwe_ids, cvss_vector=cvss_vector)
    if family and getattr(family, "value", str(family)).lower() == "spring4shell":
        spring_override = True
        # Use family-scoped behaviors as authoritative; ensure signature-required behaviors are preserved
        mandatory_behaviors = list(dict.fromkeys(list(inferred_family.behaviors) + list(mandatory_behaviors)))
        # record family-scoped reasoning to merge later
        family_reasons.extend(getattr(inferred_family, "reasoning", []))

    # Add heuristic behaviors from description
    text = (description or "").lower()
    if "powershell" in text or "cmd.exe" in text:
        evasive_indicators.append("command_obfuscation")
    if "webshell" in text:
        mandatory_behaviors.append("webshell_drop")
    if "ldap" in text or "jndi" in text:
        mandatory_behaviors.append("network_callback")

    if classifier.get("remote_exploitable"):
        exploit_requirements.append("reachable_service")

    if references:
        for reference in references:
            ref = reference.lower()
            if "poc" in ref or "exploit" in ref:
                exploit_requirements.append("public_exploit_artifact")
            if "github.com" in ref:
                evasive_indicators.append("commodity_exploitation_tooling")

    if cpes and any(":a:" in cpe for cpe in cpes):
        exploit_requirements.append("application_runtime_present")

    if "privilege_escalation" in ontology.behaviors:
        exploit_requirements.append("elevated_privileges_or_driver_install")

    # Build classification reasoning
    classification_reasons: list[str] = list(ontology.reasoning)
    if family_reasons:
        classification_reasons.extend(family_reasons)
    if family and family != VulnerabilityFamily.UNKNOWN:
        classification_reasons.append(f"family:{family.value}")
        classification_reasons.extend(fam_reasons)
    if signature_match is not None:
        classification_reasons = list(dict.fromkeys(classification_reasons + [f"signature:{signature_match.signature.name}"] + list(signature_match.reasons)))

    vulnerability_class = _derive_vulnerability_class(cve_id, description, cwe_profiles, ontology, signature_match)
    if vulnerability_class == VulnerabilityClass.CODE_INJECTION and "network_callback" in mandatory_behaviors:
        vulnerability_class = VulnerabilityClass.REMOTE_CODE_EXECUTION

    likely_outcome = _derive_likely_outcome(vulnerability_class, cwe_profiles, classifier, ontology)
    behavior_reason = list(dict.fromkeys([
        f"ontology_behaviors:{','.join(ontology.behaviors)}" if ontology.behaviors else "ontology_behaviors:none",
        f"mandatory_behaviors:{','.join(list(dict.fromkeys(mandatory_behaviors)))}" if mandatory_behaviors else "mandatory_behaviors:none",
        "classifier:remote_exploitable" if classifier.get("remote_exploitable") else "classifier:non_remote",
    ]))

    vulnerability_type = vulnerability_class.value
    if signature_match is not None:
        vulnerability_type = signature_match.signature.vulnerability_type

    analysis_confidence = ontology.confidence
    if signature_match is not None:
        analysis_confidence = round(min(0.98, (ontology.confidence * 0.6) + (signature_match.confidence * 0.4)), 2)

    # Enforce family-specific overrides (Spring4Shell deterministic outcomes)
    if spring_override:
        likely_outcome = "remote_code_execution"
        analysis_confidence = round(max(analysis_confidence, 0.92), 2)

    return {
        "signature": signature_name,
        "vulnerability_type": vulnerability_type,
        "vulnerability_class": vulnerability_class,
        "family": family,
        "cwe_metadata": _build_cwe_metadata(cwe_profiles),
        "attack_flow": _build_attack_flow(vulnerability_class, classifier, list(dict.fromkeys(mandatory_behaviors))),
        "likely_outcome": likely_outcome,
        "mandatory_behaviors": list(dict.fromkeys(mandatory_behaviors)),
        "evasive_indicators": list(dict.fromkeys(evasive_indicators)),
        "exploit_requirements": list(dict.fromkeys(exploit_requirements)),
        "ontology_confidence": ontology.confidence,
        "analysis_confidence": analysis_confidence,
        "classification_reason": list(dict.fromkeys(classification_reasons)),
        "behavior_reason": behavior_reason,
        "ontology_reasoning": list(dict.fromkeys(classification_reasons)),
    }
