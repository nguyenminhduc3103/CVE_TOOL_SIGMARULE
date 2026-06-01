from __future__ import annotations

from app.analysis.attack_mapper import map_attack
from app.analysis.behavior_analyzer import analyze_behavior
from app.analysis.cwe_mapper import map_cwe_profiles
from app.analysis.exploit_classifier import classify_exploit_vector
from app.models.attack import AttackMapping, TechnicalAnalysis
from app.models.enriched import EnrichedCVEContext
from app.triage.capability_checker import CapabilityClassification


async def run_analysis_stage(
    context: EnrichedCVEContext,
    capability: CapabilityClassification | None = None,
) -> tuple[TechnicalAnalysis, AttackMapping]:
    description_raw = context.core.description or ""
    description = description_raw.lower()
    software_keywords = ["winrar", "outlook", "excel", "word", "zoom", "chrome"]
    extracted_keywords = [keyword for keyword in software_keywords if keyword in description]

    rce_phrases = ["remote code execution", "execute arbitrary code", "run arbitrary commands"]
    user_exec_phrases = ["open a malicious file", "user interaction", "crafted file"]
    has_rce_phrase = any(phrase in description for phrase in rce_phrases)
    has_user_exec_phrase = any(phrase in description for phrase in user_exec_phrases)
    cwe_profiles = map_cwe_profiles(context.core.cwe_ids)
    classifier = classify_exploit_vector(context.core.cvss_vector)
    behavior = analyze_behavior(
        cve_id=context.core.cve_id,
        description=context.core.description,
        references=context.core.references,
        cpes=context.core.cpes,
        cwe_ids=context.core.cwe_ids,
        cvss_vector=context.core.cvss_vector,
        cwe_profiles=cwe_profiles,
        classifier=classifier,
    )
    attack = map_attack(
        ontology_behaviors=behavior.get("mandatory_behaviors", []),
        vulnerability_class=behavior.get("vulnerability_class"),
        cwe_profiles=cwe_profiles,
        classifier=classifier,
        ontology_confidence=behavior.get("ontology_confidence") if isinstance(behavior.get("ontology_confidence"), float) else None,
    )

    # Family-scoped overrides for ATT&CK mapping (e.g., Spring4Shell deterministic mapping)
    family = behavior.get("family")
    try:
        from app.types.vulnerability_family import VulnerabilityFamily

        if family == VulnerabilityFamily.SPRING4SHELL:
            attack["techniques"] = ["T1190", "T1059", "T1105"]
            attack["mapping_reasons"] = ["family:spring4shell", "signature:spring4shell"]
            attack["confidence"] = max(attack.get("confidence", 0.2), 0.92)
    except Exception:
        pass

    has_generic_keywords = any(keyword in description for keyword in ("winrar", "archive", "file", "user interaction"))
    type_unknown = (behavior.get("vulnerability_type") or "").lower() in {"", "unknown", "none"}
    family_unknown = (behavior.get("family") or "").lower() in {"", "unknown", "none"}

    confidence = behavior.get("analysis_confidence") if isinstance(behavior.get("analysis_confidence"), float) else 0.35
    if (type_unknown or family_unknown) and has_generic_keywords:
        behavior["vulnerability_type"] = "user_execution_artifact"
        behavior["exploit_complexity"] = "low"
        confidence = max(confidence, 0.7)
    if capability and capability.value.startswith("out_of_scope"):
        confidence = round(confidence * capability.confidence_modifier, 2)

    likely_outcome = behavior.get("likely_outcome")
    if has_rce_phrase:
        likely_outcome = "remote_code_execution"

    analysis = TechnicalAnalysis(
        family=behavior.get("family"),
        signature=behavior.get("signature"),
        extracted_keywords=extracted_keywords or None,
        vulnerability_type=behavior.get("vulnerability_type"),
        vulnerability_class=behavior.get("vulnerability_class"),
        exploit_vector=classifier.get("exploit_vector"),
        pre_auth=classifier.get("pre_auth"),
        remote_exploitable=classifier.get("remote_exploitable"),
        exploit_complexity=behavior.get("exploit_complexity") or classifier.get("exploit_complexity"),
        confidence=confidence,
        analysis_confidence=confidence,
        cwe_metadata=behavior.get("cwe_metadata"),
        attack_flow=behavior.get("attack_flow"),
        likely_outcome=likely_outcome,
        mandatory_behaviors=behavior.get("mandatory_behaviors"),
        evasive_indicators=behavior.get("evasive_indicators"),
        exploit_requirements=behavior.get("exploit_requirements"),
        reasoning=behavior.get("ontology_reasoning"),
        classification_reason=behavior.get("classification_reason"),
        behavior_reason=behavior.get("behavior_reason"),
    )

    if has_rce_phrase:
        attack_tactics = list(dict.fromkeys((attack.get("tactics") or []) + ["TA0002"]))
        attack["tactics"] = attack_tactics
    if has_user_exec_phrase:
        attack_techniques = list(dict.fromkeys((attack.get("techniques") or []) + ["T1204"]))
        attack["techniques"] = attack_techniques

    epss_score = context.triage.epss_score if context.triage else None
    exploit_vector = str(classifier.get("exploit_vector") or "").lower()
    is_local_or_user = exploit_vector == "local" or behavior.get("vulnerability_type") == "user_execution_artifact"
    if not attack.get("techniques") and epss_score is not None and epss_score > 0.5 and is_local_or_user:
        attack["tactics"] = ["TA0001", "TA0002"]
        attack["techniques"] = ["T1204", "T1204.002"]
        attack["mapping_reasons"] = ["epss_high", "user_execution_fallback"]
        attack["confidence"] = max(attack.get("confidence", 0.2), 0.6)

    attack_mapping = AttackMapping(
        tactics=attack.get("tactics"),
        techniques=attack.get("techniques"),
        subtechniques=attack.get("subtechniques"),
        confidence=attack.get("confidence"),
        attack_mapping_confidence=attack.get("confidence"),
        mapping_reasons=attack.get("mapping_reasons"),
    )
    return analysis, attack_mapping
