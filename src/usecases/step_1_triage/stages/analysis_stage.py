from __future__ import annotations

from src.usecases.step_2_analysis.rule_based.attack_mapper import map_attack
from src.usecases.step_2_analysis.rule_based.behavior_analyzer import analyze_behavior
from src.usecases.step_2_analysis.rule_based.cwe_mapper import map_cwe_profiles
from src.usecases.step_2_analysis.rule_based.exploit_classifier import classify_exploit_vector
from src.domain.models.attack import AttackMapping, TechnicalAnalysis
from src.domain.models.enriched import EnrichedCVEContext
from src.domain.services.capability import CapabilityClassification


async def run_analysis_stage(
    context: EnrichedCVEContext,
    capability: CapabilityClassification | None = None,
) -> tuple[TechnicalAnalysis, AttackMapping]:
    # Round-2: chuẩn hoá description (có thể là dict ở một số entry path) → str để .lower() không crash.
    description_raw = context.core.description or ""
    if isinstance(description_raw, dict):
        description_raw = description_raw.get("value") or description_raw.get("text") or ""
    description = str(description_raw).lower()
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
        description=context.core.description if isinstance(context.core.description, str) else str(context.core.description or ""),
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

    has_generic_keywords = any(keyword in description for keyword in ("winrar", "archive", "file", "user interaction"))

    confidence = behavior.get("analysis_confidence") if isinstance(behavior.get("analysis_confidence"), float) else 0.35
    if has_generic_keywords and not behavior.get("vulnerability_type"):
        behavior["vulnerability_type"] = "user_execution_artifact"
        behavior["exploit_complexity"] = "low"
        confidence = max(confidence, 0.7)
    if capability and capability.value.startswith("out_of_scope"):
        confidence = round(confidence * capability.confidence_modifier, 2)

    # Round-2: classifier giờ chứa exploit_vector (CVSS-deterministic) — dùng nó thay vì None.
    analysis = TechnicalAnalysis(
        exploit_vector=classifier.get("exploit_vector"),
        pre_auth=classifier.get("pre_auth"),
        remote_exploitable=classifier.get("remote_exploitable"),
        exploit_complexity=behavior.get("exploit_complexity") or classifier.get("exploit_complexity"),
        user_interaction_required=classifier.get("user_interaction_required"),
        confidence=confidence,
        mandatory_behaviors=behavior.get("mandatory_behaviors"),
        evasive_indicators=behavior.get("evasive_indicators"),
        exploit_requirements=behavior.get("exploit_requirements"),
        reasoning=behavior.get("ontology_reasoning"),
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
