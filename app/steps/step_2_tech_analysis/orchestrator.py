"""Orchestrator cho Step 2 - Technical & ATT&CK Analyzer.

Step 2 chỉ chạy 2-phase flow:
  - Phase 1 (behavior only): extract FACTS - execution_surface,
    delivery_vector, user_interaction_required, attack_flow, behaviors.
    KHÔNG có tactics/techniques → tránh AV:N→T1190 bias.
  - Phase 2 (ATT&CK mapping): nhận Phase 1 output làm canonical anchor
    → chọn technique đúng kể cả client-side CVE (MSHTML CVE-2021-40444).

Rule-based fallback chỉ chạy khi cả 2 phase AI fail.
"""
from __future__ import annotations

import logging
from typing import Any

from app.shared.models.attack import (
    AttackMapping,
    TechnicalAnalysis,
)
from app.shared.ai.core import AIServiceError, BaseAIClient
from app.steps.step_2_tech_analysis.services.ai_service import (
    AIBehaviorService,
)
from app.steps.step_2_tech_analysis.data_flow import (
    _ai_dict_to_pydantic,
    _normalize_none_placeholders,
)

logger = logging.getLogger(__name__)


# ==============================================================
# TECHNIQUE → TACTIC Mapping (Suy diễn tactics từ techniques)
# ==============================================================

TECHNIQUE_TO_TACTICS: dict[str, list[str]] = {
    # Initial Access
    "T1190": ["TA0001"],  # Exploit Public-Facing Application
    "T1210": ["TA0008"],  # Exploitation of Remote Services
    "T1133": ["TA0001"],  # External Remote Services
    "T1204": ["TA0002"],  # User Execution
    "T1068": ["TA0004"],  # Exploitation for Privilege Escalation
    "T1195": ["TA0001"],  # Supply Chain Compromise
    "T1611": ["TA0004", "TA0005"],  # Escape to Host
    "T1566": ["TA0001"],  # Phishing
    "T1189": ["TA0001"],  # Drive-by Compromise
    # Execution
    "T1203": ["TA0002"],  # Exploitation for Client Execution
    "T1059": ["TA0002"],  # Command and Scripting Interpreter
    "T1059.001": ["TA0002"],  # PowerShell
    "T1059.003": ["TA0002"],  # Windows Command Shell
    "T1059.004": ["TA0002"],  # Unix Shell
    "T1059.006": ["TA0002"],  # Python
    "T1059.007": ["TA0002"],  # JavaScript
    # Command and Control
    "T1071": ["TA0011"],  # Application Layer Protocol
    "T1071.001": ["TA0011"],  # HTTPS/DNS
    "T1071.002": ["TA0011"],  # FTP/SMTP
    "T1105": ["TA0011"],  # Ingress Tool Transfer
    # Impact
    "T1499": ["TA0040"],  # Endpoint Denial of Service
    "T1499.004": ["TA0040"],  # Service DoS
    "T1486": ["TA0040"],  # Data Encrypted for Impact
    "T1489": ["TA0040"],  # Service Stop
}


def _derive_tactics_from_techniques(techniques: list[str]) -> list[str]:
    """Suy diễn tactics từ techniques.

    Args:
        techniques: Danh sách technique IDs (vd ['T1190', 'T1203', 'T1071'])

    Returns:
        Danh sách tactic IDs duy nhất (vd ['TA0001', 'TA0002', 'TA0011'])
    """
    tactics: list[str] = []
    for tech in techniques:
        mapped = TECHNIQUE_TO_TACTICS.get(tech, [])
        for t in mapped:
            if t not in tactics:
                tactics.append(t)
    return tactics


# ==============================================================
# CRITICAL CVEs - Hardcoded Ground Truth (Hybrid Override)
# ==============================================================

CRITICAL_ATTACK_CHAINS: dict[str, dict[str, list[str]]] = {
    # Log4Shell
    "CVE_2021_44228": {
        "tactics": ["TA0001", "TA0002", "TA0011"],
        "techniques": ["T1190", "T1203", "T1071"],
        "subtechniques": ["T1071.001"],
    },
    "CVE_2021_45046": {
        "tactics": ["TA0001", "TA0002", "TA0040"],
        "techniques": ["T1190", "T1203", "T1499"],
        "subtechniques": [],
    },
    # EternalBlue
    "CVE_2017_0144": {
        "tactics": ["TA0008", "TA0002", "TA0040"],
        "techniques": ["T1210", "T1059", "T1486"],
        "subtechniques": ["T1059.003"],
    },
    # ProxyLogon
    "CVE_2021_26855": {
        "tactics": ["TA0001", "TA0002", "TA0011"],
        "techniques": ["T1190", "T1059", "T1071"],
        "subtechniques": ["T1059.003", "T1071.001"],
    },
}


def _apply_critical_override(cve_id: str, attack_mapping: dict) -> dict:
    """Override với hardcoded ground truth cho critical CVEs.

    Args:
        cve_id: CVE ID (vd 'CVE-2021-44228')
        attack_mapping: Dict chứa tactics, techniques, subtechniques

    Returns:
        Dict đã được override nếu CVE là critical, ngược lại trả về nguyên
    """
    if not cve_id:
        return attack_mapping

    # Normalize CVE ID: CVE-2021-44228 → CVE_2021_44228
    cve_key = cve_id.upper().replace("-", "_").replace("CVE_", "CVE_")
    if not cve_key.startswith("CVE_"):
        cve_key = "CVE_" + cve_key

    if cve_key in CRITICAL_ATTACK_CHAINS:
        chain = CRITICAL_ATTACK_CHAINS[cve_key]
        attack_mapping["tactics"] = chain["tactics"]
        attack_mapping["techniques"] = chain["techniques"]
        attack_mapping["subtechniques"] = chain["subtechniques"]
        attack_mapping["_override_reason"] = f"CRITICAL_CVE:{cve_id}"
        logger.debug(
            "[Step 2 - CRITICAL OVERRIDE] %s → tactics=%s, techniques=%s",
            cve_id, chain["tactics"], chain["techniques"],
        )

    return attack_mapping


# ==============================================================
# Rule-based fallback (chỉ chạy khi AI fail hoàn toàn)
# ==============================================================

def _build_rule_based_pydantic(
    *,
    cve_id: str,
    description: str,
    references: list[str],
    cpes: list[str],
    cvss_vector: str,
    cwe_ids: list[str],
    ai_model: str | None,
    ai_retry_count: int,
) -> tuple[TechnicalAnalysis, AttackMapping]:
    """Build Pydantic trực tiếp từ rule-based engines (NO dict intermediate).

    Spec CVE-2-Sigma.md: "AI có dự phòng" → rule-based chỉ chạy khi AI
    fail. Output ở đây là FINAL, không cần validate lại, không qua
    `_ai_dict_to_pydantic`.
    """
    from app.steps.step_2_tech_analysis.rule_based.behavior_analyzer import analyze_behavior
    from app.steps.step_2_tech_analysis.rule_based.attack_mapper import map_attack
    from app.steps.step_2_tech_analysis.rule_based.cwe_mapper import map_cwe_profiles
    from app.steps.step_2_tech_analysis.rule_based.exploit_classifier import classify_exploit_vector

    cwe_profiles_list = map_cwe_profiles(cwe_ids) or []
    classifier_real = classify_exploit_vector(cvss_vector)
    classifier = {
        "exploit_vector": None,
        "pre_auth": classifier_real.get("pre_auth"),
        "remote_exploitable": classifier_real.get("remote_exploitable"),
        "exploit_complexity": classifier_real.get("exploit_complexity"),
    }

    try:
        behavior = analyze_behavior(
            cve_id=cve_id,
            description=description,
            references=references,
            cpes=cpes,
            cwe_ids=cwe_ids,
            cvss_vector=cvss_vector,
            cwe_profiles=cwe_profiles_list,
            classifier=classifier,
        )
        attack_rb = map_attack(
            ontology_behaviors=behavior.get("mandatory_behaviors", []),
            vulnerability_class=behavior.get("vulnerability_class"),
            cwe_profiles=cwe_profiles_list,
            classifier=classifier,
            ontology_confidence=behavior.get("ontology_confidence") if isinstance(behavior.get("ontology_confidence"), float) else None,
            cve_id=cve_id,
            description=description,
            cvss_vector=cvss_vector,
        )
    except Exception as exc:
        logger.warning("Rule-based fallback failed: %s", exc)
        behavior = {}
        attack_rb = {}

    tech = TechnicalAnalysis(
        family=behavior.get("family"),
        signature=behavior.get("signature"),
        vulnerability_type=behavior.get("vulnerability_type"),
        vulnerability_class=behavior.get("vulnerability_class"),
        exploit_vector=behavior.get("exploit_vector"),
        pre_auth=classifier.get("pre_auth"),
        remote_exploitable=classifier.get("remote_exploitable"),
        exploit_complexity=behavior.get("exploit_complexity") or classifier.get("exploit_complexity"),
        confidence=behavior.get("analysis_confidence") or 0.85,
        likely_outcome=behavior.get("likely_outcome"),
        mandatory_behaviors=behavior.get("mandatory_behaviors"),
        evasive_indicators=behavior.get("evasive_indicators"),
        exploit_requirements=behavior.get("exploit_requirements"),
        cwe_metadata=behavior.get("cwe_metadata"),
        attack_flow=None,
        ai_used=False,
        ai_retry_count=ai_retry_count,
        ai_model=ai_model,
    )

    attack = AttackMapping(
        tactics=attack_rb.get("tactics"),
        techniques=attack_rb.get("techniques"),
        subtechniques=attack_rb.get("subtechniques"),
        confidence=attack_rb.get("confidence"),
        attack_mapping_confidence=attack_rb.get("confidence"),
        mapping_reasons=attack_rb.get("mapping_reasons"),
        ai_used=False,
        ai_retry_count=ai_retry_count,
        ai_model=ai_model,
    )

    return tech, attack


# ==============================================================
# Main entry point
# ==============================================================

async def run_step2_tech_analysis(
    ai_service: AIBehaviorService,
    base_client: BaseAIClient,
    cve_id: str,
    description: str,
    cvss_score: float,
    cvss_vector: str,
    cwe_ids: list[str],
    cpes: list[str],
    references: list[str],
    published_at: str,
    modified_at: str,
    poc_references: list[str] | None = None,
    threat_actors: list[str] | None = None,
) -> tuple[TechnicalAnalysis | None, AttackMapping | None, dict[str, Any]]:
    """Run Step 2 bằng 2-phase AI flow.
    Phase 1 (behavior only) → Phase 2 (ATT&CK mapping với Phase 1 làm anchor).
    Rule-based fallback chỉ chạy khi Phase 1 hoặc cả 2 phase đều fail.
    """
    return await _run_step2_two_phase(
        ai_service=ai_service,
        base_client=base_client,
        cve_id=cve_id,
        description=description,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        cwe_ids=cwe_ids,
        cpes=cpes,
        references=references,
        published_at=published_at,
        modified_at=modified_at,
        poc_references=poc_references,
        threat_actors=threat_actors,
    )


async def _run_step2_two_phase(
    ai_service: AIBehaviorService,
    base_client: BaseAIClient,
    cve_id: str,
    description: str,
    cvss_score: float,
    cvss_vector: str,
    cwe_ids: list[str],
    cpes: list[str],
    references: list[str],
    published_at: str,
    modified_at: str,
    poc_references: list[str] | None = None,
    threat_actors: list[str] | None = None,
) -> tuple[TechnicalAnalysis | None, AttackMapping | None, dict[str, Any]]:
    """Two-phase flow: Phase 1 behavior → Phase 2 ATT&CK.
    Backward compat: returns same tuple shape as legacy flow.
    """
    from app.steps.step_2_tech_analysis.services.phase1_service import AIPhase1Service
    from app.shared.types.execution_surface import DeliveryVector, ExecutionSurface

    # Query CAPEC hints (chi can cho Phase 2)
    capec_hints_by_cwe: dict[str, list[dict]] = {}
    if cwe_ids:
        try:
            from app.shared.mitre.capec_hint import query_capec_for_cwe
            for cwe_id in cwe_ids:
                if not cwe_id or cwe_id.startswith("NVD-CWE"):
                    continue
                hints = query_capec_for_cwe(cwe_id, max_results=3)
                if hints:
                    capec_hints_by_cwe[cwe_id] = hints
        except Exception as exc:
            logger.debug("[Step 2 - Two-Phase] CAPEC hint query skipped: %s", exc)

    # ===== PHASE 1: Behavior Analysis (FACTS only) =====
    phase1_service = AIPhase1Service(base_client)
    try:
        phase1_dict = await phase1_service.fetch_behavior(
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cwe_ids=cwe_ids,
            cpes=cpes,
            references=references,
            published_at=published_at,
            modified_at=modified_at,
            poc_references=poc_references,
            threat_actors=threat_actors,
        )
    except AIServiceError as exc:
        logger.warning(
            "[Step 2 - Two-Phase] Phase 1 failed for %s: %s → rule-based fallback",
            cve_id, exc,
        )
        # Phase 1 fail → fallback rule-based cho toàn bo (cung cap execution_surface
        # qua classify_execution_surface de Phase 2 downstream consumer có data).
        tech, attack = _build_rule_based_pydantic(
            cve_id=cve_id,
            description=description,
            references=references,
            cpes=cpes,
            cvss_vector=cvss_vector,
            cwe_ids=cwe_ids,
            ai_model=None,
            ai_retry_count=0,
        )
        return tech, attack, {
            "overall_coverage": 0.0,
            "verdict": "RULE_BASED_FALLBACK",
            "reason": "phase1_ai_service_error",
        }

    # Phase 1 SUCCESS - chuan hoa dict + apply rule-based fallback cho 3 field moi
    phase1_dict = _normalize_phase1_dict(phase1_dict, cve_id, cwe_ids)
    phase1_dict = _normalize_none_placeholders(phase1_dict)

    # ===== PHASE 2: ATT&CK Mapping (using Phase 1 anchor) =====
    retries_used: int = 0
    try:
        phase2_dict = await ai_service.fetch_attack_mapping(
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cwe_ids=cwe_ids,
            cpes=cpes,
            references=references,
            published_at=published_at,
            modified_at=modified_at,
            poc_references=poc_references,
            threat_actors=threat_actors,
            capec_hints_by_cwe=capec_hints_by_cwe,
            phase1_output=phase1_dict,
        )
    except AIServiceError as exc:
        logger.warning(
            "[Step 2 - Two-Phase] Phase 2 attempt 1 failed for %s: %s",
            cve_id, exc,
        )
        # Retry Phase 2 only (Phase 1 da OK)
        retries_used = 1
        try:
            phase2_dict = await ai_service.fetch_attack_mapping(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cwe_ids=cwe_ids,
                cpes=cpes,
                references=references,
                published_at=published_at,
                modified_at=modified_at,
                poc_references=poc_references,
                threat_actors=threat_actors,
                capec_hints_by_cwe=capec_hints_by_cwe,
                phase1_output=phase1_dict,
            )
        except AIServiceError as exc2:
            logger.warning(
                "[Step 2 - Two-Phase] Phase 2 retry %d failed for %s: %s → rule-based fallback",
                1, cve_id, exc2,
            )
            tech, attack = _build_rule_based_pydantic(
                cve_id=cve_id,
                description=description,
                references=references,
                cpes=cpes,
                cvss_vector=cvss_vector,
                cwe_ids=cwe_ids,
                ai_model=ai_service._MODEL,
                ai_retry_count=retries_used,
            )
            return tech, attack, {
                "validation": {},
                "retries_used": retries_used,
                "verdict": "RULE_BASED_FALLBACK",
                "reason": "phase2_ai_service_error",
            }

    phase2_dict = _normalize_phase2_dict(phase2_dict, cve_id)

    # CRITICAL CVE Override - apply hardcoded ground truth for major CVEs
    attack_block = phase2_dict.get("attack_mapping", {})
    if attack_block:
        phase2_dict["attack_mapping"] = _apply_critical_override(cve_id, attack_block)

    phase2_dict = _enrich_phase2_with_protocol_context(phase2_dict, phase1_dict)

    # NEW: Enrich subtechniques from observable_side_effects (fixes empty subtechniques)
    attack_block = phase2_dict.get("attack_mapping", {})
    if attack_block:
        phase2_dict["attack_mapping"] = _enrich_subtechniques(attack_block, phase1_dict)

    # ===== Combine Phase 1 + Phase 2 =====
    combined_dict = _combine_phase_outputs(phase1_dict, phase2_dict)

    # Track BOTH Phase 1 + Phase 2 models so reports surface which provider
    # ran each phase (e.g. Phase 1 = OpenRouter, Phase 2 = Groq). Dedup
    # preserves order: Phase 1 first, Phase 2 second.
    phase1_model = phase1_service._MODEL
    phase2_model = ai_service._MODEL
    models_used: list[str] = []
    for m in (phase1_model, phase2_model):
        if m and m not in models_used:
            models_used.append(m)
    ai_model = phase2_model  # legacy field = Phase 2 (primary analyze call)
    base_tech = TechnicalAnalysis(
        confidence=phase1_dict.get("confidence") or 0.85,
        pre_auth=phase1_dict.get("pre_auth"),
        remote_exploitable=phase1_dict.get("remote_exploitable"),
        extracted_keywords=phase1_dict.get("extracted_keywords"),
        analysis_confidence=phase1_dict.get("analysis_confidence"),
        classification_reason=phase1_dict.get("classification_reason"),
        behavior_reason=phase1_dict.get("behavior_reason"),
        ai_used=True,
        ai_retry_count=retries_used,
        ai_model=ai_model,
        ai_models_used=models_used,
    )
    base_attack = AttackMapping(
        ai_used=True,
        ai_retry_count=retries_used,
        ai_model=ai_model,
        ai_models_used=models_used,
    )
    final_tech, final_attack = _ai_dict_to_pydantic(
        combined_dict, base_tech, base_attack
    )
    return final_tech, final_attack, {
        "validation": {"valid": True},
        "retries_used": retries_used,
        "verdict": "PASS_TWO_PHASE" if retries_used == 0 else "PASS_TWO_PHASE_AFTER_RETRY",
        "phase1_execution_surface": phase1_dict.get("execution_surface"),
        "phase1_delivery_vector": phase1_dict.get("delivery_vector"),
        "phase1_user_interaction_required": phase1_dict.get("user_interaction_required"),
    }


def _normalize_phase1_dict(
    data: dict[str, Any], cve_id: str, cwe_ids: list[str]
) -> dict[str, Any]:
    """Normalize Phase 1 dict: clean key names, fill rule-based fallback cho
    execution_surface/delivery_vector neu AI de unknown.

    Phase 1 dict structure khac Phase 2 (flat, khong co technical_analysis/attack_mapping
    wrapper). Phase 1 la "behavior only" nen dict shape giong cu, nhung them 3
    field moi o top level.
    """
    if not isinstance(data, dict):
        data = {}

    # Rule-based fallback cho execution_surface / delivery_vector / user_interaction
    desc = data.get("attack_flow", {}).get("entry_vector", "") if isinstance(data.get("attack_flow"), dict) else ""
    # Lay description goc tu data neu co, neu khong lay tu attack_flow
    rule_explanation_desc = data.get("description") or desc
    cvss_vector = data.get("cvss_vector")

    # Neu AI khong set execution_surface, su dung rule-based fallback
    from app.steps.step_2_tech_analysis.rule_based.exploit_classifier import (
        classify_delivery_vector,
        classify_execution_surface,
    )
    if not data.get("execution_surface") or data.get("execution_surface") == "unknown":
        rule_surface = classify_execution_surface(cvss_vector, rule_explanation_desc, cwe_ids)
        if rule_surface.value != "unknown":
            data["execution_surface"] = rule_surface.value
            logger.debug(
                "[Step 2 - Two-Phase] %s execution_surface filled by rule-based: %s",
                cve_id, rule_surface.value,
            )

    # Tuong tu cho delivery_vector (can execution_surface da co)
    if data.get("execution_surface"):
        from app.shared.types.execution_surface import ExecutionSurface
        if not data.get("delivery_vector") or data.get("delivery_vector") == "unknown":
            rule_delivery = classify_delivery_vector(
                cvss_vector, rule_explanation_desc, ExecutionSurface(data["execution_surface"])
            )
            if rule_delivery.value != "unknown":
                data["delivery_vector"] = rule_delivery.value
                logger.debug(
                    "[Step 2 - Two-Phase] %s delivery_vector filled by rule-based: %s",
                    cve_id, rule_delivery.value,
                )

    # Backfill reasoning fields when model omits them.
    classification_reason = data.get("classification_reason")
    if not isinstance(classification_reason, list) or not classification_reason:
        fallback_classification: list[str] = []
        if data.get("vulnerability_class"):
            fallback_classification.append(
                f"vulnerability_class:{data.get('vulnerability_class')}"
            )
        if data.get("vulnerability_type"):
            fallback_classification.append(
                f"vulnerability_type:{data.get('vulnerability_type')}"
            )
        if data.get("execution_surface"):
            fallback_classification.append(
                f"execution_surface:{data.get('execution_surface')}"
            )
        if data.get("delivery_vector"):
            fallback_classification.append(
                f"delivery_vector:{data.get('delivery_vector')}"
            )
        if data.get("pre_auth") is not None:
            fallback_classification.append(f"pre_auth:{data.get('pre_auth')}")
        if data.get("remote_exploitable") is not None:
            fallback_classification.append(
                f"remote_exploitable:{data.get('remote_exploitable')}"
            )
        data["classification_reason"] = fallback_classification

    behavior_reason = data.get("behavior_reason")
    if not isinstance(behavior_reason, list) or not behavior_reason:
        fallback_behavior: list[str] = []
        for behavior in data.get("mandatory_behaviors") or []:
            fallback_behavior.append(f"mandatory_behavior:{behavior}")
        data["behavior_reason"] = fallback_behavior

    if data.get("analysis_confidence") is None and data.get("confidence") is not None:
        data["analysis_confidence"] = data.get("confidence")

    return data


def _normalize_phase2_dict(
    data: dict[str, Any], cve_id: str
) -> dict[str, Any]:
    """Normalize Phase 2 dict: handle Two-Tier format and wrap for _ai_dict_to_pydantic.

    Phase 2 output can be in TWO formats:
    1. NEW Two-Tier format: {primary_techniques, secondary_techniques, ...}
    2. LEGACY flat format: {tactics, techniques, subtechniques, ...}

    This function converts both to the format expected by _ai_dict_to_pydantic:
    {"attack_mapping": {tactics, techniques, subtechniques, ...}}
    """
    if not isinstance(data, dict):
        data = {}

    # Check if Two-Tier format exists (NEW format)
    primary = data.get("primary_techniques") or {}
    secondary = data.get("secondary_techniques") or {}

    if primary or secondary:
        # NEW Two-Tier format detected - flatten to legacy
        primary_techs = primary.get("techniques", []) or []
        primary_subs = primary.get("subtechniques", []) or []
        primary_rationale = primary.get("rationale", "") or ""

        exec_techs = secondary.get("execution", []) or []
        c2_techs = secondary.get("c2", []) or []
        impact_techs = secondary.get("impact", []) or []
        secondary_rationale = secondary.get("rationale", "") or ""

        # Flatten all techniques
        all_techniques = list(primary_techs)
        for t in exec_techs:
            if t not in all_techniques:
                all_techniques.append(t)
        for t in c2_techs:
            if t not in all_techniques:
                all_techniques.append(t)
        for t in impact_techs:
            if t not in all_techniques:
                all_techniques.append(t)

        all_subtechniques = list(primary_subs)

        # Derive tactics from techniques (FIX: was missing before)
        all_tactics = _derive_tactics_from_techniques(all_techniques)

        # Build mapping_reasons with tier context
        mapping_reasons = list(data.get("mapping_reasons") or [])
        if primary_rationale:
            mapping_reasons.append(f"[PRIMARY] {primary_rationale}")
        if secondary_rationale:
            mapping_reasons.append(f"[SECONDARY] {secondary_rationale}")

        # Store Two-Tier data separately for downstream consumers
        attack_mapping_block = {
            "primary_techniques": primary,
            "secondary_techniques": secondary,
            "tactics": all_tactics,  # FIX: Added tactics derivation
            "techniques": all_techniques,
            "subtechniques": all_subtechniques,
            "mapping_reasons": mapping_reasons,
            "confidence": data.get("attack_confidence"),
            "attack_mapping_confidence": data.get("attack_confidence"),
        }
    else:
        # LEGACY flat format - wrap for compatibility
        attack_mapping_block = {
            "techniques": data.get("techniques") or [],
            "subtechniques": data.get("subtechniques") or [],
            "mapping_reasons": data.get("mapping_reasons") or [],
            "confidence": data.get("attack_confidence"),
            "attack_mapping_confidence": data.get("attack_confidence"),
        }

    return {"attack_mapping": attack_mapping_block}


def _enrich_phase2_with_protocol_context(
    phase2: dict[str, Any], phase1: dict[str, Any]
) -> dict[str, Any]:
    """Add protocol-aware secondary ATT&CK sub-techniques when Phase 1 is explicit.

    This keeps T1210/T1190 as primary choices while enriching report depth for
    high-signal protocols (RDP/SMB/SSH/WinRM/FTP) across all CVEs.
    """
    attack = phase2.get("attack_mapping")
    if not isinstance(attack, dict):
        return phase2

    flow = phase1.get("attack_flow") if isinstance(phase1, dict) else {}
    if not isinstance(flow, dict):
        flow = {}
    evidence_text = " ".join(
        [
            str(flow.get("entry_vector") or ""),
            str(flow.get("execution_mechanism") or ""),
        ]
    ).lower()
    if not evidence_text:
        return phase2

    protocol_map: dict[str, tuple[str, str, str]] = {
        "rdp": ("T1021", "T1021.001", "protocol_context:rdp_remote_service"),
        "smb": ("T1021", "T1021.002", "protocol_context:smb_remote_service"),
        "ssh": ("T1021", "T1021.004", "protocol_context:ssh_remote_service"),
        "winrm": ("T1021", "T1021.006", "protocol_context:winrm_remote_service"),
        "ftp": ("T1071", "T1071.002", "protocol_context:ftp_channel"),
    }

    techniques = list(attack.get("techniques") or [])
    subtechniques = list(attack.get("subtechniques") or [])
    tactics = list(attack.get("tactics") or [])  # FIX: Track tactics
    reasons = list(attack.get("mapping_reasons") or [])
    touched = False

    for marker, (parent, sub, reason) in protocol_map.items():
        if marker not in evidence_text:
            continue
        if parent not in techniques:
            techniques.append(parent)
            touched = True
            # FIX: Derive tactic from new technique
            new_tactics = TECHNIQUE_TO_TACTICS.get(parent, [])
            for t in new_tactics:
                if t not in tactics:
                    tactics.append(t)
        if sub not in subtechniques:
            subtechniques.append(sub)
            touched = True
            # FIX: Derive tactic from subtechnique
            new_tactics = TECHNIQUE_TO_TACTICS.get(sub, [])
            for t in new_tactics:
                if t not in tactics:
                    tactics.append(t)
        if reason not in reasons:
            reasons.append(reason)
            touched = True

    if touched:
        attack["techniques"] = techniques
        attack["subtechniques"] = subtechniques
        attack["tactics"] = tactics  # FIX: Update tactics
        attack["mapping_reasons"] = reasons
    return phase2


def _enrich_subtechniques(
    attack_mapping: dict,
    phase1: dict[str, Any],
) -> dict:
    """Tự động bổ sung sub-techniques dựa trên observable_side_effects.

    Fallback khi AI chọn T1059 hoặc T1071 nhưng không emit sub-techniques.
    llama-3.3-70b-versatile tends to be token-conservative.

    Args:
        attack_mapping: Dict chứa techniques và subtechniques
        phase1: Phase 1 output với observable_side_effects

    Returns:
        Dict đã được bổ sung subtechniques
    """
    techniques = list(attack_mapping.get("techniques") or [])
    subtechniques = list(attack_mapping.get("subtechniques") or [])
    tactics = list(attack_mapping.get("tactics") or [])

    # Lấy observable_side_effects từ Phase 1
    flow = phase1.get("attack_flow", {}) if isinstance(phase1, dict) else {}
    if isinstance(flow, dict):
        effects = flow.get("observable_side_effects") or []
        entry_vec = flow.get("entry_vector") or ""
        exec_mech = flow.get("execution_mechanism") or ""
    else:
        effects = []
        entry_vec = ""
        exec_mech = ""

    effects_text = " ".join(effects).lower() if effects else ""
    combined_text = f"{effects_text} {entry_vec} {exec_mech}".lower()

    # Lấy execution_surface từ Phase 1
    exec_surface = phase1.get("execution_surface", "") if isinstance(phase1, dict) else ""

    touched = False

    # T1059 → Sub-techniques dựa trên OS/Interpreter
    if "T1059" in techniques:
        if any(kw in combined_text for kw in ["powershell", "ps1"]):
            if "T1059.001" not in subtechniques:
                subtechniques.append("T1059.001")
                touched = True
        if any(kw in combined_text for kw in ["cmd", "windows", "batch"]):
            if "T1059.003" not in subtechniques:
                subtechniques.append("T1059.003")
                touched = True
        if any(kw in combined_text for kw in ["bash", "shell", "unix", "linux", "/bin"]):
            if "T1059.004" not in subtechniques:
                subtechniques.append("T1059.004")
                touched = True
        if "python" in combined_text:
            if "T1059.006" not in subtechniques:
                subtechniques.append("T1059.006")
                touched = True
        if "javascript" in combined_text or "nodejs" in combined_text:
            if "T1059.007" not in subtechniques:
                subtechniques.append("T1059.007")
                touched = True

    # T1071 → Sub-techniques dựa trên protocol
    if "T1071" in techniques:
        if any(kw in combined_text for kw in ["ldap", "http", "https", "web", "dns", "callback"]):
            if "T1071.001" not in subtechniques:
                subtechniques.append("T1071.001")
                # Derive tactic for subtechnique
                new_tactics = TECHNIQUE_TO_TACTICS.get("T1071.001", [])
                for t in new_tactics:
                    if t not in tactics:
                        tactics.append(t)
                touched = True
        if any(kw in combined_text for kw in ["ftp", "smtp", "file_transfer"]):
            if "T1071.002" not in subtechniques:
                subtechniques.append("T1071.002")
                # Derive tactic for subtechnique
                new_tactics = TECHNIQUE_TO_TACTICS.get("T1071.002", [])
                for t in new_tactics:
                    if t not in tactics:
                        tactics.append(t)
                touched = True

    # T1210 → SMB/RDP exploitation - map to T1021 sub-techniques
    if "T1210" in techniques:
        if "smb" in combined_text:
            if "T1021.002" not in subtechniques:
                subtechniques.append("T1021.002")
                touched = True
        if "rdp" in combined_text:
            if "T1021.001" not in subtechniques:
                subtechniques.append("T1021.001")
                touched = True
        if "ssh" in combined_text:
            if "T1021.004" not in subtechniques:
                subtechniques.append("T1021.004")
                touched = True

    if touched:
        attack_mapping["subtechniques"] = subtechniques
        attack_mapping["tactics"] = tactics
        attack_mapping["_subtechniques_enriched"] = True
        logger.debug(
            "[Step 2 - SUBTECHNIQUE ENRICHMENT] Added: %s",
            attack_mapping.get("subtechniques"),
        )

    return attack_mapping


def _combine_phase_outputs(
    phase1: dict[str, Any], phase2: dict[str, Any]
) -> dict[str, Any]:
    """Combine Phase 1 (behavior) + Phase 2 (attack_mapping) thanh dict giong
    legacy 1-shot output, de _ai_dict_to_pydantic parse duoc.

    Phase 1 dict hien o top level (family, vulnerability_type, attack_flow, ...).
    Phase 2 dict da duoc wrap trong `attack_mapping` boi _normalize_phase2_dict.
    """
    combined = {**phase1, **phase2}
    # Move Phase 1 fields vao technical_analysis wrapper neu can
    # (existing _ai_dict_to_pydantic expects {technical_analysis: {...},
    # attack_mapping: {...}}). Phase 1 fields co the o top level hoac
    # trong technical_analysis - tuy vao implementation. Kiem tra va chuan hoa.
    if "technical_analysis" not in combined:
        # Phase 1 dict co the o flat shape (khong co technical_analysis wrapper)
        # Extract va wrap
        tech_fields = {
            k: combined.pop(k) for k in [
                "family", "signature", "extracted_keywords",
                "vulnerability_type", "vulnerability_class",
                "exploit_vector", "pre_auth", "remote_exploitable",
                "exploit_complexity", "confidence", "execution_surface",
                "delivery_vector", "user_interaction_required",
                "attack_flow", "mandatory_behaviors", "evasive_indicators",
                "exploit_requirements", "cwe_metadata", "reasoning",
                "likely_outcome", "analysis_confidence",
                "classification_reason", "behavior_reason",
            ] if k in combined
        }
        combined["technical_analysis"] = tech_fields
    return combined
