from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.domain.models.enriched import EnrichedCVEContext
from src.domain.models.telemetry import SigmaLogsource, TelemetryAssessment, TelemetryRequirements
from src.usecases.step_4_telemetry._shared_engines.correlation_advisor import advise_correlation
from src.usecases.step_4_telemetry._shared_engines.field_mapper import map_required_fields
from src.usecases.step_4_telemetry._shared_engines.logsource_mapper import map_logsources, extract_events_from_logsources
from src.usecases.step_4_telemetry._shared_engines.telemetry_selector import select_detection_axis
from src.usecases.step_4_telemetry._shared_engines.taxonomy_validator import validate_fields_by_logsources, validate_logsources_by_cpe, validate_logsources_by_cvss
from src.domain.services.capability import CapabilityClassification

# Nạp detection_phase_definitions từ sigma_taxonomy_mappings.json — không hardcode
_DEFAULTS_FILE = Path(__file__).resolve().parents[2] / "infrastructure" / "local_truth" / "sigma_taxonomy_mappings.json"


def _load_detection_phases() -> dict[str, set[str]]:
    """Nạp detection_phase_definitions từ JSON: pre_exploit, post_exploit, impact → set of behaviors."""
    try:
        with open(_DEFAULTS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        phases = data.get("detection_phase_definitions", {})
        return {
            phase: set(behaviors)
            for phase, behaviors in phases.items()
            if not phase.startswith("_") and isinstance(behaviors, list)
        }
    except (OSError, json.JSONDecodeError):
        # Fallback tối thiểu nếu file không đọc được
        return {
            "pre_exploit": {"public_facing_exploit", "web_request", "auth_bypass"},
            "post_exploit": {"process_creation", "file_write", "registry_modification", "image_load", "network_callback"},
            "impact": {"privilege_escalation", "webshell_drop", "tool_download"},
        }


# Nạp 1 lần khi import module
_DETECTION_PHASES: dict[str, set[str]] = _load_detection_phases()

_CWE_TO_ATTACK_FILE = Path(__file__).resolve().parents[2] / "infrastructure" / "local_truth" / "cwe_to_attack.json"

def _load_cwe_to_attack() -> dict[str, list[str]]:
    """Nạp mapping CWE -> MITRE từ file JSON trích xuất từ CAPEC."""
    try:
        with open(_CWE_TO_ATTACK_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}

_CWE_TO_ATTACK: dict[str, list[str]] = _load_cwe_to_attack()

def _determine_smart_fallback(cpes: list[str], cvss_vector: str | None, cwe_ids: list[str] | None) -> list[str]:
    """Layer 2 Fallback Heuristics: Suy luận logsource từ CWE, CPE và CVSS Multi-Metric (AV, UI, PR, I/S)."""
    fallback_cats = set()
    
    # 1. CWE Heuristics
    cwe_str = " ".join(cwe_ids or []).upper()
    if any(cwe in cwe_str for cwe in ["CWE-89", "CWE-79", "CWE-22", "CWE-352", "CWE-611", "CWE-94"]):
        fallback_cats.add("webserver")
    if any(cwe in cwe_str for cwe in ["CWE-78", "CWE-502", "CWE-269"]):
        fallback_cats.add("process_creation")
    if "CWE-434" in cwe_str:
        fallback_cats.add("file_event")
        fallback_cats.add("webserver")

    # 2. CPE Heuristics
    cpe_str = " ".join(cpes or []).lower()
    web_keywords = {"apache", "nginx", "iis", "tomcat", "wordpress", "php", "f5", "citrix", "weblogic"}
    if any(kw in cpe_str for kw in web_keywords):
        fallback_cats.add("webserver")

    # 3. CVSS Multi-Metric Heuristics (AV, UI, PR, I/S)
    if cvss_vector:
        from src.shared.parsers.cvss_parser import parse_cvss_vector
        cvss_metrics = parse_cvss_vector(cvss_vector)

        # Chiều 1: Attack Vector (AV)
        av = cvss_metrics.get("AV")
        if av in ("N", "A"):
            fallback_cats.add("network_connection")
        elif av in ("L", "P"):
            fallback_cats.add("process_creation")

        # Chiều 2: User Interaction (UI) -> Yêu cầu tương tác / Client-side
        if cvss_metrics.get("UI") == "R":
            fallback_cats.update(["file_event", "process_creation"])

        # Chiều 3: Privileges Required (PR)
        pr = cvss_metrics.get("PR")
        if pr in ("L", "H"):
            fallback_cats.update(["authentication", "process_creation"])
        elif pr == "N" and av == "N":
            fallback_cats.update(["webserver", "network_connection"])

        # Chiều 4: Integrity Impact (I / VI) & Scope (S)
        integrity = cvss_metrics.get("I") or cvss_metrics.get("VI")
        if integrity == "H":
            fallback_cats.update(["file_event", "file_change"])
            if "windows" in cpe_str:
                fallback_cats.add("registry_event")
        if cvss_metrics.get("S") == "C":
            fallback_cats.update(["process_creation", "network_connection"])

    # 4. Default safe-net
    if not fallback_cats:
        fallback_cats.update(["process_creation", "network_connection"])
        
    return list(fallback_cats)

# Tập hợp tất cả behaviors đã định nghĩa (dùng cho tính coverage)
_ALL_KNOWN_BEHAVIORS: set[str] = set()
for _phase_behaviors in _DETECTION_PHASES.values():
    _ALL_KNOWN_BEHAVIORS.update(_phase_behaviors)


def _classify_behaviors(mandatory_behaviors: list[str]) -> dict[str, list[str]]:
    """Phân loại behaviors vào detection phases dựa trên cấu hình JSON."""
    result: dict[str, list[str]] = {phase: [] for phase in _DETECTION_PHASES}
    for behavior in mandatory_behaviors:
        for phase, phase_behaviors in _DETECTION_PHASES.items():
            if behavior in phase_behaviors:
                result[phase].append(behavior)
                break  # Mỗi behavior chỉ thuộc 1 phase
    return result


async def run_telemetry_stage(
    context: EnrichedCVEContext,
    capability: CapabilityClassification | None = None,
) -> TelemetryAssessment:
    mandatory_behaviors = context.analysis.mandatory_behaviors if context.analysis else []
    techniques = context.attack.techniques if context.attack else []

    # Layer 1: CAPEC STIX Enrichment
    cwe_ids = context.core.cwe_ids if context.core else []
    if cwe_ids:
        for cwe in cwe_ids:
            if cwe in _CWE_TO_ATTACK:
                for tech in _CWE_TO_ATTACK[cwe]:
                    if tech not in techniques:
                        techniques.append(tech)

    # 1. Candidate selection (Layer 1 STIX techniques & mandatory behaviors)
    sigma_logsources, _, _ = map_logsources(
        mandatory_behaviors=mandatory_behaviors,
        techniques=techniques,
    )

    # 2. Lọc logsource qua CPE & CVSS
    cpes = context.core.cpes if context.core else []
    cvss_vector = context.core.cvss_vector if context.core else None
    sigma_logsources, _, cpe_warnings = validate_logsources_by_cpe(sigma_logsources, cpes)
    sigma_logsources, _, cvss_warnings = validate_logsources_by_cvss(sigma_logsources, cvss_vector)

    # 3. Layer 2: Smart Fallback (nếu toàn bộ logsource bị trống hoặc bị xoá sau khi lọc)
    if not sigma_logsources:
        fallback_cats = _determine_smart_fallback(cpes, cvss_vector, cwe_ids)
        fallback_ls, _, _ = map_logsources(categories=fallback_cats)
        sigma_logsources, _, cpe_warnings = validate_logsources_by_cpe(fallback_ls, cpes)
        sigma_logsources, _, cvss_warnings = validate_logsources_by_cvss(sigma_logsources, cvss_vector)

    # 4. Đồng bộ chính xác Event, Event ID và Field CHỈ từ các logsource ĐÃ VƯỢT QUA BỘ LỌC
    categories = list(dict.fromkeys(ls.category for ls in sigma_logsources))
    required_events, required_event_ids = extract_events_from_logsources(sigma_logsources)
    required_fields = map_required_fields(categories, use_core_only=True)

    detection_axis, selector_confidence = select_detection_axis(mandatory_behaviors, categories, techniques)
    correlation_required, notes = advise_correlation(categories)

    target_products = {ls.product for ls in sigma_logsources if ls.product}
    validated_fields, invalid_fields, taxonomy_warnings = validate_fields_by_logsources(
        categories, required_fields, target_products=target_products
    )
    
    # 5. Deduplicate warnings
    taxonomy_warnings = list(dict.fromkeys(cpe_warnings + cvss_warnings + taxonomy_warnings))

    # Phân loại behaviors vào detection phases (đọc từ JSON, không hardcode)
    phase_classification = _classify_behaviors(mandatory_behaviors or [])
    pre_exploit_detection = phase_classification.get("pre_exploit", [])
    post_exploit_detection = phase_classification.get("post_exploit", [])
    impact_detection = phase_classification.get("impact", [])

    # Tự động tạo strategy từ categories
    strategy: list[str] = []
    for cat in categories:
        label = cat.replace("_", " ").capitalize()
        if label not in strategy:
            strategy.append(label)

    # Bổ sung thêm các strategy đặc thù từ impact (nếu có)
    if "privilege_escalation" in impact_detection and "Privilege escalation" not in strategy:
        strategy.append("Privilege escalation")

    # Coverage tính toán
    behavior_total = len(mandatory_behaviors or [])
    behavior_detected = len([b for b in (mandatory_behaviors or []) if b in _ALL_KNOWN_BEHAVIORS])
    behavior_coverage = (behavior_detected / behavior_total) if behavior_total else 1.0

    # Expected logsources dựa trên BEHAVIOR_TO_CATEGORY (nạp từ JSON)
    from src.usecases.step_4_telemetry._shared_engines.logsource_mapper import BEHAVIOR_TO_CATEGORY
    expected_logsources: set[str] = set()
    for behavior in mandatory_behaviors or []:
        cat = BEHAVIOR_TO_CATEGORY.get(behavior)
        if cat:
            expected_logsources.add(cat)

    logsource_coverage = (
        len(expected_logsources.intersection(set(categories))) / len(expected_logsources)
    ) if expected_logsources else 1.0

    total_fields = len(validated_fields) + len(invalid_fields)
    field_validation_score = (len(validated_fields) / total_fields) if total_fields else 1.0

    telemetry_confidence = round(
        min(
            0.98,
            (0.45 * behavior_coverage) + (0.35 * logsource_coverage) + (0.2 * field_validation_score),
        ),
        2,
    )
    telemetry_confidence = round((telemetry_confidence + selector_confidence) / 2, 2)
    feasibility = telemetry_confidence

    if capability and capability.value.startswith("out_of_scope"):
        telemetry_confidence = round(telemetry_confidence * capability.telemetry_modifier, 2)
        feasibility = round(feasibility * capability.telemetry_modifier, 2)

    return TelemetryAssessment(
        detection_axis=detection_axis or None,
        candidate_logsources=categories or None,
        sigma_logsources=sigma_logsources or None,
        telemetry_requirements=TelemetryRequirements(
            required_event_ids=required_event_ids or None,
            required_events=required_events or None,
            required_fields=validated_fields or None,
        ),
        pre_exploit_detection=pre_exploit_detection or None,
        post_exploit_detection=post_exploit_detection or None,
        impact_detection=impact_detection or None,
        telemetry_feasibility_score=round(feasibility, 2),
        detection_strategy=strategy or None,
        required_events=required_events or None,
        required_fields=validated_fields or None,
        validated_fields=validated_fields or None,
        invalid_fields=invalid_fields or None,
        taxonomy_warnings=taxonomy_warnings or None,
        telemetry_confidence=telemetry_confidence,
        correlation_required=correlation_required,
        field_taxonomy_notes=(notes + taxonomy_warnings) or None,
    )
