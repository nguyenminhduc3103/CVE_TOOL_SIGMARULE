from __future__ import annotations

from app.shared.models.enriched import EnrichedCVEContext
from app.shared.models.telemetry import SigmaLogsource, TelemetryAssessment, TelemetryRequirements
from app.steps.step_4_telemetry._shared_engines.correlation_advisor import advise_correlation
from app.steps.step_4_telemetry._shared_engines.field_mapper import map_required_fields
from app.steps.step_4_telemetry._shared_engines.logsource_mapper import map_logsources
from app.steps.step_4_telemetry._shared_engines.telemetry_selector import select_detection_axis
from app.steps.step_4_telemetry._shared_engines.taxonomy_validator import validate_fields_by_logsources
from app.steps.step_1_triage.capability_checker import CapabilityClassification


async def run_telemetry_stage(
    context: EnrichedCVEContext,
    capability: CapabilityClassification | None = None,
) -> TelemetryAssessment:
    mandatory_behaviors = context.analysis.mandatory_behaviors if context.analysis else []
    techniques = context.attack.techniques if context.attack else []

    sigma_logsources, required_events, required_event_ids, derived_fields = map_logsources(
        mandatory_behaviors=mandatory_behaviors,
        techniques=techniques,
    )
    categories = [item.category for item in sigma_logsources]
    required_fields = map_required_fields(categories, mandatory_behaviors)
    required_fields = list(dict.fromkeys(required_fields + derived_fields))
    if not categories:
        categories = ["process_creation"]
        sigma_logsources = [SigmaLogsource(category="process_creation", product="windows")]
        required_fields = list(dict.fromkeys(required_fields + ["CommandLine", "Image", "ParentImage"]))
    detection_axis, selector_confidence = select_detection_axis(mandatory_behaviors, categories, techniques)
    correlation_required, notes = advise_correlation(categories)

    validated_fields, invalid_fields, taxonomy_warnings = validate_fields_by_logsources(categories, required_fields)

    pre_exploit_detection = [
        behavior
        for behavior in mandatory_behaviors
        if behavior in {"public_facing_exploit", "web_request", "auth_bypass"}
    ]
    post_exploit_detection = [
        behavior
        for behavior in mandatory_behaviors
        if behavior in {"process_creation", "file_write", "registry_modification", "image_load", "network_callback"}
    ]
    impact_detection = [
        behavior
        for behavior in mandatory_behaviors
        if behavior in {"privilege_escalation", "webshell_drop", "tool_download"}
    ]

    strategy: list[str] = []
    if "web_request" in mandatory_behaviors or "public_facing_exploit" in mandatory_behaviors:
        strategy.append("Web request")
    if "process_creation" in mandatory_behaviors:
        strategy.append("Process creation")
    if "network_callback" in mandatory_behaviors or "network_connection" in mandatory_behaviors:
        strategy.append("Network callback")
    if "privilege_escalation" in mandatory_behaviors:
        strategy.append("Privilege escalation")

    behavior_total = len(mandatory_behaviors or [])
    behavior_detected = len(
        [
            behavior
            for behavior in mandatory_behaviors or []
            if behavior in {"public_facing_exploit", "web_request", "process_creation", "file_write", "registry_modification", "image_load", "network_callback", "privilege_escalation", "webshell_drop"}
        ]
    )
    behavior_coverage = (behavior_detected / behavior_total) if behavior_total else 1.0

    expected_logsources = {
        "webserver" if any(item in (mandatory_behaviors or []) for item in {"public_facing_exploit", "web_request", "webshell_drop"}) else None,
        "process_creation" if any(item in (mandatory_behaviors or []) for item in {"process_creation", "privilege_escalation"}) else None,
        "network_connection" if any(item in (mandatory_behaviors or []) for item in {"network_callback", "network_connection"}) else None,
        "file_event" if "file_write" in (mandatory_behaviors or []) else None,
        "registry_event" if "registry_modification" in (mandatory_behaviors or []) else None,
        "image_load" if "image_load" in (mandatory_behaviors or []) else None,
    }
    expected_logsources = {item for item in expected_logsources if item}
    logsource_coverage = (len(expected_logsources.intersection(set(categories))) / len(expected_logsources)) if expected_logsources else 1.0

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
        telemetry_requirements=TelemetryRequirements(required_event_ids=required_event_ids or None),
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
