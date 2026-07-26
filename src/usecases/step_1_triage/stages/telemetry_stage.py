"""Stage wrapper for Step 4 — Telemetry Assessment.

Refactor 2026-07:
  - AI primary: AITelemetrySelector.select() emit candidate_*, run code layer
    (mapper + validator + feasibility) → TelemetryAssessment.
  - Rule-based fallback: Nếu AI fail → shared_engines rule-based.

Logic cũ (rule-based thuần) preserve 100% làm fallback.
"""
from __future__ import annotations

import logging
from typing import Any

from config.settings import settings
from src.domain.models.enriched import EnrichedCVEContext
from src.domain.models.telemetry import DetectionFeature, SigmaLogsource, TelemetryAssessment
from src.domain.services.capability import CapabilityClassification
from src.infrastructure.ai.core import AIServiceError, BaseAIClient
from src.usecases.step_4_telemetry._shared_engines.correlation_advisor import advise_correlation
from src.usecases.step_4_telemetry._shared_engines.field_mapper import map_required_fields
from src.usecases.step_4_telemetry._shared_engines.logsource_mapper import map_logsources
from src.usecases.step_4_telemetry._shared_engines.taxonomy_validator import validate_fields_by_logsources
from src.usecases.step_4_telemetry._shared_engines.telemetry_feasibility import (
    compute_effective_confidence,
    compute_telemetry_feasibility,
)
from src.usecases.step_4_telemetry._shared_engines.telemetry_selector import select_detection_axis
from src.usecases.step_4_telemetry._resolver import resolve, validate_domains, map_to_sigma
from src.usecases.step_4_telemetry.services.ai_telemetry_service import AITelemetrySelector

logger = logging.getLogger(__name__)


async def run_telemetry_stage(
    context: EnrichedCVEContext,
    capability: CapabilityClassification | None = None,
) -> TelemetryAssessment:
    """Run Step 4 — Telemetry Assessment.

    Args:
        context: EnrichedCVEContext (cần analysis + attack từ Step 2).
        capability: Optional capability classification (gate modifier).

    Returns:
        TelemetryAssessment đã populate. Nếu AI chạy được → ai_used=True.
        Nếu fallback → ai_used=False, telemetry_confidence giảm.
    """
    # AI primary (nếu enabled + có analysis từ Step 2)
    ai_used = False
    ai_attempt_failed = False
    if getattr(settings, "ai_enabled", False) and context.analysis is not None:
        try:
            logger.info(
                "[Stage-4] Attempting AI telemetry selection (model=%s)",
                settings.get_step4_model(),
            )
            client = BaseAIClient()
            ai_selector = AITelemetrySelector(client)
            ai_assessment = await ai_selector.select(
                cve_id=context.core.cve_id,
                analysis=context.analysis,
                attack=context.attack,
            )
            ai_used = True
            # Apply capability modifier
            if capability and capability.value.startswith("out_of_scope"):
                if ai_assessment.telemetry_feasibility_score is not None:
                    ai_assessment.telemetry_feasibility_score = round(
                        ai_assessment.telemetry_feasibility_score * capability.telemetry_modifier,
                        2,
                    )
                if ai_assessment.telemetry_confidence is not None:
                    ai_assessment.telemetry_confidence = round(
                        ai_assessment.telemetry_confidence * capability.telemetry_modifier,
                        2,
                    )
            logger.info(
                "[Stage-4] AI success: feasibility=%.2f confidence=%.2f",
                ai_assessment.telemetry_feasibility_score or 0.0,
                ai_assessment.telemetry_confidence or 0.0,
            )
            return ai_assessment
        except AIServiceError as exc:
            logger.warning(
                "[Stage-4] AI telemetry selection failed: %s → fallback rule-based",
                exc,
            )
            ai_attempt_failed = True
        except Exception as exc:
            logger.warning(
                "[Stage-4] AI telemetry unexpected error: %s → fallback rule-based",
                exc,
            )
            ai_attempt_failed = True

    # Rule-based fallback (legacy path, preserve 100%)
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

    # Compute feasibility_score rule-based (cùng công thức với AI path để consistency)
    feasibility_score_rb, feasibility_breakdown_rb = compute_telemetry_feasibility(
        sigma_logsources=sigma_logsources,
        validated_fields=validated_fields,
        invalid_fields=invalid_fields,
        correlation_required=correlation_required,
        rule_strategy=strategy,
    )

    # Cap bằng legacy `feasibility` để tránh giảm quality cho rule-based path đã mature.
    final_feasibility = round(max(feasibility, feasibility_score_rb), 2)

    # === Refactor 2026-07: KB-resolved fields cho rule-based path ===
    # mandatory_behaviors → canonical domains
    behavior_to_domains: dict[str, list[str]] = {
        "process_creation": ["process"],
        "file_write": ["filesystem"],
        "registry_modification": ["registry"],
        "image_load": ["memory"],
        "network_callback": ["network"],
        "network_connection": ["network"],
        "web_request": ["http"],
        "public_facing_exploit": ["http"],
        "auth_bypass": ["identity"],
        "privilege_escalation": ["identity", "process"],
        "webshell_drop": ["filesystem", "persistence"],
        "ldap_query": ["ldap"],
        "credential_dump": ["credential", "memory"],
        "cloud_api_call": ["cloud"],
        "container_exec": ["container"],
        "k8s_api_call": ["kubernetes"],
    }
    rb_domains: list[str] = []
    for b in mandatory_behaviors or []:
        for d in behavior_to_domains.get(b, []):
            if d not in rb_domains:
                rb_domains.append(d)
    valid_domains, invalid_domains, _ = validate_domains(rb_domains)

    # Resolve → Canonical telemetry (để populate canonical_telemetry, canonical_fields)
    canonical_bundle = resolve(domains=valid_domains or ["process"], attacker_platforms=["windows"])
    rb_canonical_telemetry = [ct.id for ct in canonical_bundle.canonical_telemetry]
    rb_canonical_fields = [cf.canonical for cf in canonical_bundle.canonical_fields]
    rb_skipped = canonical_bundle.skipped_domains

    # Effective confidence cho rule-based path
    rb_effective_confidence = compute_effective_confidence(
        ai_confidence=telemetry_confidence,
        validated_fields=validated_fields,
        invalid_fields=invalid_fields,
        canonical_resolved=len(canonical_bundle.canonical_telemetry),
        canonical_skipped=len(canonical_bundle.skipped_domains),
    )

    # === Telemetry requirements → structured dict ===
    rb_telemetry_requirements: dict[str, list[str]] = {}
    if required_event_ids:
        rb_telemetry_requirements["sysmon"] = [str(e) for e in required_event_ids]
    if required_events:
        rb_telemetry_requirements.setdefault("events", []).extend(required_events)
    # Populate từ canonical telemetry (để Step 6 đọc dễ)
    for ct in canonical_bundle.canonical_telemetry:
        if ct.events:
            rb_telemetry_requirements[ct.id] = [str(e) for e in ct.events]

    # === Phase 6: Rule-based 3-tier features (fix Bug #2) ===
    rb_stable_features: list[DetectionFeature] = []
    rb_conditional_features: list[DetectionFeature] = []
    rb_optional_features: list[DetectionFeature] = []

    # Stable: required event IDs (Windows Security / Sysmon)
    for eid in required_event_ids or []:
        rb_stable_features.append(
            DetectionFeature(
                field='EventID',
                value=str(eid),
                pattern=None,
                rationale=f'Required event {eid} from canonical telemetry — direct artifact',
            )
        )

    # Conditional: behaviors → suspicious indicators (Post-exploit RCE)
    behavior_indicators: dict[str, list[DetectionFeature]] = {
        'process_creation': [
            DetectionFeature(field='Image', value='\\cmd.exe', rationale='Post-exploit shell spawn'),
            DetectionFeature(field='Image', value='\\powershell.exe', rationale='Post-exploit PowerShell'),
        ],
        'privilege_escalation': [
            DetectionFeature(field='Image', value='\\cmd.exe', rationale='PrivEsc result'),
        ],
        'auth_bypass': [
            DetectionFeature(field='CommandLine', pattern='*lsass*', rationale='Credential access after bypass'),
        ],
        'file_write': [
            DetectionFeature(field='TargetFilename', pattern='*.aspx', rationale='Webshell drop'),
        ],
        'registry_modification': [
            DetectionFeature(field='TargetObject', pattern='*\\Run\\*', rationale='Persistence key'),
        ],
        'network_callback': [
            DetectionFeature(field='DestinationPort', value=4444, rationale='Common C2 port'),
        ],
    }
    seen_cond: set[str] = set()
    for b in mandatory_behaviors or []:
        for f in behavior_indicators.get(b, []):
            key = f'{f.field}={f.value or f.pattern}'
            if key not in seen_cond:
                rb_conditional_features.append(f)
                seen_cond.add(key)

    # Optional: easy-to-spoof indicators
    rb_optional_features = [
        DetectionFeature(field='SourceIp', pattern='*', rationale='Easily spoofed via proxy'),
        DetectionFeature(field='UserAgent', pattern='*', rationale='Easily spoofed'),
    ]

    # Rule-based rationale (since AI didn't provide one)
    rb_selection_rationale: list[str] = []
    for ct in canonical_bundle.canonical_telemetry[:5]:
        rb_selection_rationale.append(
            f'{ct.id}: rule-based mapping from mandatory_behaviors'
        )

    return TelemetryAssessment(
        detection_axis=detection_axis or None,
        candidate_logsources=categories or None,
        # NEW: KB-resolved fields
        candidate_telemetry_domains=valid_domains or None,
        canonical_telemetry=rb_canonical_telemetry or None,
        canonical_fields=rb_canonical_fields or None,
        skipped_domains=rb_skipped or None,
        effective_confidence=rb_effective_confidence,
        sigma_logsources=sigma_logsources or None,
        telemetry_requirements=rb_telemetry_requirements,
        pre_exploit_detection=pre_exploit_detection or None,
        post_exploit_detection=post_exploit_detection or None,
        impact_detection=impact_detection or None,
        telemetry_feasibility_score=final_feasibility,
        telemetry_feasibility_breakdown=feasibility_breakdown_rb,
        detection_strategy=strategy or None,
        rule_strategy=strategy or None,
        recommended_rule_strategy=strategy or None,
        stable_features=rb_stable_features or None,
        conditional_features=rb_conditional_features or None,
        optional_features=rb_optional_features or None,
        telemetry_selection_rationale=rb_selection_rationale or None,
        required_events=required_events or None,
        required_fields=validated_fields or None,
        validated_fields=validated_fields or None,
        invalid_fields=invalid_fields or None,
        taxonomy_warnings=taxonomy_warnings or None,
        telemetry_confidence=telemetry_confidence,
        correlation_required=correlation_required,
        field_taxonomy_notes=(notes + taxonomy_warnings) or None,
        ai_used=ai_used,
        ai_retry_count=0,
        ai_model=None,  # Rule-based fallback không có AI model
    )
