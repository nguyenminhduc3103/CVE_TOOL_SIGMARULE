"""Rule-based fallback Detection Logic Planner.

Used when:
- AI is disabled (settings.step6_ai_enabled=False)
- AI call fails (AIServiceError)
- planner_confidence < fallback_threshold

This is a SEMANTIC planner — emits DetectionPlan (intent + logic + risk_bias),
NOT Sigma YAML. The orchestrator's Deterministic Builder still does the actual
Sigma emission downstream.
"""
from __future__ import annotations

from typing import Any

from src.usecases.step_6_generate_sigma._knowledge import loader
from src.usecases.step_6_generate_sigma.domain.detection_plan import (
    DetectionIntent,
    DetectionLogic,
    DetectionPlan,
)


def _list(value: object | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value if item is not None]


def _behaviors_to_intents(mandatory_behaviors: list[str]) -> list[DetectionIntent]:
    """Map each mandatory_behavior → DetectionIntent using KB behaviors.<name>."""
    intents: list[DetectionIntent] = []
    for mb in mandatory_behaviors:
        slug = mb.strip().lower().replace("-", "_").replace(" ", "_")
        kb_entry = loader.get_behavior(slug)
        if kb_entry:
            intents.append(
                DetectionIntent(
                    intent=kb_entry.get("intent", slug),
                    priority="high",
                    rationale=f"mandatory_behavior '{mb}' mapped to KB behavior intent",
                    selection_hint=None,
                )
            )
        else:
            intents.append(
                DetectionIntent(
                    intent=slug,
                    priority="medium",
                    rationale=f"mandatory_behavior '{mb}' (no KB entry, default mapping)",
                    selection_hint=None,
                )
            )
    return intents


def _observable_effects_to_intents(observable_side_effects: list[str]) -> list[DetectionIntent]:
    """Each observable side effect → DetectionIntent."""
    return [
        DetectionIntent(
            intent=effect.lower(),
            priority="high",
            rationale=f"observable side effect from attack_flow: {effect}",
            selection_hint=None,
        )
        for effect in observable_side_effects
    ]


def build_rule_based_plan(
    technical_analysis: dict[str, Any] | None,
    telemetry: dict[str, Any] | None,
    family_signature: str | None = None,
    fallback_reason: str = "AI unavailable or low confidence",
) -> DetectionPlan:
    """Build a rule-based semantic DetectionPlan.

    Source of intents (priority order):
        1. families.<signature>.intents (if family known)
        2. mandatory_behaviors → KB behaviors
        3. attack_flow.observable_side_effects
    """
    technical_analysis = technical_analysis or {}
    telemetry = telemetry or {}

    intents: list[DetectionIntent] = []

    # 1. Family-specific intents from KB
    if family_signature:
        family_entry = loader.get_family(family_signature)
        if family_entry:
            for fam_intent in family_entry.get("intents", []) or []:
                intents.append(
                    DetectionIntent(
                        intent=str(fam_intent.get("intent", "")),
                        priority="high",
                        rationale=f"family '{family_signature}' intent from KB",
                        selection_hint=None,
                    )
                )

    # 2. mandatory_behaviors → KB behaviors
    if not intents:
        mb = _list(technical_analysis.get("mandatory_behaviors"))
        intents.extend(_behaviors_to_intents(mb))

    # 3. observable_side_effects as fallback
    if not intents:
        flow = technical_analysis.get("attack_flow") or {}
        if not isinstance(flow, dict):
            flow = {}
        effects = _list(flow.get("observable_side_effects"))
        intents.extend(_observable_effects_to_intents(effects))

    # If still empty, emit a single generic detection
    if not intents:
        intents = [
            DetectionIntent(
                intent="exploitation_indicator",
                priority="medium",
                rationale="no specific evidence; generic detection emitted as last resort",
                selection_hint=None,
            )
        ]

    # Determine operator from correlation_required
    correlation_required = bool(telemetry.get("correlation_required", False))
    if correlation_required and len(intents) > 1:
        operator = "all"
        operands = list(range(len(intents)))
        threshold = None
    elif len(intents) > 1:
        operator = "any"
        operands = list(range(len(intents)))
        threshold = None
    else:
        operator = "all"
        operands = [0]
        threshold = None

    return DetectionPlan(
        detections=intents,
        logic=DetectionLogic(operator=operator, operands=operands, threshold=threshold),
        falsepositives=["legitimate administrative activity"],
        risk_bias="neutral",
        rationale=f"Rule-based planner used ({fallback_reason}).",
        planner_confidence=0.5,
        source="rule_based",
        ai_model=None,
        ai_retry_count=0,
    )


__all__ = ["build_rule_based_plan"]