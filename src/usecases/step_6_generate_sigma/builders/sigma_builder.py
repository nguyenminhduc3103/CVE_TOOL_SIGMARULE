"""Phase D — Deterministic Sigma Rule Builder.

Consumes: DetectionPlan + TelemetryAssessment + TechnicalAnalysis + KB + CoreCVEData.
Produces: SigmaRule list + YAML + LevelResolution. Zero AI involvement.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from src.domain.models.attack import AttackMapping, TechnicalAnalysis
from src.domain.models.cve import CoreCVEData
from src.usecases.step_6_generate_sigma._knowledge import loader
from src.usecases.step_6_generate_sigma._shared_engines.correlation.correlation_models import (
    SigmaCorrelationBlock,
)
from src.usecases.step_6_generate_sigma._shared_engines.models.sigma_detection import (
    SigmaDetection,
)
from src.usecases.step_6_generate_sigma._shared_engines.models.sigma_metadata import (
    SigmaMetadata,
)
from src.usecases.step_6_generate_sigma._shared_engines.models.sigma_rule import (
    SigmaRule,
)
from src.usecases.step_6_generate_sigma._shared_engines.serializers.yaml_serializer import (
    SigmaYamlSerializer,
)
from src.usecases.step_6_generate_sigma.domain.detection_plan import DetectionPlan
from src.usecases.step_6_generate_sigma.services.condition_renderer import (
    render_condition,
)
from src.usecases.step_6_generate_sigma.services.intent_mapper import (
    IntentResolution,
    _intent_slug,
    map_all_intents,
)
from src.usecases.step_6_generate_sigma.services.level_resolver import (
    resolve_level,
)

logger = logging.getLogger(__name__)


def _get_attr(obj: object | None, key: str, default: object | None = None) -> object | None:
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _list(value: object | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value if item is not None]


def _normalize_slug(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower().replace(".", "_").replace("-", "_")
    return text or None


def _display(value: str | None) -> str:
    if not value:
        return ""
    return " ".join(part.capitalize() for part in value.replace("_", " ").split())


def _generate_title(
    cve_id: str,
    family: str | None,
    signature: str | None,
    intent_count: int,
    correlation_required: bool,
) -> str:
    label = _display(signature or family) or "Exploitation"
    if correlation_required:
        return f"{label} Multi-Stage Correlation Attempt"
    if intent_count > 1:
        return f"{label} Combined Detection Attempt"
    return f"{label} Attempt"


def _generate_description(
    cve_id: str,
    analysis: TechnicalAnalysis | dict[str, object] | None,
    attack: AttackMapping | dict[str, object] | None,
    telemetry: dict[str, Any] | None,
    intent_count: int,
    correlation_required: bool,
) -> str:
    family = _normalize_slug(_get_attr(analysis, "family")) or _normalize_slug(_get_attr(analysis, "signature"))
    vuln_type = _get_attr(analysis, "vulnerability_type")
    outcomes = _list(_get_attr(analysis, "mandatory_behaviors"))
    summary = (
        f"Detects exploit activity for {cve_id} ({_display(family) or 'unknown family'}). "
        f"Vulnerability class: {vuln_type or 'unspecified'}. "
        f"Behaviors: {', '.join(outcomes) if outcomes else 'n/a'}."
    )

    # Append CVE id (out of `tags` because SigmaValidator.TAG_PATTERN rejects cve.*)
    if cve_id:
        summary = f"{summary} CVE: {cve_id}."

    techniques = _list(_get_attr(attack, "techniques"))
    lines = [summary]
    if techniques:
        lines.append(f"ATT&CK techniques: {', '.join(techniques)}.")
    if correlation_required:
        lines.append("Correlation rule joins multiple sub-rules within the timespan.")
    elif intent_count > 1:
        lines.append("Single-event rule fires on combined detection logic.")
    return "\n".join(lines)


def _build_tags(attack: AttackMapping | dict[str, object] | None, cve_id: str) -> list[str]:
    """Emit only ATT&CK technique tags.

    Validator rejects cve.*; cve id goes to description, correlation via x_* flags.
    """
    techniques: list[str] = []
    seen: set[str] = set()
    for tech in _list(_get_attr(attack, "techniques")):
        key = tech.lower()
        if key not in seen:
            seen.add(key)
            techniques.append(f"attack.{key}")
    return techniques


def _generate_references(
    cve_id: str,
    analysis: TechnicalAnalysis | dict[str, object] | None,
    telemetry: dict[str, Any] | None,
) -> list[str]:
    refs: list[str] = [f"https://nvd.nist.gov/vuln/detail/{cve_id}"]
    extra = _list(_get_attr(analysis, "references"))
    for r in extra:
        if r and r not in refs:
            refs.append(r)
    return refs


def _generate_rule_id(cve_id: str, title: str, tags: list[str]) -> str:
    basis = f"{cve_id}:{title}:{','.join(tags)}"
    return str(uuid5(NAMESPACE_URL, basis))


# Built-in fallback alias map for common vendor field names that the AI may
# emit without a corresponding Step 4 ``field_name_map`` entry. Step 4's map
# takes precedence when present; this is the safety net.
_BUILTIN_FIELD_ALIASES: dict[str, str] = {
    # Web / HTTP
    "uri": "cs-uri-stem",
    "request": "cs-uri-stem",
    "request_uri": "cs-uri-stem",
    "uri_query": "cs-uri-query",
    "cs_uri_stem": "cs-uri-stem",
    "cs_uri_query": "cs-uri-query",
    "cs_uri_stem_query": "cs-uri-stem",
    "url": "cs-uri-stem",
    "url_original": "url.original",
    "request_method": "cs-method",
    "http_method": "cs-method",
    "method": "cs-method",
    "useragent": "UserAgent",
    "user_agent": "UserAgent",
    # Network
    "destinationport": "DestinationPort",
    "dest_port": "DestinationPort",
    "destination_port": "DestinationPort",
    "destinationip": "DestinationIp",
    "destination_ip": "DestinationIp",
    "dest_ip": "DestinationIp",
    "sourceip": "SourceIp",
    "source_ip": "SourceIp",
    "src_ip": "SourceIp",
    "sourceport": "SourcePort",
    "source_port": "SourcePort",
    "src_port": "SourcePort",
    # Process
    "image": "Image",
    "process_image": "Image",
    "commandline": "CommandLine",
    "cmd": "CommandLine",
    "command_line": "CommandLine",
    "parentimage": "ParentImage",
    "parent_image": "ParentImage",
    "parentcommandline": "ParentCommandLine",
    "parent_command_line": "ParentCommandLine",
    # DNS
    "queryname": "QueryName",
    "query_name": "QueryName",
    "dns_query": "QueryName",
    # Auth / Identity
    "targetusername": "TargetUserName",
    "target_user": "TargetUserName",
    "subjectusername": "SubjectUserName",
    "subject_user": "SubjectUserName",
    # File / Registry
    "targetfilename": "TargetFilename",
    "target_filename": "TargetFilename",
    "targetobject": "TargetObject",
    "target_object": "TargetObject",
}


def _resolve_intent_field_alias(
    key: str,
    field_name_map: dict[str, str] | None,
) -> str:
    """Translate a selection_hint key (e.g. ``Uri``, ``DestinationPort|contains``)
    to the Sigma field name produced by Step 4 (e.g. ``cs-uri-stem``).

    Modifier suffixes (``|contains``, ``|endswith``, ``|startswith``, ``|re``) are
    stripped first; lookup is case-insensitive; the modifier is re-applied.

    Lookup priority:
      1. Step 4's ``field_name_map`` (canonical source of truth).
      2. Built-in ``_BUILTIN_FIELD_ALIASES`` fallback for common vendor names
         when Step 4 didn't produce a ``field_name_map``.

    Idempotent: a miss returns the input unchanged so AI-emitted Sigma-form keys
    pass through.
    """
    field_part, _, modifier = key.partition("|")
    if not field_part:
        return key

    target: str | None = None
    if field_name_map:
        target = (
            field_name_map.get(field_part)
            or field_name_map.get(field_part.lower())
        )
    if not target:
        builtin = _BUILTIN_FIELD_ALIASES
        target = builtin.get(field_part) or builtin.get(field_part.lower())
    new_field = target or field_part
    return f"{new_field}|{modifier}" if modifier else new_field


def _pick_logsource_for_intent(
    intent_text: str,
    resolutions: list[IntentResolution],
    telemetry: dict[str, Any],
    plan: DetectionPlan,
) -> dict[str, str]:
    """Per-intent Sigma logsource.

    Resolution order:
      1. ``IntentResolution`` matching ``intent_text`` (per-intent, set via
         family KB ``domain_hint``).
      2. ``_pick_logsource`` fallback (first resolved, then first
         ``sigma_logsources[0]``).
      3. ``{"category": "process_creation", "product": "windows"}``.
    """
    DEFAULT = {"category": "process_creation", "product": "windows"}
    slug = _intent_slug(intent_text)
    for res in resolutions:
        if _intent_slug(getattr(res, "intent", "")) != slug:
            continue
        if not getattr(res, "resolved", False):
            continue
        ls = getattr(res, "canonical_logsource", None)
        if ls and ls.get("category"):
            return dict(ls)
    return _pick_logsource(plan, telemetry) or DEFAULT


def _build_selections(
    plan: DetectionPlan,
    telemetry: dict[str, Any] | None,
    family_signature: str | None,
) -> dict[str, dict[str, list[str]]]:
    """Build Sigma selections dict from DetectionPlan.

    Fallback chain (first non-empty wins): selection_hint → stable_features →
    conditional_features → required_events → validated_fields → wildcard.
    """
    selections: dict[str, dict[str, list[str]]] = {}
    telemetry = telemetry or {}
    field_name_map = telemetry.get("field_name_map") or {}
    stable_features = telemetry.get("stable_features") or []
    conditional_features = telemetry.get("conditional_features") or []
    required_events = telemetry.get("required_events") or []
    validated_fields = telemetry.get("validated_fields") or []

    for idx, intent in enumerate(plan.detections):
        selection_name = f"sel_{idx}"
        # 1. AI selection_hint (preferred) — keys translated via Step 4 field_name_map.
        # Colliding keys (different AI keys → same Sigma field) merge value lists.
        if intent.selection_hint:
            merged: dict[str, list[str]] = {}
            for k, vs in intent.selection_hint.items():
                aliased = _resolve_intent_field_alias(k, field_name_map)
                merged.setdefault(aliased, []).extend(str(v) for v in vs)
            selections[selection_name] = merged
            continue

        # 2. stable_features — exact match (canonical field → Sigma alias)
        if stable_features:
            fields: dict[str, list[str]] = {}
            for feat in stable_features:
                field = getattr(feat, "field", None)
                if not field:
                    continue
                vals = _feature_values(feat)
                if vals:
                    fields[_resolve_intent_field_alias(field, field_name_map)] = vals
            if fields:
                selections[selection_name] = fields
                continue

        # 3. conditional_features — with modifier (canonical field → Sigma alias first)
        if conditional_features:
            fields = {}
            for feat in conditional_features:
                field = getattr(feat, "field", None)
                if not field:
                    continue
                vals = _feature_values(feat)
                if not vals:
                    continue
                modifier = _infer_modifier(feat)
                aliased = _resolve_intent_field_alias(field, field_name_map)
                key = f"{aliased}|{modifier}" if modifier else aliased
                fields[key] = vals
            if fields:
                selections[selection_name] = fields
                continue

        # 4. required_events → EventID
        if required_events:
            event_ids = [str(ev) for ev in required_events if str(ev).isdigit()]
            if event_ids:
                selections[selection_name] = {"EventID": event_ids}
                continue

        # 5. validated_fields wildcard
        if validated_fields:
            selections[selection_name] = {
                f: ["*"] for f in validated_fields[:3]
            }
            logger.warning(
                "selection_hint empty for intent[%d] '%s'; falling back to validated_fields wildcard",
                idx, intent.intent,
            )
            continue

        # 6. last resort: EventID wildcard
        selections[selection_name] = {"EventID": ["*"]}
        logger.warning(
            "selection_hint and all telemetry features empty for intent[%d] '%s'; using wildcard",
            idx, intent.intent,
        )

    return selections


def _feature_values(feat: Any) -> list[str]:
    """Extract string values from a DetectionFeature (value may be str | list[str] | int)."""
    val = getattr(feat, "value", None)
    if val is None:
        pattern = getattr(feat, "pattern", None)
        if pattern:
            return [str(pattern)]
        return []
    if isinstance(val, list):
        return [str(v) for v in val if v is not None]
    return [str(val)]


def _infer_modifier(feat: Any) -> str | None:
    """Infer Sigma modifier from a conditional feature based on its rationale/pattern."""
    rationale = (getattr(feat, "rationale", "") or "").lower()
    if "endswith" in rationale or "ends with" in rationale or "suffix" in rationale:
        return "endswith"
    if "startswith" in rationale or "starts with" in rationale or "prefix" in rationale:
        return "startswith"
    if "contains" in rationale or "substring" in rationale:
        return "contains"
    return None


def _family_correlation_block(
    family_signature: str | None,
    correlation_required: bool,
) -> SigmaCorrelationBlock | None:
    if not correlation_required:
        return None
    family_entry = loader.get_family(family_signature) if family_signature else None
    hints = loader.get_correlation_hints() or {}
    if family_entry and family_entry.get("correlation"):
        fc = family_entry["correlation"]
        return SigmaCorrelationBlock(
            type=str(fc.get("type", hints.get("default_correlation_type", "temporal_ordered"))),
            timespan=str(fc.get("timespan", hints.get("default_timespan", "5m"))),
            rules=[],
        )
    return SigmaCorrelationBlock(
        type=str(hints.get("default_correlation_type", "temporal_ordered")),
        timespan=str(hints.get("default_timespan", "5m")),
        rules=[],
    )


def build_sigma_rule(
    plan: DetectionPlan,
    core: CoreCVEData,
    analysis: TechnicalAnalysis | dict[str, object] | None,
    attack: AttackMapping | dict[str, object] | None,
    telemetry: dict[str, Any] | None,
    completeness_validation: object | None = None,
    family_signature: str | None = None,
) -> tuple[list[SigmaRule], str, Any]:
    """Build SigmaRule(s) + YAML + LevelResolution.

    Returns:
        (rules, yaml_output, level_resolution)
    """
    cve_id = _get_attr(core, "cve_id") or "CVE-UNKNOWN"
    cvss_score = _get_attr(core, "cvss_score")
    severity = _get_attr(core, "severity")
    vuln_type = _get_attr(analysis, "vulnerability_type")
    family = _normalize_slug(_get_attr(analysis, "family"))
    signature = _normalize_slug(_get_attr(analysis, "signature")) or family_signature

    telemetry = telemetry or {}
    correlation_required = bool(telemetry.get("correlation_required", False))
    pipeline_feasibility = telemetry.get("pipeline_feasibility") or telemetry.get("telemetry_feasibility_score")

    # completeness level (Phase C) used as Level cap
    completeness_level = None
    if completeness_validation is not None:
        completeness_level = getattr(completeness_validation, "level", None)

    level_res = resolve_level(
        vulnerability_type=vuln_type,
        cvss_score=float(cvss_score) if cvss_score is not None else None,
        severity=str(severity) if severity is not None else None,
        correlation_required=correlation_required,
        risk_bias=plan.risk_bias,
        pipeline_feasibility=pipeline_feasibility,
        completeness_level=completeness_level,
    )

    # Build selections
    selections = _build_selections(plan, telemetry, family_signature or signature)

    # Metadata fields
    title = _generate_title(cve_id, family, signature, len(plan.detections), correlation_required)
    description = _generate_description(cve_id, analysis, attack, telemetry, len(plan.detections), correlation_required)
    tags = _build_tags(attack, cve_id)
    references = _generate_references(cve_id, analysis, telemetry)
    date = datetime.now(timezone.utc).strftime("%Y/%m/%d")

    # Decide rule structure: cross-event correlation vs single-event
    if correlation_required and len(plan.detections) > 1:
        rendered = render_condition(plan.logic, plan.detections)
        block = _family_correlation_block(family_signature or signature, correlation_required)

        # Sub-rules: each intent → one sub-rule (per-intent logsource via IntentMapper)
        rules_list: list[SigmaRule] = []
        sub_ids: list[str] = []
        resolutions = map_all_intents(
            plan.detections,
            telemetry,
            family_signature or signature,
            family,
        )
        selected_logsource = _pick_logsource(
            plan,
            telemetry,
            family_signature or signature,
            family,
        )

        for idx, intent in enumerate(plan.detections):
            sub_title = f"{title} (Component {idx})"
            sub_id = _generate_rule_id(cve_id, sub_title, tags)
            sub_ids.append(sub_id)
            sub_selections = {f"sel_{idx}": selections.get(f"sel_{idx}", {})}
            sub_detection = SigmaDetection(
                selections=sub_selections,
                condition=f"sel_{idx}",
            )
            sub_metadata = SigmaMetadata(
                title=sub_title,
                id=sub_id,
                status="experimental",
                description=description,
                references=references,
                author=_get_attr(core, "author") or "cve-ti-platform",
                date=date,
                tags=tags,
                falsepositives=list(plan.falsepositives) or ["legitimate administrative activity"],
                level=level_res.level,
                related=[],
            )
            sub_logsource = _pick_logsource_for_intent(
                intent.intent, resolutions, telemetry, plan,
            )
            rules_list.append(
                SigmaRule(
                    metadata=sub_metadata,
                    logsource=sub_logsource,
                    detection=sub_detection,
                    x_family=family or "generic",
                    x_signature=signature or family or "generic",
                    x_detection_confidence=plan.planner_confidence,
                    x_correlation_required=False,
                    x_correlation_logic=False,
                    x_correlation_reasoning=f"sub-rule of multi-stage correlation ({rendered.human})",
                    x_secondary_logsources=[],
                    x_ai_used=plan.source == "ai",
                    x_ai_model=plan.ai_model,
                )
            )

        # Parent correlation rule
        corr_title = f"{title} (Correlation)"
        corr_id = _generate_rule_id(cve_id, corr_title, tags)
        corr_metadata = SigmaMetadata(
            title=corr_title,
            id=corr_id,
            status="experimental",
            description=description,
            references=references,
            author=_get_attr(core, "author") or "cve-ti-platform",
            date=date,
            tags=tags,
            falsepositives=list(plan.falsepositives) or ["legitimate administrative activity"],
            level=level_res.level,
            related=[],
        )
        # Parent correlation rule: empty detection (block replaces it), but logsource must be set (validator requires).
        parent_rule = SigmaRule(
            metadata=corr_metadata,
            logsource=dict(selected_logsource) if selected_logsource else _pick_logsource(plan, telemetry),
            detection=SigmaDetection(selections={}, condition=""),
            x_family=family or "generic",
            x_signature=signature or family or "generic",
            x_detection_confidence=plan.planner_confidence,
            x_correlation_required=True,
            x_correlation_logic=True,
            x_correlation_reasoning=rendered.human,
            x_secondary_logsources=[],
            x_ai_used=plan.source == "ai",
            x_ai_model=plan.ai_model,
        )
        rules_list.append(parent_rule)

        # Wire correlation block
        if block is not None:
            block.rules = sub_ids

        yaml = _serialize_rules(rules_list, correlation_block=block)
        return rules_list, yaml, level_res

    # Single-event rule path
    logsource = _pick_logsource(
        plan, telemetry, family_signature or signature, family,
    )
    rendered = render_condition(plan.logic, plan.detections)
    detection = SigmaDetection(
        selections=selections,
        condition=rendered.condition,
    )
    metadata = SigmaMetadata(
        title=title,
        id=_generate_rule_id(cve_id, title, tags),
        status="experimental",
        description=description,
        references=references,
        author=_get_attr(core, "author") or "cve-ti-platform",
        date=date,
        tags=tags,
        falsepositives=list(plan.falsepositives) or ["legitimate administrative activity"],
        level=level_res.level,
        related=[],
    )
    rule = SigmaRule(
        metadata=metadata,
        logsource=dict(logsource) if logsource else {},
        detection=detection,
        x_family=family or "generic",
        x_signature=signature or family or "generic",
        x_detection_confidence=plan.planner_confidence,
        x_correlation_required=correlation_required,
        x_correlation_logic=correlation_required,
        x_correlation_reasoning=rendered.human if correlation_required else "",
        x_secondary_logsources=[],
        x_ai_used=plan.source == "ai",
        x_ai_model=plan.ai_model,
    )
    yaml = _serialize_rules([rule])
    return [rule], yaml, level_res


def _pick_logsource(
    plan: DetectionPlan,
    telemetry: dict[str, Any] | None,
    family_signature: str | None = None,
    family: str | None = None,
) -> dict[str, str]:
    """Pick the best Sigma logsource for the plan.

    Falls back to first Step 4 sigma_logsource, then default process_creation/windows.
    ``family_signature`` / ``family`` thread through to ``map_all_intents`` so
    family-based intent resolution can match the KB.
    """
    DEFAULT = {"category": "process_creation", "product": "windows"}
    telemetry = telemetry or {}

    try:
        resolutions = map_all_intents(plan.detections, telemetry, family_signature, family)
        for res in resolutions:
            if getattr(res, "resolved", False) and getattr(res, "canonical_logsource", None):
                ls = dict(res.canonical_logsource)
                if ls.get("category"):
                    return ls
    except Exception as exc:
        logger.debug("_pick_logsource: intent_mapper failed: %s", exc)

    sigma_logsources = telemetry.get("sigma_logsources") or []
    if sigma_logsources:
        first = sigma_logsources[0] if isinstance(sigma_logsources[0], dict) else {}
        category = str(first.get("category", "")).strip()
        if category:
            return {
                "category": category,
                "product": str(first.get("product", "windows")),
                **({"service": str(first["service"])} if first.get("service") else {}),
            }

    logger.debug("_pick_logsource: using default %s", DEFAULT)
    return DEFAULT


def _serialize_rules(
    rules: list[SigmaRule],
    correlation_block: SigmaCorrelationBlock | None = None,
) -> str:
    """Serialize Sigma rules to YAML.

    For correlation sets: rebuild the parent's YAML from scratch to avoid
    regex-substituting the empty detection block.
    """
    if correlation_block is None or len(rules) < 2:
        return _join_yamls([r.to_yaml() for r in rules])

    yaml_texts: list[str] = [r.to_yaml() for r in rules[:-1]]
    parent = rules[-1]
    yaml_texts.append(_build_correlation_parent_yaml(parent, correlation_block))
    return _join_yamls(yaml_texts)


def _build_correlation_parent_yaml(
    rule: SigmaRule,
    correlation_block: SigmaCorrelationBlock,
) -> str:
    """Build YAML for a parent correlation rule.

    Metadata + `action: correlation` + `correlation:` block; no detection/logsource.
    """
    serializer = SigmaYamlSerializer()
    lines: list[str] = []

    meta = rule.metadata
    serializer._add_scalar(lines, "title", meta.title)
    serializer._add_scalar(lines, "id", meta.id)
    serializer._add_scalar(lines, "status", meta.status)
    serializer._add_folded(lines, "description", meta.description)
    serializer._add_list(lines, "references", meta.references)
    serializer._add_scalar(lines, "author", meta.author)
    serializer._add_scalar(lines, "date", meta.date)
    serializer._add_list(lines, "tags", meta.tags)
    serializer._add_list(lines, "falsepositives", meta.falsepositives)
    serializer._add_scalar(lines, "level", meta.level)
    serializer._add_related(lines, meta.related)

    # action: correlation + correlation block
    lines.append("action: correlation")
    lines.append("correlation:")
    try:
        dumped = correlation_block.model_dump(by_alias=True, exclude_none=True)
    except AttributeError:
        dumped = correlation_block.dict(by_alias=True, exclude_none=True)
    for k, v in dumped.items():
        if isinstance(v, list):
            lines.append(f"  {k}:")
            for item in v:
                lines.append(f"    - {item}")
        else:
            lines.append(f"  {k}: {v}")

    # x_* metadata fields (correlation-specific)
    serializer._add_scalar(lines, "x_family", rule.x_family)
    serializer._add_scalar(lines, "x_signature", rule.x_signature)
    serializer._add_number(lines, "x_detection_confidence", rule.x_detection_confidence)
    serializer._add_bool(lines, "x_correlation_required", rule.x_correlation_required)
    serializer._add_bool(lines, "x_correlation_logic", rule.x_correlation_logic)
    serializer._add_scalar(lines, "x_correlation_reasoning", rule.x_correlation_reasoning)
    serializer._add_bool(lines, "x_ai_used", rule.x_ai_used)
    serializer._add_scalar(lines, "x_ai_model", rule.x_ai_model)

    return "\n".join(lines).rstrip() + "\n"


def _join_yamls(texts: list[str]) -> str:
    if not texts:
        return ""
    return "\n---\n".join(texts)


__all__ = ["build_sigma_rule"]