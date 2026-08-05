"""Sigma YAML Builder — Step 6 semantic plan -> multi-doc Sigma YAML string.

Produces well-formed Sigma rules per the Meta Rule Spec v2.1.0:
  - Detection rule:  title, id, status, description, logsource, detection, falsepositives, level, tags, date
  - Correlation rule: title, id, status, description, correlation, level, tags, date
UUID v5 is deterministic from (cve_id, rule.id) / (cve_id, correlation_index) only.
"""
from __future__ import annotations

from datetime import date
from typing import Any

import yaml

from src.usecases.step_6_generate_sigma.builder.attack_tag_map import build_attack_tags
from src.usecases.step_6_generate_sigma.builder.sigma_id import correlation_uuid, rule_uuid
from src.usecases.step_6_generate_sigma.models.correlation import Correlation, CorrelationBody
from src.usecases.step_6_generate_sigma.models.detection import Detection, DetectionRule, SelectedField
from src.usecases.step_6_generate_sigma.models.result import Step6Result

# Default rule status — single edit point.
DEFAULT_STATUS = "experimental"
# Fallback timespan when CorrelationBody.window is None (matches common default).
DEFAULT_TIMESPAN = "5m"


# Sigma modifier keyword map (Step 6 modifier -> Sigma modifier suffix).
_MODIFIER_KEYWORDS = frozenset({
    "contains", "equals", "startswith", "endswith",
    "all", "re", "cidr", "fieldref", "windash",
})


def _today_iso() -> str:
    return date.today().isoformat()


def _humanize_rule_id(rule_id: str) -> str:
    """rule_1 -> Rule 1."""
    parts = rule_id.split("_", 1)
    if len(parts) == 2 and parts[0] == "rule":
        return f"Rule {parts[1]}"
    return rule_id.replace("_", " ").title()


def _render_logsource(detection_rule: DetectionRule) -> dict[str, Any]:
    """Render Sigma logsource block; product omitted if None (per doc style)."""
    ls = detection_rule.logsource
    out: dict[str, Any] = {"category": ls.category}
    if ls.product is not None:
        out["product"] = ls.product
    return out


def _render_selection_block(sel: SelectedField) -> tuple[str, str]:
    """Return (field_name_with_modifier, value) — modifier appended as |suffix per Sigma."""
    name = sel.name
    if sel.modifier and sel.modifier in _MODIFIER_KEYWORDS:
        return f"{name}|{sel.modifier}", sel.value
    return name, sel.value


def _render_detection(cve_id: str, det: Detection, attack_tags: list[str]) -> dict[str, Any]:
    rule = det.rule
    selection_pairs = [_render_selection_block(sel) for sel in rule.detection.selection]
    detection_block: dict[str, Any] = {
        "selection": _selection_to_yaml(selection_pairs),
        "condition": rule.detection.condition or "selection",
    }
    doc: dict[str, Any] = {
        "title": f"Sigma Rule for {cve_id} {_humanize_rule_id(det.id)}",
        "id": rule_uuid(cve_id, det.id),
        "status": DEFAULT_STATUS,
        "description": rule.description,
        "logsource": _render_logsource(rule),
        "detection": detection_block,
        "level": rule.level,
        "tags": list(attack_tags),
        "date": _today_iso(),
    }
    if rule.falsepositives:
        doc["falsepositives"] = list(rule.falsepositives)
    return doc


def _selection_to_yaml(pairs: list[tuple[str, str]]) -> list[dict[str, str]]:
    """Render a list of (field, value) pairs as a Sigma selection list."""
    return [{field: value} for field, value in pairs]


def _render_correlation_body(body: CorrelationBody) -> dict[str, Any]:
    """Map Step 6 CorrelationBody -> Sigma correlation block.

    Required fields (per Meta Rule Spec): type, rules, timespan, group-by.
    Conditional: condition (required for event_count and value_*).
    """
    out: dict[str, Any] = {
        "type": body.type,
        "rules": list(body.rules),
        "group-by": [],
        "timespan": body.window or DEFAULT_TIMESPAN,
    }
    if body.type not in ("temporal", "temporal_ordered"):
        out["condition"] = {"gte": 1}
    return out


def _render_correlation(cve_id: str, corr: Correlation, index: int, attack_tags: list[str]) -> dict[str, Any]:
    rule = corr.rule
    return {
        "title": f"Sigma Correlation for {cve_id}",
        "id": correlation_uuid(cve_id, index),
        "status": DEFAULT_STATUS,
        "description": rule.description,
        "correlation": _render_correlation_body(rule.correlation),
        "level": rule.level,
        "tags": list(attack_tags),
        "date": _today_iso(),
    }


class SigmaBuilder:
    """Convert Step6Result into a multi-doc Sigma YAML string."""

    def build_yaml(
        self,
        *,
        cve_id: str,
        result: Step6Result,
        tactics: list[str],
        techniques: list[str],
    ) -> str:
        """Render detection + correlation documents joined by --- separators."""
        # Derive tactic IDs from techniques via MitreAttackWhitelist (when whitelist is loaded).
        derived_tactics = list(tactics)
        if not derived_tactics and techniques:
            try:
                from src.shared.mitre.loader import MitreAttackWhitelist
                for tech in techniques:
                    for tac in MitreAttackWhitelist.get().technique_to_tactics(tech):
                        if tac not in derived_tactics:
                            derived_tactics.append(tac)
            except Exception:
                pass
        attack_tags = build_attack_tags(derived_tactics, techniques)
        documents: list[dict[str, Any]] = []
        for det in result.detections:
            documents.append(_render_detection(cve_id, det, attack_tags))
        for idx, corr in enumerate(result.correlations, start=1):
            documents.append(_render_correlation(cve_id, corr, idx, attack_tags))
        if not documents:
            documents.append({
                "title": f"Sigma Rule for {cve_id}",
                "status": DEFAULT_STATUS,
                "tags": attack_tags,
                "date": _today_iso(),
            })
        return yaml.safe_dump_all(
            documents,
            explicit_start=True,
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
        )


__all__ = ["SigmaBuilder", "DEFAULT_STATUS", "DEFAULT_TIMESPAN"]
