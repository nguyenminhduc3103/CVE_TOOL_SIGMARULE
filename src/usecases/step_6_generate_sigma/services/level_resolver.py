"""Deterministic Level Resolver — computes Sigma rule level from
severity + correlation + risk_bias + feasibility + completeness.

AI NEVER emits level. AI emits `risk_bias` ∈ {conservative, neutral, aggressive}.
Builder then translates:
    base_level = severity_from_vulnerability_type(role)
    + correlation_bump if correlation_required
    + risk_bias_offset
    CAP by feasibility
    CAP by completeness (Phase C)
    clamp to [0..4]
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from src.usecases.step_6_generate_sigma._knowledge import loader
from src.usecases.step_6_generate_sigma.domain.detection_plan import RiskBias


# Order: informational=0, low=1, medium=2, high=3, critical=4
LEVEL_ORDER = ["informational", "low", "medium", "high", "critical"]


class LevelResolution(BaseModel):
    level: str = "medium"
    level_index: int = 2
    base_level: str = "medium"
    base_index: int = 2
    correlation_bump: int = 0
    risk_bias_offset: int = 0
    feasibility_cap: str | None = None
    feasibility_cap_index: int | None = None
    completeness_cap: str | None = None
    completeness_cap_index: int | None = None
    final_index: int = 2
    reasoning: list[str] = Field(default_factory=list)


def _normalize_vuln_type(value: object | None) -> str:
    if value is None:
        return ""
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")


def _resolve_base_level(
    vulnerability_type: str | None,
    cvss_score: float | None,
    severity: str | None,
    table: dict[str, Any],
) -> tuple[str, int]:
    """Lookup base level from `level_translation.base_by_vuln_type` table."""
    base_by_vuln = table.get("base_by_vuln_type", {}) or {}
    vt = _normalize_vuln_type(vulnerability_type)
    if vt and vt in base_by_vuln:
        idx = int(base_by_vuln[vt])
        return LEVEL_ORDER[idx], idx

    # CVSS fallback
    if cvss_score is not None:
        if cvss_score >= 9.0:
            return "critical", 4
        if cvss_score >= 7.0:
            return "high", 3
        if cvss_score >= 4.0:
            return "medium", 2
        return "low", 1

    # Severity fallback
    severity_map = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "moderate": 2,
        "low": 1,
    }
    if severity and severity.lower() in severity_map:
        idx = severity_map[severity.lower()]
        return LEVEL_ORDER[idx], idx

    idx = int(base_by_vuln.get("default", 3))
    return LEVEL_ORDER[idx], idx


def _resolve_feasibility_cap(feasibility: float | None, table: dict[str, Any]) -> tuple[str | None, int | None]:
    """If feasibility is low, cap the level."""
    if feasibility is None:
        return None, None
    caps = table.get("feasibility_caps", {}) or {}
    if feasibility < 0.4:
        idx = int(caps.get("lt_0_4", caps.get("lt_0.4", 0)))
    elif feasibility < 0.7:
        idx = int(caps.get("between_0_4_and_0_7", caps.get("between_0.4_and_0.7", 2)))
    else:
        idx = int(caps.get("gt_0_7", caps.get("gt_0.7", 4)))
    return LEVEL_ORDER[idx], idx


def _resolve_completeness_cap(
    completeness_level: str | None,
    table: dict[str, Any],
) -> tuple[str | None, int | None]:
    if not completeness_level:
        return None, None
    caps = table.get("completeness_caps", {}) or {}
    if completeness_level not in caps:
        return None, None
    idx = int(caps[completeness_level])
    return LEVEL_ORDER[idx], idx


def resolve_level(
    vulnerability_type: str | None,
    cvss_score: float | None,
    severity: str | None,
    correlation_required: bool,
    risk_bias: RiskBias | str,
    pipeline_feasibility: float | None,
    completeness_level: str | None = None,
) -> LevelResolution:
    """Compute final Sigma rule level deterministically.

    Args:
        vulnerability_type: From Step 2 TechnicalAnalysis (e.g. "rce", "sqli").
        cvss_score: From CoreCVEData.
        severity: From CoreCVEData (CVSS severity string).
        correlation_required: From Step 4 TelemetryAssessment.
        risk_bias: From AI DetectionPlan {conservative, neutral, aggressive}.
        pipeline_feasibility: From Step 4 (0.0-1.0). Caps level if low.
        completeness_level: From Phase C Detection Completeness Validator
            {incomplete, minimal, full}.
    """
    table = loader.get_level_translation() or {}

    base_level, base_idx = _resolve_base_level(vulnerability_type, cvss_score, severity, table)
    reasoning: list[str] = [
        f"base={base_level} (from vulnerability_type={vulnerability_type!r}, "
        f"cvss={cvss_score}, severity={severity!r})"
    ]

    # Apply correlation_bump
    bump = int(table.get("correlation_bump", 0)) if correlation_required else 0
    after_bump_idx = min(4, base_idx + bump)
    reasoning.append(f"correlation_bump=+{bump} → {LEVEL_ORDER[after_bump_idx]}")

    # Apply risk_bias offset
    bias_map = table.get("risk_bias_offset", {}) or {}
    bias_offset = int(bias_map.get(risk_bias, 0))
    after_bias_idx = max(0, min(4, after_bump_idx + bias_offset))
    reasoning.append(f"risk_bias={risk_bias} ({bias_offset:+d}) → {LEVEL_ORDER[after_bias_idx]}")

    # Apply feasibility cap
    feas_cap_level, feas_cap_idx = _resolve_feasibility_cap(pipeline_feasibility, table)
    if feas_cap_idx is not None:
        reasoning.append(
            f"feasibility_cap={feas_cap_level} (pipeline_feasibility={pipeline_feasibility})"
        )
        after_bias_idx = min(after_bias_idx, feas_cap_idx)

    # Apply completeness cap
    comp_cap_level, comp_cap_idx = _resolve_completeness_cap(completeness_level, table)
    if comp_cap_idx is not None:
        reasoning.append(f"completeness_cap={comp_cap_level} (completeness={completeness_level})")
        after_bias_idx = min(after_bias_idx, comp_cap_idx)

    final_idx = max(0, min(4, after_bias_idx))
    final_level = LEVEL_ORDER[final_idx]

    return LevelResolution(
        level=final_level,
        level_index=final_idx,
        base_level=base_level,
        base_index=base_idx,
        correlation_bump=bump,
        risk_bias_offset=bias_offset,
        feasibility_cap=feas_cap_level,
        feasibility_cap_index=feas_cap_idx,
        completeness_cap=comp_cap_level,
        completeness_cap_index=comp_cap_idx,
        final_index=final_idx,
        reasoning=reasoning,
    )


__all__ = ["LevelResolution", "LEVEL_ORDER", "resolve_level"]