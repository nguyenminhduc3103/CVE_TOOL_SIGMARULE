# Telemetry Plan — new Step 4 output shape. Hard-constrained ontology.
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator

# Lazy KB import: avoids circular import via enriched.py / step_4 __init__.
def _kb() -> dict[str, str]:
    from src.usecases.step_4_telemetry._knowledge.loader import load_concept_to_group
    return load_concept_to_group()


# Hard-constrained enums (Literal for Pydantic + JSON Schema compliance).
DetectionAxisLiteral = Literal["initial_access", "post_exploitation", "impact"]
GapSeverityLiteral = Literal["low", "medium", "high"]


class DetectionAxis(BaseModel):
    """Hard-constrained detection axis. Primary ∈ {3 values}; secondary excludes primary."""

    primary: DetectionAxisLiteral
    secondary: list[DetectionAxisLiteral] = Field(default_factory=list)

    @model_validator(mode="after")
    def _primary_not_in_secondary(self):
        if self.primary in self.secondary:
            raise ValueError(
                f"detection_axis.primary '{self.primary}' must NOT appear in secondary"
            )
        # Deduplicate secondary while preserving order.
        seen: set[str] = set()
        deduped: list[str] = []
        for axis in self.secondary:
            if axis not in seen:
                seen.add(axis)
                deduped.append(axis)
        object.__setattr__(self, "secondary", deduped)
        return self


class TargetEnvironment(BaseModel):
    """Target environment classification — list[str] fields, free text but bounded."""

    platforms: list[str] = Field(default_factory=list)
    deployment: list[str] = Field(default_factory=list)
    application_types: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    special_environments: list[str] = Field(default_factory=list)


class CandidateFeature(BaseModel):
    """Single detection feature. `telemetry_concept` validated against KB whitelist."""

    semantic: str = Field(min_length=1, description="Free-text human description.")
    telemetry_concept: str = Field(
        min_length=1,
        description="Must be exactly one of the KB whitelist concepts (see telemetry_concepts.yaml).",
    )
    evidence: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _concept_must_be_in_kb(self):
        allowed = _kb()
        if self.telemetry_concept not in allowed:
            raise ValueError(
                f"telemetry_concept '{self.telemetry_concept}' is not in the KB whitelist. "
                f"Allowed concepts belong to groups: {sorted(set(allowed.values()))}."
            )
        return self


class CandidateFeatures(BaseModel):
    """Three-tier feature classification. Each feature carries telemetry_concept + evidence."""

    stable: list[CandidateFeature] = Field(default_factory=list)
    conditional: list[CandidateFeature] = Field(default_factory=list)
    optional: list[CandidateFeature] = Field(default_factory=list)


class TelemetryPlan(BaseModel):
    """Final Step 4 output — canonical shape consumed by downstream rule builders."""

    cve_id: str = Field(min_length=1)
    target_environment: TargetEnvironment
    detection_axis: DetectionAxis
    detection_strategy: str = Field(
        min_length=1,
        description="One-sentence summary of the recommended detection strategy.",
    )
    correlation_required: bool
    candidate_features: CandidateFeatures
    telemetry_gaps: list[str] = Field(default_factory=list)
    gap_severity: GapSeverityLiteral = "medium"
    telemetry_confidence: float = Field(ge=0.0, le=1.0)
    ai_model: str | None = Field(
        default=None,
        description="AI model used to produce this plan (audit / debugging).",
    )

    @model_validator(mode="after")
    def _correlation_required_sanity(self):
        # Placeholder for future enrichment — currently no-op (data may be sparse).
        return self