# Strict LLM contract for new Step 4 — validates raw LLM response before building TelemetryPlan.
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator

from src.usecases.step_4_telemetry._knowledge.loader import load_concept_to_group
from src.usecases.step_4_telemetry.models.telemetry_plan import (
    CandidateFeatures,
    DetectionAxis,
    GapSeverityLiteral,
    TargetEnvironment,
)


class TelemetryLLMResponse(BaseModel):
    """Strict contract for raw LLM output. Validate before building TelemetryPlan."""

    target_environment: TargetEnvironment
    detection_axis: DetectionAxis
    detection_strategy: str = Field(min_length=1)
    correlation_required: bool
    candidate_features: CandidateFeatures
    telemetry_gaps: list[str] = Field(default_factory=list)
    gap_severity: GapSeverityLiteral = "medium"
    telemetry_confidence: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _check_telemetry_concepts(self):
        # Reject any LLM output whose telemetry_concept is not in the KB whitelist.
        allowed = load_concept_to_group()
        offender: list[str] = []
        for tier in ("stable", "conditional", "optional"):
            tier_features = getattr(self.candidate_features, tier)
            for f in tier_features:
                if f.telemetry_concept not in allowed:
                    offender.append(f"{tier}={f.telemetry_concept}")
        if offender:
            raise ValueError(
                f"telemetry_concept not in KB whitelist: {', '.join(offender)}"
            )
        return self