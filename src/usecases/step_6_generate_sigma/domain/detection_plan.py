"""DetectionPlan domain model — semantic output from the AI Detection Logic Planner.

AI emits ONLY:
    detections: list of {intent, priority, rationale, optional selection_hint}
    logic: {operator, operands, threshold?}
    falsepositives: list of strings
    risk_bias: conservative | neutral | aggressive
    rationale: string
    planner_confidence: 0.0-1.0

AI must NOT emit:
    - domain (Step 4 already chose the telemetry domain)
    - logsource (Step 4 sigma_logsources is canonical)
    - Sigma field names / modifiers
    - condition literal string (Builder renders from DetectionLogic)
    - level (Builder computes from severity + correlation + risk_bias + feasibility)
    - title / id / status / author / date / tags / references
    - UUID, YAML

This module is the AI contract surface. Validation must reject any field outside
this shape via Step6LLMResponse (models/llm_contract.py).
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator


Priority = Literal["critical", "high", "medium", "low"]
Operator = Literal["all", "any", "at_least"]
RiskBias = Literal["conservative", "neutral", "aggressive"]
PlanSource = Literal["ai", "rule_based"]


class DetectionIntent(BaseModel):
    """One semantic detection intent. Free-text; resolved by Intent Mapper."""

    intent: str = Field(min_length=1)
    priority: Priority = "medium"
    rationale: str = ""
    selection_hint: dict[str, list[str]] | None = None


class DetectionLogic(BaseModel):
    """How to combine intents. Builder renders the Sigma condition string."""

    operator: Operator
    operands: list[int] = Field(min_length=1)
    threshold: int | None = None

    @model_validator(mode="after")
    def _validate_operands(self) -> "DetectionLogic":
        if self.operator == "at_least":
            if self.threshold is None or self.threshold < 1:
                raise ValueError("operator=at_least requires threshold >= 1")
            if self.threshold > len(self.operands):
                raise ValueError("threshold cannot exceed number of operands")
        for idx in self.operands:
            if idx < 0:
                raise ValueError("operands must be non-negative detection-plan indexes")
        return self


class DetectionPlan(BaseModel):
    """Final AI emit shape. Source differentiates AI from rule-based fallback."""

    detections: list[DetectionIntent]
    logic: DetectionLogic
    falsepositives: list[str] = Field(default_factory=list)
    risk_bias: RiskBias = "neutral"
    rationale: str = ""
    planner_confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    source: PlanSource = "ai"
    ai_model: str | None = None
    ai_retry_count: int = 0

    @model_validator(mode="after")
    def _validate_plan(self) -> "DetectionPlan":
        if not self.detections:
            raise ValueError("DetectionPlan must contain at least one DetectionIntent")
        max_idx = len(self.detections) - 1
        for idx in self.logic.operands:
            if idx > max_idx:
                raise ValueError(
                    f"logic operand {idx} out of range (plan has {len(self.detections)} intents)"
                )
        return self


__all__ = [
    "DetectionIntent",
    "DetectionLogic",
    "DetectionPlan",
    "Priority",
    "Operator",
    "RiskBias",
    "PlanSource",
]