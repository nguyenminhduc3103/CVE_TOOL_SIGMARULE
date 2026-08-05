# Correlation-domain models for Step 6 (Pydantic invariants only).
# Schema: CorrelationBody.rules refs Detection.id; Correlation.reasoning is a CorrelationReasoning struct.
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from src.usecases.step_6_generate_sigma.models.detection import LevelLiteral

CorrelationTypeLiteral = Literal["temporal", "frequency", "order"]


class ParameterReasoning(BaseModel):
    # Reasoning for ONE correlation parameter (type, window, group-by, ...).
    parameter: str = Field(min_length=1)
    value: str = Field(min_length=1)
    reason: str = Field(min_length=1)


class CorrelationReasoning(BaseModel):
    # Structured reasoning: correlation_strategy (WHY) + parameter_reasoning (per-parameter).
    correlation_strategy: str = Field(min_length=1)
    parameter_reasoning: list[ParameterReasoning] = Field(default_factory=list)


class CorrelationBody(BaseModel):
    # Correlation spec — references Detection.id strings (>= 2).
    rules: list[str] = Field(min_length=2)
    type: CorrelationTypeLiteral = "temporal"
    window: str | None = None  # optional, vd "5m", "1h"


class CorrelationRule(BaseModel):
    # Sigma correlation rule shape.
    description: str = Field(min_length=1)
    correlation: CorrelationBody
    level: LevelLiteral = "high"


class Correlation(BaseModel):
    # One Sigma correlation.
    rule: CorrelationRule
    reasoning: CorrelationReasoning


__all__ = [
    "CorrelationTypeLiteral",
    "ParameterReasoning",
    "CorrelationReasoning",
    "CorrelationBody",
    "CorrelationRule",
    "Correlation",
]
