from __future__ import annotations

from pydantic import BaseModel, Field


class SigmaCorrelationBlock(BaseModel):
    # SigmaHQ correlation block: type/rules/timespan/group-by/condition.
    type: str
    rules: list[str] = Field(default_factory=list)
    timespan: str | None = None
    group_by: list[str] | None = Field(alias="group-by", default=None)
    condition: dict[str, int] | None = None


class CorrelationCondition(BaseModel):
    # Single-event: expression string. Cross-event: SigmaCorrelationBlock.
    expression: str | None = None
    is_cross_event: bool = False
    correlation_block: SigmaCorrelationBlock | None = None

    confidence: float
    reasoning: str
    required_selections: list[str] = Field(default_factory=list)