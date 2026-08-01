from __future__ import annotations

from pydantic import BaseModel, Field


# Phase 1 LLM response
class Phase1LLMResponse(BaseModel):
    execution_surface: str | None = None
    delivery_vector: str | None = None
    mandatory_behaviors: list[str] = Field(default_factory=list)
    evasive_indicators: list[str] = Field(default_factory=list)
    exploit_requirements: list[str] = Field(default_factory=list)
    reasoning: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


# Phase 2A - Extract TTPs
class Phase2LLMResponse(BaseModel):
    tactics: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    subtechniques: list[str] = Field(default_factory=list)
