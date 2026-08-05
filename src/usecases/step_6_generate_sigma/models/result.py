# Step 6 result models. SigmaRuleLLMResponse = AI wire; Step6Result = public output.
# Architect v9: Pydantic invariants only — business validation lives in validators/.
from __future__ import annotations

from pydantic import BaseModel, Field

from src.usecases.step_6_generate_sigma.models.correlation import Correlation
from src.usecases.step_6_generate_sigma.models.detection import Detection


class SigmaRuleLLMResponse(BaseModel):
    # AI wire format — exact shape the LLM emits. Structural validity only.
    detections: list[Detection] = Field(default_factory=list)
    correlations: list[Correlation] = Field(default_factory=list)
    reasoning: str = Field(min_length=1)


class Step6Result(BaseModel):
    # Final public output (CLI / integration / future renderer). cve_id + ai_model injected by orchestrator.
    cve_id: str = Field(min_length=1)
    ai_model: str | None = None
    detections: list[Detection] = Field(default_factory=list)
    correlations: list[Correlation] = Field(default_factory=list)
    reasoning: str = Field(min_length=1)


__all__ = ["SigmaRuleLLMResponse", "Step6Result"]
