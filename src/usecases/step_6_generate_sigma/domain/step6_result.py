"""Step6Result domain model — typed result of Step 6 (Planner + Builder only)."""
from __future__ import annotations

from pydantic import BaseModel, Field

from src.usecases.step_6_generate_sigma._shared_engines.models.sigma_rule import SigmaRule
from src.usecases.step_6_generate_sigma.domain.detection_plan import DetectionPlan


class Step6Result(BaseModel):
    detection_plan: DetectionPlan
    rules: list[SigmaRule] = Field(default_factory=list)
    yaml_output: str = ""


__all__ = ["Step6Result"]
