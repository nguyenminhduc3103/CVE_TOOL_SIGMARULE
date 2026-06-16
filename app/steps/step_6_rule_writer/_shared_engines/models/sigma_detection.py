from __future__ import annotations

from pydantic import BaseModel, Field


class SigmaDetection(BaseModel):
    selections: dict[str, dict[str, list[str]]] = Field(default_factory=dict)
    condition: str = "1 of selection_*"