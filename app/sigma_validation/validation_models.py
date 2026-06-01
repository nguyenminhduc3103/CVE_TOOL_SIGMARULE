from __future__ import annotations

from pydantic import BaseModel, Field


class ValidationResult(BaseModel):
    valid: bool = False
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    score: int = 0
    grade: str = "F"