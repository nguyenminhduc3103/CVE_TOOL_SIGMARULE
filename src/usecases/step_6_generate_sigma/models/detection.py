# Detection-domain models for Step 6 (Pydantic invariants only).
# Architect v9: id is deterministic positional (rule_1, rule_2...); SelectedField.reason holds inline reasoning.
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

LevelLiteral = Literal["informational", "low", "medium", "high", "critical"]


class LogsourceRef(BaseModel):
    # Sigma logsource reference — matches Step 4 (category, product) tuple.
    category: str = Field(min_length=1)
    product: str | None = None


class SelectedField(BaseModel):
    # One field-with-matcher. value is AI semantic indicator (not validator-checked).
    # reason (optional) is inline reasoning AI emits directly in selection[].
    name: str = Field(min_length=1)
    modifier: str | None = None  # null = no modifier (chỉ valid nếu allowed_fields[field] = [] trong Step 4)
    value: str = Field(min_length=1)
    reason: str | None = None


class DetectionBody(BaseModel):
    # Sigma detection body (MVP: single selection block, condition=selection).
    selection: list[SelectedField] = Field(min_length=1)
    condition: str = "selection"


class DetectionRule(BaseModel):
    # One Sigma detection rule (one detection = one chosen logsource).
    description: str = Field(min_length=1)
    logsource: LogsourceRef
    detection: DetectionBody
    falsepositives: list[str] = Field(default_factory=list)
    level: LevelLiteral = "high"


class Detection(BaseModel):
    # One Sigma detection. id is deterministic positional (rule_1, rule_2...).
    id: str = Field(pattern=r"^rule_[0-9]+$")
    rule: DetectionRule


__all__ = [
    "LevelLiteral",
    "LogsourceRef",
    "SelectedField",
    "DetectionBody",
    "DetectionRule",
    "Detection",
]
