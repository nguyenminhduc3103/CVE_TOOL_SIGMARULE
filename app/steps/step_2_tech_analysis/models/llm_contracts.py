from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class Phase1AttackFlow(BaseModel):
    entry_vector: str = Field(min_length=1)
    execution_mechanism: str = Field(min_length=1)
    observable_side_effects: list[str] = Field(min_length=1)

    @field_validator("entry_vector", "execution_mechanism")
    @classmethod
    def _strip_non_empty(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must be non-empty")
        return text

    @field_validator("observable_side_effects")
    @classmethod
    def _normalize_effects(cls, value: list[str]) -> list[str]:
        items = [str(item).strip() for item in value if str(item).strip()]
        if not items:
            raise ValueError("must contain at least one non-empty item")
        return items


class Phase1LLMResponse(BaseModel):
    family: str | None
    signature: str | None
    extracted_keywords: list[str] = Field(default_factory=list)
    vulnerability_type: str | None
    vulnerability_class: str | None
    exploit_vector: Literal["remote", "local", "unknown"] | None
    pre_auth: bool | None
    remote_exploitable: bool | None
    exploit_complexity: Literal["low", "medium", "high"] | None
    confidence: float = Field(ge=0.0, le=1.0)
    execution_surface: Literal["client_side", "server_side", "local", "multi_hop", "unknown"] | None
    delivery_vector: Literal[
        "email_attachment",
        "email_link",
        "web_download",
        "network_protocol",
        "physical",
        "local_execution",
        "unknown",
    ] | None
    user_interaction_required: bool | None
    attack_flow: Phase1AttackFlow
    mandatory_behaviors: list[str] = Field(default_factory=list)
    evasive_indicators: list[str] = Field(default_factory=list)
    exploit_requirements: list[str] = Field(default_factory=list)
    cwe_metadata: dict | None = None
    likely_outcome: str | None = None
    analysis_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    classification_reason: list[str] = Field(default_factory=list)
    behavior_reason: list[str] = Field(default_factory=list)
    reasoning: list[str] = Field(default_factory=list)


class Phase2LLMResponse(BaseModel):
    tactics: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    subtechniques: list[str] = Field(default_factory=list)
    attack_confidence: float = Field(ge=0.0, le=1.0)
    mapping_reasons: list[str] = Field(default_factory=list)
