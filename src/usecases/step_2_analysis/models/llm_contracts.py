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


class Phase2TechniqueEntry(BaseModel):
    """One entry in the Evidence-to-TTP Matrix. Each technique must cite a behavior anchor from Phase 1's mandatory_behaviors."""
    technique_id: str = Field(min_length=1)
    exact_behavior_anchor: str = Field(min_length=1, description="MUST match a Phase 1 mandatory_behaviors entry")
    textual_evidence: str = Field(default="", description="Quote from CVE description supporting this mapping")


class Phase2PrimaryTechniques(BaseModel):
    """Primary techniques - direct exploitation technique."""
    techniques: list[str] = Field(default_factory=list)
    subtechniques: list[str] = Field(default_factory=list)
    rationale: str = Field(default="")
    # Evidence-to-TTP Matrix - required for each technique
    behavior_anchors: list[Phase2TechniqueEntry] = Field(default_factory=list)


class Phase2SecondaryTechniques(BaseModel):
    """Secondary techniques - post-exploit behaviors."""
    execution: list[str] = Field(default_factory=list)
    c2: list[str] = Field(default_factory=list)
    impact: list[str] = Field(default_factory=list)
    rationale: str = Field(default="")
    # Evidence-to-TTP Matrix - required for each technique
    behavior_anchors: list[Phase2TechniqueEntry] = Field(default_factory=list)


class Phase2LLMResponse(BaseModel):
    """Phase 2 ATT&CK mapping response. Supports Evidence-to-TTP Matrix, Two-Tier, và Legacy flat format."""
    # Format 1: Evidence-to-TTP Matrix (NEW - Preferred)
    mitre_attack_chain: list[Phase2TechniqueEntry] = Field(default_factory=list)

    # Format 2: Two-Tier format (existing)
    primary_techniques: Phase2PrimaryTechniques = Field(default_factory=Phase2PrimaryTechniques)
    secondary_techniques: Phase2SecondaryTechniques = Field(default_factory=Phase2SecondaryTechniques)

    # Common fields
    attack_confidence: float = Field(ge=0.0, le=1.0)
    mapping_reasons: list[str] = Field(default_factory=list)

    # Legacy fields for backward compatibility during transition
    tactics: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    subtechniques: list[str] = Field(default_factory=list)
