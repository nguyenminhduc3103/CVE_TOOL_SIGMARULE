from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


# Phase 1 LLM response chỉ còn 7 fields:
#   - execution_surface, delivery_vector (AI reason trên facts canonical)
#   - mandatory_behaviors, evasive_indicators, exploit_requirements, reasoning (behavior vocab)
#   - confidence (AI tự chấm cho các fact AI suy luận)
#
# 5 field CVSS-deterministic (exploit_vector, pre_auth, remote_exploitable,
# exploit_complexity, user_interaction_required) được fill bằng CVSS parser
# TRƯỚC khi pass to AI — AI không reason, không trả về các field này.
class Phase1LLMResponse(BaseModel):
    execution_surface: Literal[
        "client_side", "server_side", "local", "multi_hop", "firmware", "unknown"
    ] | None
    delivery_vector: Literal[
        "email_attachment",
        "email_link",
        "web_download",
        "file_open",
        "network_protocol",
        "physical",
        "local_execution",
        "unknown",
    ] | None
    mandatory_behaviors: list[str] = Field(default_factory=list)
    evasive_indicators: list[str] = Field(default_factory=list)
    exploit_requirements: list[str] = Field(default_factory=list)
    reasoning: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


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
