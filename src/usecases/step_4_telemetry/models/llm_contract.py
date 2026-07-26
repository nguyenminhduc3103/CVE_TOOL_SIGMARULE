"""LLM contract — Step 4 Telemetry Selector.

AI chỉ emit ABSTRACT/SEMANTIC terms. Schema-enforced fields
(sigma_logsources, required_fields, telemetry_feasibility_score) được code
layer (mapper + validator + feasibility_engine) sinh downstream.

Contract này KHÔNG chứa:
  - sigma_logsources              (→ logsource_mapper)
  - required_fields               (→ taxonomy_validator)
  - validated_fields / invalid_fields / taxonomy_warnings (→ taxonomy_validator)
  - telemetry_feasibility_score / breakdown (→ telemetry_feasibility)
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from src.domain.models.telemetry import DetectionFeatures


GAP_SEVERITY_VALUES = ("low", "medium", "high")
DETECTION_AXIS_VALUES = ("pre-exploit", "post-exploit", "impact")


class TelemetryLLMResponse(BaseModel):
    """Contract cho raw LLM output (Step 4 Telemetry Selector).

    Field names MUST match system prompt schema verbatim. AI emit JSON object
    với đúng các key này.
    """

    # ----- AI emit (LOOSE) -----
    candidate_logsources: list[str] = Field(
        default_factory=list,
        description="Free-form terms (vd ['process_creation', 'apache', 'ldap']). Code resolves to SigmaLogsource.",
    )
    candidate_fields: list[str] = Field(
        default_factory=list,
        description="Field names (có thể ngoài taxonomy). Validator filters against LOGSOURCE_FIELDS.",
    )
    detection_axis: list[Literal["pre-exploit", "post-exploit", "impact"]] = Field(
        default_factory=list,
        description="Các trục phát hiện mà rule có thể cover.",
    )
    primary_axis: Literal["pre-exploit", "post-exploit", "impact"] | None = Field(
        default=None,
        description="Trục ưu tiên nhất (rule đầu tiên Step 6 viết).",
    )
    required_events: list[str] = Field(
        default_factory=list,
        description="Sysmon EID cần bật (vd ['1', '3']).",
    )
    telemetry_requirements: str = Field(
        default="",
        description="Mô tả text yêu cầu telemetry.",
    )
    telemetry_gaps: list[str] = Field(
        default_factory=list,
        description="Rủi ro / thiếu telemetry (vd 'image_load cần EID 7 — thường tắt').",
    )
    gap_severity: Literal["low", "medium", "high"] | None = Field(
        default=None,
        description="Mức độ nghiêm trọng của gaps.",
    )
    rule_strategy: list[str] = Field(
        default_factory=list,
        description="Gợi ý cách Step 6 viết rule.",
    )
    correlation_required: bool = Field(
        default=False,
        description="True nếu cần Sigma Correlation rule (multi-axis).",
    )
    field_taxonomy_notes: list[str] = Field(
        default_factory=list,
        description="Giải thích field selections (vd 'webserver dùng cs-* không phải Image').",
    )
    telemetry_confidence: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="AI self-assessment. Khác telemetry_feasibility_score (rule-based downstream).",
    )
    observable_detection_features: DetectionFeatures = Field(
        default_factory=DetectionFeatures,
        description="3-tier detection features — bridge sang Step 6.",
    )
