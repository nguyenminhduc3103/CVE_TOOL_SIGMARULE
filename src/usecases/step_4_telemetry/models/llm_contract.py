# Pydantic contract for Step 4 LLM output (semantic emitter schema). Code-layer fields come from resolver + engines.
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from src.domain.models.telemetry import DetectionFeature


GAP_SEVERITY_VALUES = ("low", "medium", "high")
DETECTION_AXIS_VALUES = ("pre-exploit", "post-exploit", "impact")


class TelemetryLLMResponse(BaseModel):
    """Contract cho raw LLM output (Step 4 Telemetry Selector) — semantic emitter.

    Field names MUST match `select_telemetry.system.txt` schema verbatim.
    """

    # ----- Semantic emitter (NEW) -----
    candidate_telemetry_domains: list[str] = Field(
        default_factory=list,
        description="2-5 canonical semantic domains (identity, process, network, "
                    "registry, filesystem, dns, ldap, http, cloud, container, "
                    "kubernetes, email, office, memory, module, persistence, "
                    "credential, authorization).",
    )
    candidate_semantic_tags: list[str] = Field(
        default_factory=list,
        description="Free-form tags cho CVE context (vd ['Netlogon', 'MachineAccount', "
                    "'DomainController'] cho Zerologon).",
    )
    candidate_canonical_fields: list[str] = Field(
        default_factory=list,
        description="Field names AI muốn detect on. Use canonical names (EventID, "
                    "TargetAccount, CommandLine, Image, ParentImage, DestinationIp, "
                    "DestinationPort, SourceIp, ...). Resolver validates.",
    )

    # ----- Detection axes (kept) -----
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
        description="Event IDs/names (vd ['4742', '4624'] cho Windows Security, ['1'] cho Sysmon).",
    )

    # ----- Structured requirements (NEW shape) -----
    telemetry_requirements: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Structured dict by source — Step 6 reads directly. "
                    "vd {'windows_security': ['4742', '4624'], 'sysmon': ['1', '3']}",
    )
    telemetry_gaps: list[str] = Field(
        default_factory=list,
        description="Rủi ro / thiếu telemetry (vd 'image_load cần EID 7 — thường tắt').",
    )
    gap_severity: Literal["low", "medium", "high"] | None = Field(
        default=None,
        description="Mức độ nghiêm trọng của gaps.",
    )

    # ----- Rename: rule_strategy → recommended_rule_strategy -----
    recommended_rule_strategy: list[str] = Field(
        default_factory=list,
        description="Gợi ý cách Step 6 viết rule (vd 'prioritize post-exploit').",
    )

    # ----- Flattened 3-tier (NEW shape) -----
    stable_features: list[DetectionFeature] = Field(
        default_factory=list,
        description="Detection features KHÔNG THỂ bypass (vd EventID=4742, TargetAccount=DC$).",
    )
    conditional_features: list[DetectionFeature] = Field(
        default_factory=list,
        description="Detection features CONTEXT-DEPENDENT (vd Image=cmd.exe, CommandLine, "
                    "ParentImage). KHÔNG classify cmd.exe/powershell.exe ở stable.",
    )
    optional_features: list[DetectionFeature] = Field(
        default_factory=list,
        description="Detection features dễ spoof (vd UserAgent, SourceIp).",
    )

    # ----- NEW: Why this telemetry? -----
    telemetry_selection_rationale: list[str] = Field(
        default_factory=list,
        description="2-4 bullets giải thích vì sao chọn mỗi domain. "
                    "vd 'Identity: survives exploit variations, observable on default "
                    "Windows logging, low FP'.",
    )

    # ----- Correlation + taxonomy notes (kept) -----
    correlation_required: bool = Field(
        default=False,
        description="True nếu cần Sigma Correlation rule (multi-axis).",
    )
    field_taxonomy_notes: list[str] = Field(
        default_factory=list,
        description="Giải thích field selections.",
    )
    telemetry_confidence: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="AI self-assessment về khả năng detect CVE này với telemetry đã chọn.",
    )