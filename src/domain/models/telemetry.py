from __future__ import annotations

from pydantic import BaseModel, Field


# Sigma taxonomy whitelist — dùng bởi taxonomy_validator để filter invalid fields.
SIGMA_CATEGORY_WHITELIST: frozenset[str] = frozenset({
    "process_creation",
    "webserver",
    "network_connection",
    "file_event",
    "registry_event",
    "image_load",
    "dns_query",
    "ps_script",
    "firewall",
    "antivirus",
    "process_access",
})

# Sigma product whitelist (vendor/service).
SIGMA_PRODUCT_WHITELIST: frozenset[str] = frozenset({
    "windows", "linux", "macos", "esxi", "aws", "gcp", "azure",
    "zeek", "suricata", "apache", "nginx", "iis", "tomcat",
    "office365", "google_workspace", "okta", "cisco", "fortinet",
    "paloalto", "m365", "linux_container", "kubernetes",
})


# Sigma primitives


class SigmaLogsource(BaseModel):
    """Sigma logsource (category, product, service) — taxonomy-enforced."""

    category: str
    product: str
    service: str | None = None


class TelemetryRequirements(BaseModel):
    """Required telemetry artifacts (e.g. Sysmon EID set)."""

    required_event_ids: list[str] | None = None


# Detection features — bridge Step 4 → Step 6.
# AI emit "feature phát hiện" chia 3 tier theo độ bền.
# Step 6 dùng thẳng stable_features làm blueprint cho `selection:` block —
# không phải re-derive từ telemetry.


class DetectionFeature(BaseModel):
    """Một feature phát hiện trong log (literal value, pattern, hoặc cả hai)."""

    field: str = Field(min_length=1, description="Sigma field name (vd 'ParentImage', 'DestinationPort')")
    value: str | int | None = Field(default=None, description="Literal value (vd '\\\\java.exe', 389)")
    pattern: str | None = Field(default=None, description="Keyword / regex pattern (vd 'jndi:ldap')")
    rationale: str = Field(default="", description="Vì sao feature = detection signal (cho reviewer)")


class DetectionFeatures(BaseModel):
    """3-tier detection features — bridge từ telemetry sang Sigma rule.

    - ``stable_features`` → "khó né", rule bền vững — dùng làm PRIMARY selection.
    - ``observable_features`` → trung bình, có thể obfuscate — bổ sung.
    - ``optional_features`` → "dễ né", easy to spoof — dùng làm supplementary/filter.
    """

    stable_features: list[DetectionFeature] = Field(default_factory=list)
    observable_features: list[DetectionFeature] = Field(default_factory=list)
    optional_features: list[DetectionFeature] = Field(default_factory=list)


# TelemetryAssessment — schema chính Step 4.
#
# Refactor 2026-07:
#   - AI emit **candidate_** (free-form semantic).
#   - Code layer (mapper + validator) sinh schema-enforced fields.
#   - telemetry_feasibility_score: RULE-BASED (không AI tự chấm).
#   - telemetry_confidence: AI self-assessment.


class TelemetryAssessment(BaseModel):
    """Đầu ra Step 4 — Telemetry & logsource selection.

    Field chia 3 layer:
      1. AI emit (loose): candidate_*, detection_*, telemetry_*, rule_*, observable_detection_features.
      2. Code layer (deterministic): sigma_logsources, required_fields, validated_*, telemetry_feasibility_score + breakdown.
      3. Metadata: ai_used, ai_retry_count, ai_model.
    """

    # ----- AI emit (LOOSE) -----
    candidate_logsources: list[str] | None = Field(
        default=None,
        description="AI emit free-form (vd 'process_creation', 'network', 'apache'). Mapper sinh sigma_logsources.",
    )
    candidate_fields: list[str] | None = Field(
        default=None,
        description="AI emit fields (có thể ngoài taxonomy). Validator sinh required_fields.",
    )
    detection_axis: list[str] | None = None
    primary_axis: str | None = None
    required_events: list[str] | None = Field(
        default=None,
        description="Sysmon EID cần bật (vd ['1', '3']) — AI emit.",
    )
    telemetry_requirements: str | None = Field(
        default=None,
        description="Mô tả text yêu cầu telemetry (vd 'Sysmon EID 1 with parent-child').",
    )
    telemetry_gaps: list[str] | None = Field(
        default=None,
        description="Rủi ro / thiếu telemetry (vd 'image_load requires EID 7 — thường tắt').",
    )
    gap_severity: str | None = Field(
        default=None,
        description="Mức độ nghiêm trọng của gaps: 'low' | 'medium' | 'high'.",
    )
    rule_strategy: list[str] | None = Field(
        default=None,
        description="Gợi ý cách Step 6 viết rule (vd 'prioritize post-exploit'). Đổi tên từ detection_strategy.",
    )
    correlation_required: bool | None = None
    field_taxonomy_notes: list[str] | None = None
    telemetry_confidence: float | None = Field(
        default=None,
        ge=0.0, le=1.0,
        description="AI self-assessment (semantic). Khác telemetry_feasibility_score (technical).",
    )
    observable_detection_features: DetectionFeatures | None = Field(
        default=None,
        description="3-tier detection features (stable/observable/optional) — bridge Step 4 → Step 6.",
    )

    # ----- Code layer (DETERMINISTIC) -----
    sigma_logsources: list[SigmaLogsource] | None = Field(
        default=None,
        description="Schema-enforced logsource objects. Logsource_mapper.map() sinh từ candidate_logsources.",
    )
    required_fields: list[str] | None = Field(
        default=None,
        description="= intersection(candidate_fields, LOGSOURCE_FIELDS[category]). Validator sinh.",
    )
    validated_fields: list[str] | None = None
    invalid_fields: list[str] | None = None
    taxonomy_warnings: list[str] | None = None
    telemetry_feasibility_score: float | None = Field(
        default=None,
        ge=0.0, le=1.0,
        description="RULE-BASED score (telemetry_found + fields_validated + logsource_mapped + correlation_clear).",
    )
    telemetry_feasibility_breakdown: dict[str, float] | None = Field(
        default=None,
        description="Audit trail từng thành phần của feasibility_score.",
    )

    # ----- Legacy fields (backward compat) -----
    pre_exploit_detection: list[str] | None = None
    post_exploit_detection: list[str] | None = None
    impact_detection: list[str] | None = None
    # detection_strategy: alias cũ — code mới dùng rule_strategy.
    detection_strategy: list[str] | None = None

    # ----- Metadata -----
    ai_used: bool | None = None
    ai_retry_count: int = 0
    ai_model: str | None = None
