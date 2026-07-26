from __future__ import annotations

from typing import Literal

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

# 5 nhóm:
#   - Event-level: EventID, Provider, Channel
#   - URI pattern: Uri, RequestPath, cs-uri-stem, RequestURI, QueryString
#   - Protocol op: HTTPMethod, LDAPOperation, SMBCommand, DNSQueryType
#   - Registry path: TargetObject, RegistryPath, KeyPath
#   - Protocol version: Protocol, Smbs1
_STABLE_FEATURE_FIELDS = frozenset({
    # Event-level
    "EventID", "Provider", "Channel",
    # URI pattern (web attacks)
    "Uri", "RequestPath", "cs-uri-stem", "RequestURI", "QueryString",
    # Protocol op
    "HTTPMethod", "http_method", "Method",
    "LDAPOperation", "ldap_operation",
    "SMBCommand", "smb_command",
    "DNSQueryType", "dns_query_type",
    # Registry path
    "TargetObject", "RegistryPath", "KeyPath",
    # Protocol/version
    "Protocol", "Smbs1", "SMBv1",
})


class DetectionFeature(BaseModel):
    """Một feature phát hiện trong log (literal value, pattern, hoặc cả hai).

    Refactor 2026-07: `value` chấp nhận `list[str]` để AI có thể emit nhiều
    literal values cho cùng field (vd Image=\\cmd.exe OR \\powershell.exe).
    """

    field: str = Field(min_length=1, description="Sigma field name (vd 'ParentImage', 'DestinationPort')")
    value: str | int | list[str] | None = Field(
        default=None,
        description="Literal value(s). vd '\\\\cmd.exe' hoặc ['\\\\cmd.exe', '\\\\powershell.exe']",
    )
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

    # ----- AI emit (SEMANTIC) — Refactor 2026-07 -----
    candidate_telemetry_domains: list[str] | None = Field(
        default=None,
        description="AI emit 2-5 canonical semantic domains (identity, process, network, "
                    "registry, filesystem, dns, ldap, http, cloud, container, kubernetes, ...).",
    )
    invalid_domains: list[str] | None = Field(
        default=None,
        description="Domains AI emit nhưng không match KB — audit cho reviewer.",
    )
    candidate_semantic_tags: list[str] | None = Field(
        default=None,
        description="Free-form tags cho context (vd ['Netlogon', 'MachineAccount', 'DomainController'] cho Zerologon).",
    )
    candidate_canonical_fields: list[str] | None = Field(
        default=None,
        description="Field names AI muốn detect on. Validator match với canonical field DB.",
    )
    detection_axis: list[str] | None = None
    primary_axis: str | None = None
    required_events: list[str] | None = Field(
        default=None,
        description="Sysmon EID cần bật (vd ['1', '3']) — từ Knowledge Resolver.",
    )
    telemetry_requirements: dict[str, list[str]] | None = Field(
        default=None,
        description="Structured dict — vd {'windows_security': ['4742', '4624'], 'sysmon': ['1', '3']}. "
                    "Step 6 đọc dễ hơn string.",
    )
    telemetry_gaps: list[str] | None = Field(
        default=None,
        description="Rủi ro / thiếu telemetry (vd 'image_load requires EID 7 — thường tắt').",
    )
    gap_severity: str | None = Field(
        default=None,
        description="Mức độ nghiêm trọng của gaps: 'low' | 'medium' | 'high'.",
    )
    recommended_rule_strategy: list[str] | None = Field(
        default=None,
        description="Gợi ý cách Step 6 viết rule (vd 'prioritize post-exploit').",
    )
    correlation_required: bool | None = None
    field_taxonomy_notes: list[str] | None = None
    telemetry_confidence: float | None = Field(
        default=None,
        ge=0.0, le=1.0,
        description="AI self-assessment (semantic). Khác effective_confidence (× validation ratio).",
    )
    effective_confidence: float | None = Field(
        default=None,
        ge=0.0, le=1.0,
        description="AI confidence × validation ratio × domain resolution ratio. Phản ánh thực tế.",
    )
    # 3-tier features — flattened (Refactor 2026-07)
    stable_features: list[DetectionFeature] | None = Field(
        default=None,
        description="Stable features — đặc trưng bất biến, attacker rất khó bypass "
                    "(vd EventID=4742, URI contains jndi:ldap, HTTPMethod=POST, "
                    "TargetObject=*\\Run\\*). Field name phải thuộc _STABLE_FEATURE_FIELDS.",
    )
    conditional_features: list[DetectionFeature] | None = Field(
        default=None,
        description="Conditional features — observable nhưng context-dependent (vd Image=cmd.exe, CommandLine).",
    )
    optional_features: list[DetectionFeature] | None = Field(
        default=None,
        description="Optional features — dễ spoof (vd UserAgent, SourceIp).",
    )
    telemetry_selection_rationale: list[str] | None = Field(
        default=None,
        description="Vì sao chọn các domain này — 2-4 bullets cho reviewer.",
    )

    # ----- Phase 7 (2026-07): Explainability + audit -----
    provenance: list["ProvenanceStep"] | None = Field(
        default=None,
        description="Audit trail: Domain → KB → Canonical → Sigma. Mỗi step giải thích "
                    "vì sao mapping xảy ra (KB mapping_reason).",
    )
    ai_hallucination_ratio: float | None = Field(
        default=None,
        ge=0.0, le=1.0,
        description="|required_fields - validated_fields| / max(required, 1). "
                    "0.0 = perfect mapping, 1.0 = total mismatch. Audit telemetry.",
    )

    # ----- Canonical layer (deterministic) -----
    canonical_telemetry: list[str] | None = Field(
        default=None,
        description="Canonical Telemetry IDs (vd ['windows_security_audit', 'sysmon_process']).",
    )
    canonical_fields: list[str] | None = Field(
        default=None,
        description="Canonical field names resolved (vd ['target_user', 'event_id', 'command_line']).",
    )
    skipped_domains: list[str] | None = Field(
        default=None,
        description="Domains không match canonical telemetry cho platforms/surfaces hiện tại.",
    )

    # ----- DEPRECATED (Phase 7 2026-07): candidate_logsources REMOVED.
    # Pipeline mới: AI emit candidate_telemetry_domains → Knowledge Resolver →
    # canonical_telemetry → Sigma mapper → sigma_logsources. Field này không
    # còn data source nào emit, không ai đọc. Removed toàn tập.
    candidate_fields: list[str] | None = Field(
        default=None,
        description="DEPRECATED: dùng candidate_canonical_fields.",
    )
    rule_strategy: list[str] | None = Field(
        default=None,
        description="DEPRECATED: dùng recommended_rule_strategy.",
    )
    observable_detection_features: DetectionFeatures | None = Field(
        default=None,
        description="DEPRECATED: dùng stable_features/conditional_features/optional_features.",
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


# ============================================================
# Phase 7 (2026-07): Explainability + audit
# ============================================================


class ProvenanceStep(BaseModel):
    """Một bước trong audit trail: Domain → KB → Canonical → Sigma.

    Mỗi step giải thích mapping xảy ra (KB mapping_reason) để reviewer
    hiểu pipeline.
    """

    step: str = Field(description="Step name: 'domain', 'kb_lookup', 'canonical_resolution', 'sigma_mapping'")
    input: str = Field(description="Input của step (vd 'identity', 'windows_security_audit')")
    output: str = Field(description="Output của step (vd 'windows_security_audit', '4624')")
    reason: str = Field(default="", description="KB mapping_reason — vì sao mapping xảy ra")
    kb_source: str | None = Field(
        default=None,
        description="Path/file trong KB chứa mapping này (vd 'telemetry_domains.yaml:14')",
    )


class StructuredRationale(BaseModel):
    """Phase 7: Structured rationale per domain — Why / Evidence / Fallback / Confidence.

    Thay vì free-form `telemetry_selection_rationale: list[str]`, mỗi domain có
    structured rationale mà Knowledge Resolver reuse được cho Step 6.
    """

    domain: str = Field(description="Telemetry domain (vd 'process', 'network')")
    why: str = Field(description="Vì sao chọn domain này (vd 'RCE inevitably creates execution artifacts')")
    primary_evidence: list[str] = Field(
        default_factory=list,
        description="Primary event/field evidence (vd ['Sysmon EID 1', 'process_creation'])",
    )
    fallback: list[str] = Field(
        default_factory=list,
        description="Fallback telemetry khi primary không có (vd ['4688', 'Windows Security'])",
    )
    confidence: Literal["low", "medium", "high"] = Field(
        default="medium",
        description="AI self-assessment confidence",
    )
