# Engine-agnostic canonical telemetry + field models (decouples pipeline from Sigma/ECS/Splunk).
from __future__ import annotations

from pydantic import BaseModel, Field


class CanonicalTelemetry(BaseModel):
    """Engine-agnostic telemetry source.

    Vendor: 'windows', 'linux', 'aws', 'azure', 'kubernetes', 'm365', 'zeek', ...
    log_path: Source-specific path (Windows Security log, /var/log/audit, CloudTrail...)
    events: Specific event IDs/names within this telemetry source
    fields: Field names AS-IS in the source (not yet sigma-mapped)
    coverage: 'high' | 'medium' | 'low' — detection coverage confidence
    """

    id: str
    domain: str
    vendor: str
    execution_surfaces: list[str]
    log_path: str
    events: list[str] = Field(default_factory=list)
    fields: list[str] = Field(default_factory=list)
    coverage: str = "medium"


class CanonicalField(BaseModel):
    """Engine-agnostic field name với backend aliases.

    AI emit canonical name ('target_user') hoặc alias ('TargetAccount').
    Resolver match và trả về canonical + backends dict.
    """

    canonical: str
    semantic: str = ""
    aliases: list[str] = Field(default_factory=list)
    backends: dict[str, str] = Field(default_factory=dict)


class CanonicalTelemetryBundle(BaseModel):
    """Bundle emitted by Knowledge Resolver.

    skipped_domains: domains AI emit nhưng không có canonical telemetry cho
        platforms/surfaces hiện tại → cảnh báo cho reviewer.
    resolution_warnings: những issue trong resolution (vendor mismatch, ...).
    """

    canonical_telemetry: list[CanonicalTelemetry] = Field(default_factory=list)
    canonical_fields: list[CanonicalField] = Field(default_factory=list)
    skipped_domains: list[str] = Field(default_factory=list)
    resolution_warnings: list[str] = Field(default_factory=list)