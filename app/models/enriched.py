from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field

from app.core.constants import PIPELINE_VERSION
from app.models.attack import AttackMapping, TechnicalAnalysis
from app.models.coverage import CoverageAssessment
from app.models.core import CoreCVEData
from app.models.telemetry import TelemetryAssessment
from app.models.triage import TriageContext


class ThreatIntelligenceContext(BaseModel):
    """Reserved for Phase 2 threat-intelligence enrichment."""

    indicators: list[str] | None = None
    sources: list[str] | None = None


class AttackMappingContext(BaseModel):
    """Reserved for Phase 2 attack-path mapping."""

    mitre_techniques: list[str] | None = None
    kill_chain_phases: list[str] | None = None


class TelemetryContext(BaseModel):
    """Reserved for Phase 2 telemetry signals."""

    events: list[str] | None = None


class DetectionContext(BaseModel):
    """Reserved for Phase 2 detection engineering outputs."""

    rules: list[str] | None = None


class AIFeaturesContext(BaseModel):
    """Reserved for Phase 2 AI-assisted features."""

    summary: str | None = None


class EnrichmentMetadata(BaseModel):
    enriched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    pipeline_version: str = PIPELINE_VERSION
    enrichment_duration_ms: int = 0
    providers_used: list[str] = Field(default_factory=list)
    partial_enrichment: bool = False
    provider_durations_ms: dict[str, int] | None = None
    references_truncated: bool | None = None
    cpes_truncated: bool | None = None


class EnrichedCVEContext(BaseModel):
    core: CoreCVEData
    triage: TriageContext
    analysis: TechnicalAnalysis | None = None
    attack: AttackMapping | None = None
    coverage: CoverageAssessment | None = None
    telemetry: TelemetryAssessment | None = None
    threat_intelligence: ThreatIntelligenceContext | None = None
    attack_mapping: AttackMappingContext | None = None
    detections: DetectionContext | None = None
    ai_features: AIFeaturesContext | None = None
    provider_status: dict[str, str] = Field(default_factory=dict)
    provider_errors: dict[str, str] = Field(default_factory=dict)
    metadata: EnrichmentMetadata = Field(default_factory=EnrichmentMetadata)
