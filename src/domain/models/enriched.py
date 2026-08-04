from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field

from src.domain.constants import PIPELINE_VERSION
from src.domain.models.attack import AttackMapping, TechnicalAnalysis
from src.domain.models.coverage import CoverageAssessment
from src.domain.models.cve import CoreCVEData
from src.usecases.step_4_telemetry.models.telemetry_plan import TelemetryPlan
from src.domain.models.telemetry_discovery import PoCSummary, TelemetryDiscovery, TelemetrySourceAssessment
from src.domain.models.triage import TriageContext


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
    ai_steps_used: list[str] = Field(default_factory=list)
    ai_total_cost_usd: float | None = None


class EnrichedCVEContext(BaseModel):
    core: CoreCVEData
    triage: TriageContext
    analysis: TechnicalAnalysis | None = None
    attack: AttackMapping | None = None
    coverage: CoverageAssessment | None = None
    telemetry: TelemetryPlan | None = None  # Step 4: new TelemetryPlan (replaces TelemetryAssessment)
    intel: PoCSummary | None = None  # Step 4 input: bundled PoC doc + network + exposure
    telemetry_discovery: TelemetryDiscovery | None = None  # Step 1.3: Two-phase discovery
    telemetry_assessment: TelemetrySourceAssessment | None = None  # Step 1.4: Gate decision
    threat_intelligence: ThreatIntelligenceContext | None = None
    attack_mapping: AttackMappingContext | None = None
    detections: DetectionContext | None = None
    ai_features: AIFeaturesContext | None = None
    provider_status: dict[str, str] = Field(default_factory=dict)
    provider_errors: dict[str, str] = Field(default_factory=dict)
    metadata: EnrichmentMetadata = Field(default_factory=EnrichmentMetadata)
