"""Shared Pydantic models."""
from app.shared.models.attack import AttackFlow, AttackMapping, CWEMetadata, TechnicalAnalysis
from app.shared.models.core import CoreCVEData
from app.shared.models.coverage import CoverageAssessment
from app.shared.models.enriched import EnrichedCVEContext, EnrichmentMetadata
from app.shared.models.rule import RuleSkeleton
from app.shared.models.telemetry import TelemetryAssessment
from app.shared.models.triage import TriageContext

Rule = RuleSkeleton  # Backward compat alias

__all__ = [
    'AttackFlow', 'AttackMapping', 'CWEMetadata', 'TechnicalAnalysis',
    'CoreCVEData', 'CoverageAssessment', 'EnrichedCVEContext', 'EnrichmentMetadata',
    'Rule', 'RuleSkeleton', 'TelemetryAssessment', 'TriageContext',
]
