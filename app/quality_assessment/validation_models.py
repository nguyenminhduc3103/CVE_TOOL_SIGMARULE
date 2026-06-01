from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class SignalQuality(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class FalsePositiveRate(str, Enum):
    high = "high"
    medium = "medium"
    low = "low"


class ComplexityClass(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class DeploymentReadiness(str, Enum):
    experimental = "experimental"
    test = "test"
    production = "production"


class MaintenanceCost(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class QualityAssessment(BaseModel):
    signal_quality: SignalQuality
    false_positive_rate: FalsePositiveRate
    complexity_class: ComplexityClass
    deployment_readiness: DeploymentReadiness
    maintenance_cost: MaintenanceCost
    quality_score: int
    reasoning: str