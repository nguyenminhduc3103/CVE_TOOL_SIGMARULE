from __future__ import annotations

from pydantic import BaseModel, Field

from app.sigma_generator.models.sigma_detection import SigmaDetection
from app.sigma_generator.models.sigma_metadata import SigmaMetadata


class SigmaRule(BaseModel):
    metadata: SigmaMetadata
    logsource: dict[str, str] = Field(default_factory=dict)
    detection: SigmaDetection
    x_family: str | None = None
    x_signature: str | None = None
    x_detection_confidence: float | None = None
    x_correlation_required: bool | None = None
    x_correlation_logic: bool | None = None
    x_correlation_reasoning: str | None = None
    x_sigma_quality_score: int | None = None
    x_sigma_quality_grade: str | None = None
    x_sigma_validation_passed: bool | None = None
    x_quality_score: int | None = None
    x_signal_quality: str | None = None
    x_false_positive_rate: str | None = None
    x_complexity_class: str | None = None
    x_deployment_readiness: str | None = None
    x_maintenance_cost: str | None = None
    x_secondary_logsources: list[str] = Field(default_factory=list)

    def to_yaml(self) -> str:
        from app.sigma_generator.serializers.yaml_serializer import SigmaYamlSerializer

        return SigmaYamlSerializer().serialize(self)