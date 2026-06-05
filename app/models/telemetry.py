from pydantic import BaseModel


class SigmaLogsource(BaseModel):
    category: str
    product: str
    service: str | None = None


class TelemetryRequirements(BaseModel):
    required_event_ids: list[str] | None = None


class TelemetryAssessment(BaseModel):
    detection_axis: list[str] | None = None
    candidate_logsources: list[str] | None = None
    sigma_logsources: list[SigmaLogsource] | None = None
    telemetry_requirements: TelemetryRequirements | None = None
    pre_exploit_detection: list[str] | None = None
    post_exploit_detection: list[str] | None = None
    impact_detection: list[str] | None = None
    telemetry_feasibility_score: float | None = None
    detection_strategy: list[str] | None = None
    required_events: list[str] | None = None
    required_fields: list[str] | None = None
    telemetry_confidence: float | None = None
    correlation_required: bool | None = None
    field_taxonomy_notes: list[str] | None = None
    validated_fields: list[str] | None = None
    invalid_fields: list[str] | None = None
    taxonomy_warnings: list[str] | None = None
    ai_used: bool | None = None
    ai_fallback_used: bool | None = None
    ai_model: str | None = None
