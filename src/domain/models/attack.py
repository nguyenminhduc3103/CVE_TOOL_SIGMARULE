from pydantic import BaseModel


class TechnicalAnalysis(BaseModel):
    exploit_vector: str | None = None
    pre_auth: bool | None = None
    remote_exploitable: bool | None = None
    exploit_complexity: str | None = None
    confidence: float | None = None
    mandatory_behaviors: list[str] | None = None
    evasive_indicators: list[str] | None = None
    exploit_requirements: list[str] | None = None
    reasoning: list[str] | None = None
    # === Two-phase refactor (Phase 1 output) ===
    # Phase 2 AI anchors on these to avoid AV:N→T1190 bias.
    # NOTE: ExecutionSurface/DeliveryVector types are in src/domain/models/execution_surface.py
    execution_surface: str | None = None
    delivery_vector: str | None = None
    user_interaction_required: bool | None = None
    # === End two-phase fields ===
    ai_used: bool | None = None
    ai_retry_count: int = 0
    ai_model: str | None = None
    ai_models_used: list[str] | None = None


class AttackMapping(BaseModel):
    tactics: list[str] | None = None
    techniques: list[str] | None = None
    subtechniques: list[str] | None = None
    confidence: float | None = None
    mapping_reasons: list[str] | None = None
    attack_mapping_confidence: float | None = None
    validation_warnings: list[str] | None = None
    dropped_tactics: list[str] | None = None
    dropped_techniques: list[str] | None = None
    dropped_subtechniques: list[str] | None = None
    ai_used: bool | None = None
    ai_retry_count: int = 0
    ai_model: str | None = None
    ai_models_used: list[str] | None = None
