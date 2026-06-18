from pydantic import BaseModel

from app.shared.types.vulnerability_class import VulnerabilityClass


class CWEMetadata(BaseModel):
    cwe_ids: list[str] | None = None
    cwe_names: list[str] | None = None
    mapping_confidence: float | None = None


class AttackFlow(BaseModel):
    entry_vector: str | None = None
    execution_mechanism: str | None = None
    observable_side_effects: list[str] | None = None


class TechnicalAnalysis(BaseModel):
    family: str | None = None
    signature: str | None = None
    extracted_keywords: list[str] | None = None
    vulnerability_type: str | None = None
    vulnerability_class: VulnerabilityClass | None = None
    exploit_vector: str | None = None
    pre_auth: bool | None = None
    remote_exploitable: bool | None = None
    exploit_complexity: str | None = None
    confidence: float | None = None
    cwe_metadata: CWEMetadata | None = None
    attack_flow: AttackFlow | None = None
    likely_outcome: str | None = None
    mandatory_behaviors: list[str] | None = None
    evasive_indicators: list[str] | None = None
    exploit_requirements: list[str] | None = None
    reasoning: list[str] | None = None
    analysis_confidence: float | None = None
    classification_reason: list[str] | None = None
    behavior_reason: list[str] | None = None
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
    ai_used: bool | None = None
    ai_model: str | None = None
    ai_models_used: list[str] | None = None
