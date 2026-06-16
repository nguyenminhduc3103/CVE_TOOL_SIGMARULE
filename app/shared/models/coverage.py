from pydantic import BaseModel


class CoverageAssessment(BaseModel):
    decision: str | None = None
    matched_rule_ids: list[str] | None = None
    matched_titles: list[str] | None = None
    matched_rule_titles: list[str] | None = None
    coverage_score: float | None = None
    coverage_reasoning: list[str] | None = None
    similarity_reasoning: list[str] | None = None
    related_rules: list[str] | None = None
    related_attack_rules: list[str] | None = None
    overlap_score: float | None = None
    relationship_type: str | None = None
    reasoning: str | None = None
    skipped: bool | None = None
    overlap_breakdown: dict[str, float] | None = None
    decision_reason: str | None = None
