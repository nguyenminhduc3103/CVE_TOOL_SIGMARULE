"""ValidationResult — Model kết quả Validate Stage (Task 4).

Đây là output của run_validate_stage(), gắn vào EnrichedCVEContext.validation
sau khi Step 2 hoàn thành. Chứa toàn bộ thông tin so sánh AI output với
Ground Truth (CTID/CAPEC) và đánh giá rủi ro False Positive.

Nằm trong src.domain.models để EnrichedCVEContext có thể import mà không
gây circular dependency với src.usecases.step_2_analysis.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


VerdictType = Literal["PASS", "PARTIAL", "FAIL", "UNKNOWN"]
FPRiskType = Literal["LOW", "MEDIUM", "HIGH"]
GroundTruthSourceType = Literal["CTID", "CAPEC", "MIXED", "WHITELIST", "UNKNOWN"]
GroundTruthQualityType = Literal["HIGH", "PARTIAL", "UNKNOWN"]


class ValidationResult(BaseModel):
    """Kết quả validate output AI (TechnicalAnalysis + AttackMapping) với Ground Truth.

    Được tính toán bởi validate_stage.run_validate_stage() và gắn vào
    EnrichedCVEContext.validation để downstream (Step 3, Step 6) có thể
    dùng để đánh giá độ tin cậy của AI output.
    """

    # ----------------------------------------------------------------
    # Scores
    # ----------------------------------------------------------------
    technique_match_rate: float | None = None
    """Recall-based: |intersection(AI techniques, expected)| / |expected|.
    None nếu ground_truth_quality == 'UNKNOWN' hoặc expected rỗng."""

    behavior_match_rate: float | None = None
    """Recall-based: |intersection(AI behaviors, CAPEC behaviors)| / |CAPEC behaviors|.
    None nếu expected_behaviors rỗng."""

    overall_confidence_score: float | None = None
    """Weighted average: technique_match_rate * 0.6 + behavior_match_rate * 0.4.
    None nếu không tính được (UNKNOWN ground truth)."""

    # ----------------------------------------------------------------
    # Verdict
    # ----------------------------------------------------------------
    verdict: VerdictType | None = None
    """
    PASS:    technique_match_rate >= 0.7 AND false_positive_risk in LOW/MEDIUM
    PARTIAL: technique_match_rate >= 0.4 AND false_positive_risk != HIGH
    FAIL:    technique_match_rate < 0.4 HOẶC false_positive_risk == HIGH
    UNKNOWN: không có ground truth để so sánh
    """

    verdict_reason: str | None = None
    """Mô tả ngắn lý do verdict (dùng để debug/report)."""

    # Technique comparison
    matched_techniques: list[str] = Field(default_factory=list)
    """AI techniques khớp với expected ground truth (intersection)."""

    missing_techniques: list[str] = Field(default_factory=list)
    """Techniques có trong ground truth nhưng AI bỏ sót (expected - AI)."""

    extra_techniques: list[str] = Field(default_factory=list)
    """Techniques AI thêm vào nhưng không có trong ground truth (AI - expected).
    Không nhất thiết là sai — có thể ground truth chưa cover đầy đủ."""

    # Behavior comparison
    matched_behaviors: list[str] = Field(default_factory=list)
    """mandatory_behaviors AI sinh ra khớp với CAPEC expected behaviors."""

    # False Positive assessment
    whitelist_hits: list[str] = Field(default_factory=list)
    """Behaviors/processes AI đưa ra nằm trong OS whitelist (FP candidates)."""

    false_positive_risk: FPRiskType | None = None
    """LOW: <20% behaviors là whitelist | MEDIUM: 20-50% | HIGH: >50%"""

    # Ground Truth metadata
    ground_truth_source: GroundTruthSourceType | None = None
    """Nguồn ground truth được sử dụng: CTID > CAPEC > MIXED > WHITELIST > UNKNOWN."""

    ground_truth_quality: GroundTruthQualityType | None = None
    """HIGH: CTID direct | PARTIAL: CAPEC/Whitelist | UNKNOWN: không có data."""

    # Metadata
    validated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
