"""Thin re-export wrapper — ValidationResult đã được chuyển sang
app.shared.models.validation để EnrichedCVEContext có thể import không
gây circular dependency.

Import từ đây vẫn hoạt động bình thường (backward-compatible).
"""
from src.domain.models.validation import (  # noqa: F401
    FPRiskType,
    GroundTruthQualityType,
    GroundTruthSourceType,
    ValidationResult,
    VerdictType,
)

__all__ = [
    "ValidationResult",
    "VerdictType",
    "FPRiskType",
    "GroundTruthSourceType",
    "GroundTruthQualityType",
]
