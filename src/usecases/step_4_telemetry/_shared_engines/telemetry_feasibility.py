# Rule-based telemetry feasibility score (0..1). Weights: telemetry_found 0.40, fields_validated 0.30, logsource_mapped 0.20, correlation_clear 0.10.
from __future__ import annotations

from typing import Any

from src.domain.models.telemetry import SigmaLogsource


# Trọng số — sum = 1.0. Tweak cẩn thận.
_W_TELEMETRY_FOUND = 0.40
_W_FIELDS_VALIDATED = 0.30
_W_LOGSOURCE_MAPPED = 0.20
_W_CORRELATION_CLEAR = 0.10

# Typical CVE: 2-3 SigmaLogsource. Mức này → full score.
_EXPECTED_LOGSOURCE_MAX = 3.0


def compute_telemetry_feasibility(
    sigma_logsources: list[SigmaLogsource] | None,
    validated_fields: list[str] | None,
    invalid_fields: list[str] | None,
    correlation_required: bool | None,
    rule_strategy: list[str] | None = None,
) -> tuple[float, dict[str, float]]:
    """Compute telemetry_feasibility_score rule-based.

    Refactor Phase 7 (2026-07): Drop `candidate_logsources` parameter. AI emit
    semantic domains → Knowledge Resolver → canonical telemetry → Sigma. Step
    feasibility score không cần biết candidate domain nữa — chỉ cần sigma
    output + validated fields.

    Returns:
        Tuple (score ∈ [0, 1], breakdown dict).
    """
    sigma_logsources = sigma_logsources or []
    validated_fields = validated_fields or []
    invalid_fields = invalid_fields or []
    rule_strategy = rule_strategy or []

    # telemetry_found
    telemetry_found = min(1.0, len(sigma_logsources) / _EXPECTED_LOGSOURCE_MAX)

    # fields_validated — không có field nào → 0.5 (neutral; CVE có thể pure DoS)
    total_fields = len(validated_fields) + len(invalid_fields)
    if total_fields == 0:
        fields_validated = 0.5
    else:
        fields_validated = len(validated_fields) / total_fields

    # logsource_mapped: ratio sigma_logsources vs validated fields coverage
    # (Refactor Phase 7: không còn candidate_logsources → dùng unique categories)
    unique_categories = len({item.category for item in sigma_logsources})
    logsource_mapped = 1.0 if sigma_logsources else 0.0

    # correlation_clear
    if correlation_required is None or correlation_required is False:
        correlation_clear = 1.0
    else:
        correlation_clear = 0.7 if rule_strategy else 0.3

    score = (
        _W_TELEMETRY_FOUND * telemetry_found
        + _W_FIELDS_VALIDATED * fields_validated
        + _W_LOGSOURCE_MAPPED * logsource_mapped
        + _W_CORRELATION_CLEAR * correlation_clear
    )

    score = max(0.0, min(1.0, score))
    breakdown: dict[str, float] = {
        "telemetry_found": round(telemetry_found, 3),
        "fields_validated": round(fields_validated, 3),
        "logsource_mapped": round(logsource_mapped, 3),
        "correlation_clear": round(correlation_clear, 3),
        "n_sigma_logsources": float(len(sigma_logsources)),
        "n_validated_fields": float(len(validated_fields)),
        "n_invalid_fields": float(len(invalid_fields)),
    }
    return round(score, 2), breakdown