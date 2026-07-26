"""Rule-based telemetry feasibility engine.

AI KHÔNG tự chấm telemetry_feasibility_score (cảm tính, không reproducible).
Score tính deterministic từ:
  - telemetry_found: số SigmaLogsource schema-enforced (0..1)
  - fields_validated: ratio validated / total candidate fields (0..1)
  - logsource_mapped: ratio mapped / total candidate terms (0..1)
  - correlation_clear: 1.0 nếu không cần correlation hoặc đã có strategy (0..1)

Công thức trọng số (sum = 1.0):
  score = 0.40 * telemetry_found + 0.30 * fields_validated
        + 0.20 * logsource_mapped + 0.10 * correlation_clear

Trả về (score, breakdown_dict) để audit.
"""
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
    candidate_logsources: list[str] | None,
    correlation_required: bool | None,
    rule_strategy: list[str] | None = None,
) -> tuple[float, dict[str, float]]:
    """Compute telemetry_feasibility_score rule-based.

    Returns:
        Tuple (score ∈ [0, 1], breakdown dict).
    """
    sigma_logsources = sigma_logsources or []
    validated_fields = validated_fields or []
    invalid_fields = invalid_fields or []
    candidate_logsources = candidate_logsources or []
    rule_strategy = rule_strategy or []

    # telemetry_found
    telemetry_found = min(1.0, len(sigma_logsources) / _EXPECTED_LOGSOURCE_MAX)

    # fields_validated — không có field nào → 0.5 (neutral; CVE có thể pure DoS)
    total_fields = len(validated_fields) + len(invalid_fields)
    if total_fields == 0:
        fields_validated = 0.5
    else:
        fields_validated = len(validated_fields) / total_fields

    # logsource_mapped
    if not candidate_logsources:
        logsource_mapped = 1.0 if sigma_logsources else 0.0
    else:
        # Ước lượng: min(mapped, candidate) / candidate
        mapped_count = min(len(sigma_logsources), len(candidate_logsources))
        logsource_mapped = mapped_count / len(candidate_logsources)

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
        "n_candidate_logsources": float(len(candidate_logsources)),
    }
    return round(score, 2), breakdown
