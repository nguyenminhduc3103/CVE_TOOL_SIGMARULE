# Validate AI-emitted candidate fields against canonical field DB (sigma/ecs/splunk aliases).
from __future__ import annotations

from src.usecases.step_4_telemetry._resolver.canonical_model import CanonicalField


def validate_candidate_fields(
    candidate_fields: list[str],
    canonical_fields: list[CanonicalField],
) -> tuple[list[str], list[str], list[str]]:
    """Validate AI-emitted fields against canonical field DB.

    Args:
        candidate_fields: Field names AI muốn detect on.
        canonical_fields: Canonical field definitions từ Knowledge Resolver.

    Returns:
        (validated_fields, invalid_fields, warnings)

    Logic:
        - candidate == cf.canonical → validated (canonical name)
        - candidate ∈ cf.aliases → validated
        - Otherwise → invalid + warning
    """
    valid: list[str] = []
    invalid: list[str] = []
    warnings: list[str] = []
    seen_valid: set[str] = set()

    for cand in candidate_fields or []:
        if not cand:
            continue
        matched = False
        for cf in canonical_fields:
            if cand == cf.canonical or cand in cf.aliases:
                if cand not in seen_valid:
                    valid.append(cand)
                    seen_valid.add(cand)
                matched = True
                break
        if not matched:
            invalid.append(cand)
            warnings.append(f"unknown_field:{cand}")

    return valid, invalid, warnings