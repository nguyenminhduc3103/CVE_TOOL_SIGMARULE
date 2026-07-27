"""Resolver — code layer cho semantic → canonical → Sigma pipeline.

Pipeline:
  AI emit (semantic domains/tags/fields)
    → domain_validator (L2: validate against KB whitelist)
    → knowledge_resolver (L3: resolve to Canonical Telemetry)
    → canonical_model (L4: Pydantic models)
    → sigma_mapper (L5: Canonical → SigmaLogsource)
    → field_mapper (L5: candidate fields → validated via canonical field DB)

Knowledge base (YAML) ở `_knowledge/`. Code layer này chỉ đọc KB.
"""
from __future__ import annotations

from src.usecases.step_4_telemetry._resolver.canonical_model import (
    CanonicalField,
    CanonicalTelemetry,
    CanonicalTelemetryBundle,
)
from src.usecases.step_4_telemetry._resolver.domain_validator import validate_domains
from src.usecases.step_4_telemetry._resolver.field_mapper import (
    validate_candidate_fields,
)
from src.usecases.step_4_telemetry._resolver.knowledge_resolver import resolve
from src.usecases.step_4_telemetry._resolver.sigma_mapper import (
    SIGMA_CATEGORY_MAP,
    map_to_sigma,
)

__all__ = [
    "CanonicalField",
    "CanonicalTelemetry",
    "CanonicalTelemetryBundle",
    "SIGMA_CATEGORY_MAP",
    "map_to_sigma",
    "resolve",
    "validate_candidate_fields",
    "validate_domains",
]