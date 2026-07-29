# Resolver layer: semantic AI output → canonical telemetry → Sigma schema.
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