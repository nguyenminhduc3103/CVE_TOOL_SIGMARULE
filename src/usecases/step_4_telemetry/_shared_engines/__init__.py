"""Shared engines for Step 4 — Telemetry selector.

Refactor 2026-07: engines split into:
- AI-emit layer: map_logsources_from_candidates(), map_required_fields()
- Rule-based: select_detection_axis(), advise_correlation()
- Validators: validate_fields_by_logsources()
- Feasibility: compute_telemetry_feasibility()
"""

from src.usecases.step_4_telemetry._shared_engines.correlation_advisor import (
    advise_correlation,
)
from src.usecases.step_4_telemetry._shared_engines.field_mapper import (
    LOGSOURCE_FIELDS,
    map_required_fields,
    validate_sigma_taxonomy,
    validate_sigma_taxonomy_multi,
)
from src.usecases.step_4_telemetry._shared_engines.logsource_mapper import (
    map_logsources,
    map_logsources_from_candidates,
)
from src.usecases.step_4_telemetry._shared_engines.taxonomy_validator import (
    validate_fields_by_logsources,
)
from src.usecases.step_4_telemetry._shared_engines.telemetry_feasibility import (
    compute_telemetry_feasibility,
)
from src.usecases.step_4_telemetry._shared_engines.telemetry_selector import (
    select_detection_axis,
)

__all__ = [
    "advise_correlation",
    "LOGSOURCE_FIELDS",
    "map_required_fields",
    "map_logsources",
    "map_logsources_from_candidates",
    "validate_fields_by_logsources",
    "validate_sigma_taxonomy",
    "validate_sigma_taxonomy_multi",
    "compute_telemetry_feasibility",
    "select_detection_axis",
]
