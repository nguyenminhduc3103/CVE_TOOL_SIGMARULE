from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class SchemaCheckOutcome:
    schema_title: str                  # Read directly from schema["title"] at runtime
    is_valid: bool
    errors: list[str]                  # Raw messages from jsonschema, path + reason
    fields_present: list[str]          # Top-level schema["properties"] present in the rule
    fields_absent: list[str]           # Top-level schema["properties"] missing from the rule
    fields_outside_schema: list[str]   # Fields in the rule NOT in schema["properties"]
                                       # (Not inherently an error, as Sigma schemas usually don't restrict additionalProperties)


@dataclass(frozen=True)
class ConformanceResult:
    document_type: str                   # "detection_rule" | "correlation_rule" | "sigma_filter" | "unknown"
    classification_notes: list[str]      # Anomalies detected during document classification
    outcome: Optional[SchemaCheckOutcome] # None if document_type is sigma_filter or unknown. Never None at top-level.
