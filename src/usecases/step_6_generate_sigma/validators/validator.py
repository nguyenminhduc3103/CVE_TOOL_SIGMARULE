from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .validation_models import ConformanceResult, SchemaCheckOutcome

SCHEMA_CACHE_DIR = Path(__file__).parent / "schemas"

SCHEMA_PATHS = {
    "detection_rule": SCHEMA_CACHE_DIR / "sigma-detection-rule-schema.json",
    "correlation_rule": SCHEMA_CACHE_DIR / "sigma-correlation-rules-schema.json",
}

def detect_document_type(rule: Mapping[str, Any]) -> tuple[str, list[str]]:
    notes: list[str] = []
    has_correlation = "correlation" in rule
    has_detection = "detection" in rule

    if has_correlation:
        return "correlation_rule", notes
    if has_detection:
        return "detection_rule", notes

    return "unknown", notes


def _load_schema(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        schema = json.load(f)
    Draft202012Validator.check_schema(schema)
    return schema


def _format_error(error: Any) -> str:
    path = ".".join(str(part) for part in error.absolute_path)
    return f"{path or '<root>'}: {error.message}"


def _sanitize_dict(d: Any) -> Any:
    """Recursively convert datetime objects to strings to pass JSONSchema validation."""
    from datetime import date, datetime
    if isinstance(d, dict):
        return {k: _sanitize_dict(v) for k, v in d.items()}
    elif isinstance(d, list):
        return [_sanitize_dict(v) for v in d]
    elif isinstance(d, (datetime, date)):
        return d.strftime("%Y-%m-%d")
    return d


def _check_against_schema(rule: Mapping[str, Any], schema: dict[str, Any]) -> SchemaCheckOutcome:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    sanitized_rule = _sanitize_dict(dict(rule))

    validation_errors = sorted(
        validator.iter_errors(sanitized_rule),
        key=lambda e: tuple(str(p) for p in e.absolute_path),
    )

    schema_fields = set(schema.get("properties", {}).keys())
    rule_fields = set(rule.keys())

    return SchemaCheckOutcome(
        schema_title=str(schema.get("title", "")),
        is_valid=not validation_errors,
        errors=[_format_error(e) for e in validation_errors],
        fields_present=sorted(schema_fields & rule_fields),
        fields_absent=sorted(schema_fields - rule_fields),
        fields_outside_schema=sorted(rule_fields - schema_fields),
    )


class SigmaConformanceChecker:
    def __init__(self) -> None:
        self.schemas: dict[str, dict[str, Any]] = {}
        for doc_type, path in SCHEMA_PATHS.items():
            self.schemas[doc_type] = _load_schema(path)

    def check_rule(self, rule: Mapping[str, Any]) -> ConformanceResult:
        if not isinstance(rule, Mapping):
            return ConformanceResult(document_type="unknown", classification_notes=[], outcome=None)
            
        doc_type, notes = detect_document_type(rule)
        
        if doc_type == "unknown":
            return ConformanceResult(
                document_type=doc_type,
                classification_notes=notes,
                outcome=None
            )
            
        schema = self.schemas[doc_type]
        outcome = _check_against_schema(rule, schema)
        
        return ConformanceResult(
            document_type=doc_type,
            classification_notes=notes,
            outcome=outcome
        )
 