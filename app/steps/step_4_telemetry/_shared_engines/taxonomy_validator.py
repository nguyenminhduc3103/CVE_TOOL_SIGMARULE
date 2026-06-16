from __future__ import annotations

from app.steps.step_4_telemetry._shared_engines.field_mapper import LOGSOURCE_FIELDS


def validate_fields_by_logsources(logsources: list[str], fields: list[str]) -> tuple[list[str], list[str], list[str]]:
    allowed: set[str] = set()
    for logsource in logsources:
        allowed.update(LOGSOURCE_FIELDS.get(logsource, ()))

    validated_fields: list[str] = []
    invalid_fields: list[str] = []
    warnings: list[str] = []

    for field in fields:
        if field in allowed:
            if field not in validated_fields:
                validated_fields.append(field)
            continue

        if field not in invalid_fields:
            invalid_fields.append(field)
        warnings.append(f"invalid_field_removed:{field}")

    return validated_fields, invalid_fields, warnings
