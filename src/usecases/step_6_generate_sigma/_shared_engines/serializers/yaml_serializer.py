from __future__ import annotations

from collections.abc import Mapping


class SigmaYamlSerializer:
    def serialize(self, rule) -> str:
        lines: list[str] = []
        metadata = rule.metadata

        self._add_scalar(lines, "title", metadata.title)
        self._add_scalar(lines, "id", metadata.id)
        self._add_scalar(lines, "status", metadata.status)
        self._add_folded(lines, "description", metadata.description)
        self._add_list(lines, "references", metadata.references)
        self._add_scalar(lines, "author", metadata.author)
        self._add_scalar(lines, "date", metadata.date)
        self._add_list(lines, "tags", metadata.tags)
        self._add_list(lines, "falsepositives", metadata.falsepositives)
        self._add_scalar(lines, "level", metadata.level)
        self._add_related(lines, metadata.related)

        self._add_logsource(lines, rule.logsource)
        self._add_detection(lines, rule.detection.selections, rule.detection.condition)

        self._add_scalar(lines, "x_family", rule.x_family)
        self._add_scalar(lines, "x_signature", rule.x_signature)
        self._add_number(lines, "x_detection_confidence", rule.x_detection_confidence)
        self._add_bool(lines, "x_correlation_required", rule.x_correlation_required)
        self._add_bool(lines, "x_correlation_logic", rule.x_correlation_logic)
        self._add_scalar(lines, "x_correlation_reasoning", rule.x_correlation_reasoning)
        self._add_number(lines, "x_sigma_quality_score", rule.x_sigma_quality_score)
        self._add_scalar(lines, "x_sigma_quality_grade", rule.x_sigma_quality_grade)
        self._add_bool(lines, "x_sigma_validation_passed", rule.x_sigma_validation_passed)
        self._add_number(lines, "x_quality_score", rule.x_quality_score)
        self._add_scalar(lines, "x_signal_quality", rule.x_signal_quality)
        self._add_scalar(lines, "x_false_positive_rate", rule.x_false_positive_rate)
        self._add_scalar(lines, "x_complexity_class", rule.x_complexity_class)
        self._add_scalar(lines, "x_deployment_readiness", rule.x_deployment_readiness)
        self._add_scalar(lines, "x_maintenance_cost", rule.x_maintenance_cost)
        self._add_list(lines, "x_secondary_logsources", rule.x_secondary_logsources)

        return "\n".join(lines).rstrip() + "\n"

    def _add_scalar(self, lines: list[str], key: str, value: str | None) -> None:
        if value is None:
            return
        lines.append(f"{key}: {self._quote(value)}")

    def _add_number(self, lines: list[str], key: str, value: float | None) -> None:
        if value is None:
            return
        lines.append(f"{key}: {value:.2f}")

    def _add_bool(self, lines: list[str], key: str, value: bool | None) -> None:
        if value is None:
            return
        lines.append(f"{key}: {'true' if value else 'false'}")

    def _add_list(self, lines: list[str], key: str, values: list[str]) -> None:
        if not values:
            return
        lines.append(f"{key}:")
        for value in values:
            lines.append(f"  - {self._quote(value)}")

    def _add_folded(self, lines: list[str], key: str, value: str) -> None:
        lines.append(f"{key}: >")
        for line in value.splitlines() or [""]:
            lines.append(f"  {line}" if line else "  ")

    def _add_related(self, lines: list[str], related: list[dict[str, str]]) -> None:
        if not related:
            lines.append("related: []")
            return
        lines.append("related:")
        for item in related:
            lines.append("  - id: {0}".format(self._quote(item.get("id", ""))))
            lines.append("    type: {0}".format(self._quote(item.get("type", ""))))

    def _add_logsource(self, lines: list[str], logsource: Mapping[str, str]) -> None:
        lines.append("logsource:")
        for key in ("category", "product", "service"):
            value = logsource.get(key)
            if value:
                lines.append(f"  {key}: {self._quote(value)}")

    def _add_detection(self, lines: list[str], selections: Mapping[str, Mapping[str, list[str]]], condition: str) -> None:
        lines.append("detection:")
        for name, fields in selections.items():
            lines.append(f"  {name}:")
            for field_name, values in fields.items():
                lines.append(f"    {field_name}:")
                for value in values:
                    lines.append(f"      - {self._quote(value)}")
        lines.append(f"  condition: {condition}")

    def _quote(self, value: str) -> str:
        if value == "":
            return '""'
        if value.lower() in {"true", "false", "null", "~"}:
            return f'"{value}"'
        if any(char in value for char in [":", "#", "{", "}", "[", "]", ",", "&", "*", "?", "|", ">", "=", "!", "%", "@", "`", "\\"]):
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            return f'"{escaped}"'
        if value.startswith(" ") or value.endswith(" "):
            escaped = value.replace('"', '\\"')
            return f'"{escaped}"'
        return value