from __future__ import annotations

import re

from app.steps.step_6_rule_writer.validators.quality_scorer import QualityScorer
from app.steps.step_6_rule_writer.validators.validation_models import ValidationResult


class SigmaValidator:
    ALLOWED_LOGSOURCE_CATEGORIES = {
        "process_creation",
        "webserver",
        "network_connection",
        "image_load",
        "file_event",
        "registry_event",
    }

    TAG_PATTERN = re.compile(r"^attack\.t\d{4}(?:\.\d{3})?$", re.IGNORECASE)
    SELECTION_PATTERN = re.compile(r"selection_[A-Za-z0-9_]+")

    def __init__(self, scorer: QualityScorer | None = None) -> None:
        self.scorer = scorer or QualityScorer()

    def validate(self, rule) -> ValidationResult:
        errors: list[str] = []
        warnings: list[str] = []

        missing_metadata = self._validate_metadata(rule, errors)
        invalid_attack_tags = self._validate_attack_tags(rule, warnings)
        invalid_condition = self._validate_detection(rule, errors)
        generic_placeholders = self._detect_generic_placeholders(rule, warnings)
        unknown_logsource = self._validate_logsource(rule, warnings)
        missing_correlation_reasoning = self._validate_correlation(rule, warnings)

        score = self.scorer.calculate(
            missing_metadata=missing_metadata,
            invalid_attack_tags=invalid_attack_tags,
            invalid_condition=invalid_condition,
            generic_placeholders=generic_placeholders,
            unknown_logsource=unknown_logsource,
            missing_correlation_reasoning=missing_correlation_reasoning,
        )
        grade = self.scorer.grade(score)

        return ValidationResult(
            valid=not errors,
            errors=errors,
            warnings=warnings,
            score=score,
            grade=grade,
        )

    def _validate_metadata(self, rule, errors: list[str]) -> bool:
        missing = False
        metadata = getattr(rule, "metadata", None)
        required_fields = ("title", "id", "description", "status", "level")
        if metadata is None:
            errors.append("Missing metadata")
            return True

        for field in required_fields:
            value = getattr(metadata, field, None)
            if value in (None, ""):
                errors.append(f"Missing {field}")
                missing = True

        if not getattr(rule, "logsource", None):
            errors.append("Missing logsource")
            missing = True
        if getattr(rule, "detection", None) is None:
            errors.append("Missing detection")
            missing = True
        return missing

    def _validate_attack_tags(self, rule, warnings: list[str]) -> bool:
        tags = list(getattr(getattr(rule, "metadata", None), "tags", None) or [])
        invalid = False
        for tag in tags:
            if not self.TAG_PATTERN.match(str(tag)):
                warnings.append(f"Invalid ATT&CK tag: {tag}")
                invalid = True
        return invalid

    def _validate_detection(self, rule, errors: list[str]) -> bool:
        detection = getattr(rule, "detection", None)
        if detection is None:
            return True

        selections = getattr(detection, "selections", None) or {}
        condition = getattr(detection, "condition", None)

        if not selections:
            errors.append("Detection selections missing")
            return True

        if not condition:
            errors.append("Detection condition missing")
            return True

        references = set(self.SELECTION_PATTERN.findall(str(condition)))
        if references and not all(reference in selections for reference in references):
            missing = sorted(reference for reference in references if reference not in selections)
            errors.append(f"Condition references missing selections: {', '.join(missing)}")
            return True

        if str(condition).strip() == "1 of selection_*" and not selections:
            errors.append("Condition only without selections")
            return True

        return False

    def _validate_logsource(self, rule, warnings: list[str]) -> bool:
        logsource = getattr(rule, "logsource", None) or {}
        category = logsource.get("category")
        if category and category not in self.ALLOWED_LOGSOURCE_CATEGORIES:
            warnings.append(f"Unknown logsource category: {category}")
            return True
        return False

    def _validate_correlation(self, rule, warnings: list[str]) -> bool:
        if bool(getattr(rule, "x_correlation_logic", False)) and not getattr(rule, "x_correlation_reasoning", None):
            warnings.append("Missing correlation reasoning")
            return True
        return False

    def _detect_generic_placeholders(self, rule, warnings: list[str]) -> bool:
        text_fragments: list[str] = []
        detection = getattr(rule, "detection", None)
        if detection is not None:
            text_fragments.append(str(getattr(detection, "condition", "")))
            selections = getattr(detection, "selections", None) or {}
            for fields in selections.values():
                for values in fields.values():
                    text_fragments.extend(str(value) for value in values)

        text = "\n".join(text_fragments)
        if "${IOC}" in text or "${PAYLOAD}" in text:
            warnings.append("Generic placeholder detection still present.")
            return True
        return False