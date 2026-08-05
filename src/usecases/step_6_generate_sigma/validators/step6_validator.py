# Step 6 business validator — TÁCH KHỎI Pydantic model (per architect v9).
# Why separate? Validator needs TelemetryPlan context; injecting it into model_validate would tie model to Step 4 vocabulary.
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from src.usecases.step_6_generate_sigma.models.correlation import Correlation
from src.usecases.step_6_generate_sigma.models.detection import Detection
from src.usecases.step_6_generate_sigma.models.result import Step6Result

if TYPE_CHECKING:
    from src.usecases.step_4_telemetry.models.telemetry_plan import TelemetryPlan


class Step6ValidationError(ValueError):
    # Raised when Step 6 AI output violates Step 4 search space or step-6 contract.
    pass


# Deterministic positional ID pattern: rule_1, rule_2, ..., rule_10, ... (no leading zero).
_ID_PATTERN = re.compile(r"^rule_[1-9][0-9]*$")


class Step6Validator:
    # Business-rule validator for a Step6Result, gated on the Step 4 TelemetryPlan.
    # Usage: validator = Step6Validator(telemetry_plan); validator.validate(result) -> raises on violation.
    def __init__(self, telemetry_plan: "TelemetryPlan | dict") -> None:
        # Resolve dict -> TelemetryPlan up-front so runtime check is uniform.
        if isinstance(telemetry_plan, dict):
            from src.usecases.step_4_telemetry.models.telemetry_plan import TelemetryPlan
            telemetry_plan = TelemetryPlan.model_validate(telemetry_plan)
        # Build a (category, product) -> allowed_fields lookup once (SigmaLogsource is frozen).
        self._space: dict[tuple[str, str | None], dict[str, list[str]]] = {
            (ls.category, ls.product): ls.allowed_fields
            for ls in telemetry_plan.sigma_logsources
        }

    def validate(self, result: Step6Result) -> None:
        # Run all business checks. Hard-reject on any violation.
        self._validate_detection_id_format(result.detections)
        self._validate_detection_id_uniqueness(result.detections)
        self._validate_per_logsource_uniqueness(result.detections)
        self._validate_against_search_space(result.detections)
        self._validate_correlation_ids(result.detections, result.correlations)

    @staticmethod
    def _validate_detection_id_format(detections: list[Detection]) -> None:
        # Every detection.id must match ^rule_[1-9][0-9]*$ (deterministic positional).
        for i, det in enumerate(detections):
            if not _ID_PATTERN.match(det.id):
                raise Step6ValidationError(
                    f"detections[{i}].id {det.id!r} does not match required pattern "
                    f"^rule_[1-9][0-9]*$; Step 6 contract requires deterministic positional "
                    "IDs (rule_1, rule_2, ...)"
                )

    @staticmethod
    def _validate_detection_id_uniqueness(detections: list[Detection]) -> None:
        # Every detection.id must be unique (correlation refs depend on this).
        seen: set[str] = set()
        for i, det in enumerate(detections):
            if det.id in seen:
                raise Step6ValidationError(
                    f"detections[{i}].id {det.id!r} duplicates an earlier detection; "
                    "Step 6 contract requires unique detection.id"
                )
            seen.add(det.id)

    @staticmethod
    def _validate_per_logsource_uniqueness(detections: list[Detection]) -> None:
        # One detection per chosen logsource (category, product).
        seen: set[tuple[str, str | None]] = set()
        for i, det in enumerate(detections):
            key = (det.rule.logsource.category, det.rule.logsource.product)
            if key in seen:
                raise Step6ValidationError(
                    f"detections[{i}].rule.logsource {key} duplicates an earlier detection; "
                    "Step 6 contract is one detection per chosen logsource"
                )
            seen.add(key)

    def _validate_against_search_space(self, detections: list[Detection]) -> None:
        # Every (category, product, field, modifier) must be backed by Step 4.
        # `value` is NOT checked here — it's AI's semantic knowledge.
        errors: list[str] = []
        for det_idx, det in enumerate(detections):
            ls_key = (det.rule.logsource.category, det.rule.logsource.product)
            if ls_key not in self._space:
                errors.append(
                    f"detections[{det_idx}].rule.logsource {ls_key} not in Step 4 search space"
                )
                continue
            allowed_fields = self._space[ls_key]
            for sel_idx, sel in enumerate(det.rule.detection.selection):
                if sel.name not in allowed_fields:
                    errors.append(
                        f"detections[{det_idx}].rule.detection.selection[{sel_idx}].name "
                        f"{sel.name!r} not in allowed_fields for {ls_key}: "
                        f"{sorted(allowed_fields)}"
                    )
                    continue
                allowed_modifiers = allowed_fields[sel.name]
                if sel.modifier is None:
                    # allowed_fields[field] = [] in Step 4 = "không cần modifier"
                    if allowed_modifiers:  # non-empty list -> modifier required
                        errors.append(
                            f"detections[{det_idx}].rule.detection.selection[{sel_idx}] "
                            f"{sel.name!r} requires a modifier (allowed_fields[{sel.name!r}] is non-empty)"
                        )
                else:
                    if sel.modifier not in allowed_modifiers:
                        errors.append(
                            f"detections[{det_idx}].rule.detection.selection[{sel_idx}] "
                            f"modifier {sel.modifier!r} not in allowed_fields[{sel.name!r}]: "
                            f"{allowed_modifiers}"
                        )
        if errors:
            raise Step6ValidationError(
                "Step 6 output violates Step 4 search space: " + "; ".join(errors)
            )

    @staticmethod
    def _validate_correlation_ids(
        detections: list[Detection],
        correlations: list[Correlation],
    ) -> None:
        # Every correlation.ref must resolve to a real detection.id (>= 2 refs).
        if not correlations:
            return
        if len(detections) < 2:
            raise Step6ValidationError(
                f"correlations require >= 2 detections (have {len(detections)})"
            )
        detection_ids = {det.id for det in detections}
        for corr_idx, corr in enumerate(correlations):
            refs = corr.rule.correlation.rules
            if len(refs) < 2:
                raise Step6ValidationError(
                    f"correlations[{corr_idx}].rule.correlation.rules requires >= 2 detection.id refs"
                )
            for ref in refs:
                if ref not in detection_ids:
                    raise Step6ValidationError(
                        f"correlations[{corr_idx}].rule.correlation.rules: "
                        f"id {ref!r} does not match any detections[].id {sorted(detection_ids)}"
                    )


__all__ = ["Step6Validator", "Step6ValidationError"]
