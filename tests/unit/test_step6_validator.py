from __future__ import annotations

import pytest

from src.usecases.step_6_generate_sigma.validators.step6_validator import (
    Step6ValidationError,
    Step6Validator,
)


def test_step6_validator_accepts_valid_result(telemetry_plan, step6_result):
    Step6Validator(telemetry_plan).validate(step6_result)


def test_step6_validator_rejects_duplicate_detection_ids(telemetry_plan, step6_result, step6_detection_one):
    result = step6_result.model_copy(update={"detections": [step6_detection_one, step6_detection_one]})

    with pytest.raises(Step6ValidationError):
        Step6Validator(telemetry_plan).validate(result)


def test_step6_validator_rejects_bad_detection_id_format(telemetry_plan, step6_detection_two, step6_detection_one):
    bad_detection = step6_detection_one.model_copy(update={"id": "rule_01"})
    result = step6_detection_two.model_copy(update={})
    from src.usecases.step_6_generate_sigma.models.result import Step6Result

    step6_result = Step6Result(
        cve_id="CVE-2024-0001",
        ai_model="sigma-model",
        detections=[bad_detection],
        correlations=[],
        reasoning="x",
    )

    with pytest.raises(Step6ValidationError):
        Step6Validator(telemetry_plan).validate(step6_result)


def test_step6_validator_rejects_unknown_logsource(telemetry_plan, step6_detection_one):
    unknown = step6_detection_one.model_copy(update={"rule": step6_detection_one.rule.model_copy(update={"logsource": step6_detection_one.rule.logsource.model_copy(update={"category": "unknown"})})})
    from src.usecases.step_6_generate_sigma.models.result import Step6Result

    result = Step6Result(cve_id="CVE-2024-0001", ai_model="sigma-model", detections=[unknown], correlations=[], reasoning="x")

    with pytest.raises(Step6ValidationError):
        Step6Validator(telemetry_plan).validate(result)


def test_step6_validator_rejects_invalid_correlation_refs(telemetry_plan, step6_detection_one, step6_correlation):
    from src.usecases.step_6_generate_sigma.models.result import Step6Result

    bad_correlation = step6_correlation.model_copy(update={"rule": step6_correlation.rule.model_copy(update={"correlation": step6_correlation.rule.correlation.model_copy(update={"rules": ["rule_1", "rule_999"]})})})
    result = Step6Result(cve_id="CVE-2024-0001", ai_model="sigma-model", detections=[step6_detection_one], correlations=[bad_correlation], reasoning="x")

    with pytest.raises(Step6ValidationError):
        Step6Validator(telemetry_plan).validate(result)