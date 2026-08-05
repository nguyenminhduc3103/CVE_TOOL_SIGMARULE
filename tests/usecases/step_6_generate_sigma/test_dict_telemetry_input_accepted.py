"""Telemetry input may be TelemetryPlan OR dict.

Downstream `triage_controller.py` and the integration test pass
`telemetry=telemetry_dict` (the result of `TelemetryAssessment.model_dump()`
or pipeline dict serialization), NOT a TelemetryPlan instance. The
`.plan()` method must accept both forms without breaking.
"""
from __future__ import annotations

import json

import pytest

from src.usecases.step_6_generate_sigma.services.sigma_rule_ai import SigmaRuleAI

from tests.usecases.step_6_generate_sigma.conftest import run_async


def _log4shell_plan_dict() -> dict:
    """Same Log4Shell fixture as `conftest.py`, but as a dict (the form the CLI passes)."""
    return {
        "cve_id": "CVE-2021-44228",
        "target_environment": {"platforms": ["windows", "linux"]},
        "detection_axis": {"primary": "initial_access", "secondary": ["post_exploitation"]},
        "detection_strategy": "Watch JNDI lookup strings + outbound LDAP/RMI from Java.",
        "correlation_required": True,
        "candidate_features": {"stable": [], "conditional": [], "optional": []},
        "sigma_logsources": [
            {"category": "webserver", "product": None,
             "allowed_fields": {"cs-uri-query": ["contains"]}},
            {"category": "process_creation", "product": "windows",
             "allowed_fields": {"CommandLine": ["contains", "endswith"], "Image": ["endswith"]}},
            {"category": "network_connection", "product": "windows",
             "allowed_fields": {"DestinationPort": ["equals"]}},
        ],
        "telemetry_gaps": [],
        "gap_severity": "medium",
        "telemetry_confidence": 0.95,
        "ai_model": "test",
    }


async def _dict_telemetry_input_accepted(log4shell_core, stub_client):
    stub_client.next_response = json.dumps({
        "detections": [
            {
                "id": "rule_1",
                "rule": {
                    "description": "JNDI lookup",
                    "logsource": {"category": "webserver", "product": None},
                    "detection": {"selection": [
                        {"name": "cs-uri-query", "modifier": "contains", "value": "${jndi:",
                         "reason": "JNDI lookup substring is the unique signature of Log4Shell initial-access payload."}
                    ], "condition": "selection"},
                    "falsepositives": [],
                    "level": "high",
                },
            }
        ],
        "correlations": [],
        "reasoning": "dict input works",
    })

    service = SigmaRuleAI(ai_client=stub_client)
    result = await service.plan(
        cve=log4shell_core,
        behavior=None,
        telemetry=_log4shell_plan_dict(),
    )

    assert result.cve_id == "CVE-2021-44228"
    assert len(result.detections) == 1
    assert result.detections[0].rule.detection.selection[0].value == "${jndi:"


def test_dict_telemetry_input_accepted(log4shell_core, stub_client):
    run_async(_dict_telemetry_input_accepted(log4shell_core, stub_client))


def test_dict_telemetry_produces_same_validator_behavior_as_instance(log4shell_core):
    """Validator against a dict-derived plan yields identical pass/fail as against a TelemetryPlan instance."""
    from src.usecases.step_6_generate_sigma.models.detection import (
        Detection,
        DetectionBody,
        DetectionRule,
        LogsourceRef,
        SelectedField,
    )
    from src.usecases.step_6_generate_sigma.models.result import Step6Result
    from src.usecases.step_6_generate_sigma.validators import (
        Step6ValidationError,
        Step6Validator,
    )
    from src.usecases.step_4_telemetry.models.telemetry_plan import TelemetryPlan

    plan_dict = _log4shell_plan_dict()
    plan_instance = TelemetryPlan.model_validate(plan_dict)

    valid_detection_result = Step6Result(
        cve_id="CVE-2021-44228",
        detections=[],
        correlations=[],
        reasoning="empty",
    )

    # Both forms accept the same empty result.
    Step6Validator(plan_dict).validate(valid_detection_result)
    Step6Validator(plan_instance).validate(valid_detection_result)

    # Both forms reject the same invented-category result.
    invalid = Step6Result(
        cve_id="CVE-2021-44228",
        detections=[Detection(
            id="rule_1",
            rule=DetectionRule(
                description="bad",
                logsource=LogsourceRef(category="ghost_category", product=None),
                detection=DetectionBody(selection=[
                    SelectedField(name="ghost", modifier="contains", value="x")
                ]),
                level="high",
            ),
        )],
        correlations=[],
        reasoning="invalid",
    )

    with pytest.raises(Step6ValidationError, match="not in Step 4 search space"):
        Step6Validator(plan_dict).validate(invalid)
    with pytest.raises(Step6ValidationError, match="not in Step 4 search space"):
        Step6Validator(plan_instance).validate(invalid)


async def _invalid_dict_raises_validation_error(log4shell_core, stub_client):
    """A dict missing required TelemetryPlan fields raises a Pydantic validation error."""
    from pydantic import ValidationError

    service = SigmaRuleAI(ai_client=stub_client)
    with pytest.raises(ValidationError):
        await service.plan(
            cve=log4shell_core,
            behavior=None,
            telemetry={"cve_id": "CVE-T"},  # missing target_environment, detection_axis, etc.
        )


def test_invalid_dict_raises_validation_error(log4shell_core, stub_client):
    run_async(_invalid_dict_raises_validation_error(log4shell_core, stub_client))
