"""Empty-selection path: AI returns no detections, but with non-empty reasoning.

Architect v9: when no candidate logsource in Step 4 matches the CVE behavior,
the AI emits `detections: [], correlations: [], reasoning: "<non-empty>"`.
This is NOT an error — it's a legitimate "no telemetry coverage" signal.
"""
from __future__ import annotations

import json

from src.usecases.step_6_generate_sigma.models.result import Step6Result
from src.usecases.step_6_generate_sigma.services.sigma_rule_ai import SigmaRuleAI
from src.usecases.step_6_generate_sigma.validators import Step6Validator

from tests.usecases.step_6_generate_sigma.conftest import run_async


EMPTY_RESPONSE = {
    "detections": [],
    "correlations": [],
    "reasoning": "CVE is local privilege escalation; no network, process, or webserver telemetry in Step 4 search space matches the described behavior.",
}


async def _empty_plan_with_zero_logsources(empty_telemetry_plan, log4shell_core, stub_client):
    """TelemetryPlan with `sigma_logsources=[]` — AI returns empty plan."""
    stub_client.next_response = json.dumps(EMPTY_RESPONSE)

    service = SigmaRuleAI(ai_client=stub_client)
    result = await service.plan(
        cve=log4shell_core,
        behavior=None,
        telemetry=empty_telemetry_plan,
    )

    assert isinstance(result, Step6Result)
    assert result.detections == []
    assert result.correlations == []
    assert result.reasoning == EMPTY_RESPONSE["reasoning"]


async def _empty_plan_validator_does_not_raise(empty_telemetry_plan, log4shell_core, stub_client):
    """Empty detections → no ID/format/search-space checks; validator returns silently."""
    stub_client.next_response = json.dumps(EMPTY_RESPONSE)

    service = SigmaRuleAI(ai_client=stub_client)
    result = await service.plan(
        cve=log4shell_core,
        behavior=None,
        telemetry=empty_telemetry_plan,
    )

    # Calling validator directly should also not raise.
    Step6Validator(empty_telemetry_plan).validate(result)


def test_empty_plan_with_zero_logsources(empty_telemetry_plan, log4shell_core, stub_client):
    run_async(_empty_plan_with_zero_logsources(empty_telemetry_plan, log4shell_core, stub_client))


def test_empty_plan_validator_does_not_raise(empty_telemetry_plan, log4shell_core, stub_client):
    run_async(_empty_plan_validator_does_not_raise(empty_telemetry_plan, log4shell_core, stub_client))


def test_empty_step6_result_pydantic_accepts():
    """Even an in-memory Step6Result with empty detections passes Pydantic structural validation."""
    result = Step6Result(
        cve_id="CVE-TEST",
        detections=[],
        correlations=[],
        reasoning="legitimate empty plan",
    )
    assert Step6Result.model_validate(result.model_dump()) == result
