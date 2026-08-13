from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError

from config.settings import Settings
from src.infrastructure.ai.core import AIServiceError
from src.usecases.step_6_generate_sigma.services.sigma_rule_ai import SigmaRuleAI
from conftest import extract_prompt_json


def test_sigma_rule_ai_builds_payload_and_parses_valid_response(fake_ai_client, monkeypatch, cve_core, technical_analysis, attack_mapping, telemetry_plan, poc_summary):
    monkeypatch.setattr(Settings, "get_step6_model", lambda self: "sigma-model")
    monkeypatch.setattr(
        "src.usecases.step_6_generate_sigma.services.sigma_rule_ai.Step6Validator.validate",
        lambda self, result: None,
    )

    response = (
        '{"detections":[{"id":"rule_1","rule":{"description":"Detect exploit","logsource":{"category":"process_creation","product":"windows"},"detection":{"selection":[{"name":"CommandLine","modifier":"contains","value":"jndi:"}],"condition":"selection"},"falsepositives":[],"level":"high"}}],'
        '"correlations":[],"reasoning":"One detection is enough"}'
    )
    service = SigmaRuleAI(fake_ai_client(response=response))

    result = asyncio.run(
        service.plan(
            cve=cve_core,
            behavior=technical_analysis,
            telemetry=telemetry_plan,
            attack=attack_mapping,
            poc=poc_summary,
        )
    )

    assert result.cve_id == cve_core.cve_id
    assert result.ai_model == "sigma-model"
    assert len(result.detections) == 1
    call = service.client.call_llm.await_args.kwargs
    assert call["response_format_json"] is True
    payload = extract_prompt_json(call["user_prompt"])
    assert payload["context"]["cve_id"] == cve_core.cve_id
    assert payload["behavior"]["attack_chain"] == attack_mapping.attack_chain
    assert payload["search_space"]["candidate_logsources"][0]["category"] == "process_creation"


@pytest.mark.parametrize("response_text", ["", None])
def test_sigma_rule_ai_rejects_empty_response(fake_ai_client, monkeypatch, cve_core, technical_analysis, attack_mapping, telemetry_plan, response_text):
    monkeypatch.setattr(Settings, "get_step6_model", lambda self: "sigma-model")
    monkeypatch.setattr(
        "src.usecases.step_6_generate_sigma.services.sigma_rule_ai.Step6Validator.validate",
        lambda self, result: None,
    )

    service = SigmaRuleAI(fake_ai_client(response=response_text))

    with pytest.raises(Exception):
        asyncio.run(service.plan(cve_core, technical_analysis, telemetry_plan, attack_mapping))


def test_sigma_rule_ai_rejects_invalid_schema(fake_ai_client, monkeypatch, cve_core, technical_analysis, attack_mapping, telemetry_plan):
    monkeypatch.setattr(Settings, "get_step6_model", lambda self: "sigma-model")
    monkeypatch.setattr(
        "src.usecases.step_6_generate_sigma.services.sigma_rule_ai.Step6Validator.validate",
        lambda self, result: None,
    )

    response = '{"detections":[{"id":"rule_1","rule":{"description":"Detect exploit","logsource":{"category":"process_creation","product":"windows"},"detection":{"selection":[],"condition":"selection"},"falsepositives":[],"level":"high"}}],"correlations":[],"reasoning":"x"}'
    service = SigmaRuleAI(fake_ai_client(response=response))

    with pytest.raises(ValidationError):
        asyncio.run(service.plan(cve_core, technical_analysis, telemetry_plan, attack_mapping))


def test_sigma_rule_ai_wraps_ai_exception(fake_ai_client, monkeypatch, cve_core, technical_analysis, attack_mapping, telemetry_plan):
    monkeypatch.setattr(Settings, "get_step6_model", lambda self: "sigma-model")

    service = SigmaRuleAI(fake_ai_client(side_effect=RuntimeError("boom")))

    with pytest.raises(RuntimeError):
        asyncio.run(service.plan(cve_core, technical_analysis, telemetry_plan, attack_mapping))