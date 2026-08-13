from __future__ import annotations

import asyncio

import pytest

from config.settings import Settings
from src.infrastructure.ai.core import AIServiceError
from src.usecases.step_2_analysis.services.phase2b_service import AIPhase2BService
from conftest import extract_prompt_json


def test_phase2b_adds_default_fields_and_filters_invalid_chain(fake_ai_client, monkeypatch, cve_core, technical_analysis, attack_mapping):
    monkeypatch.setattr(Settings, "get_phase2_api_keys", lambda self: ["k"])
    monkeypatch.setattr(Settings, "get_phase2_base_url", lambda self: "https://example.test")
    monkeypatch.setattr(Settings, "get_phase2_model", lambda self: "phase2b-model")

    response = '{"attack_chain":[{"step":1,"tactic_id":"TA0001","technique_id":"T1190","description":"Exploit","reasoning":"Initial access"},{"step":2,"tactic_id":"TA0001","technique_id":"T9999","description":"Invalid","reasoning":"Should be filtered"}]}'
    service = AIPhase2BService(fake_ai_client(response=response))

    result = asyncio.run(
        service.reason_chain(
            step1_output={"description": cve_core.description, "poc_description": "PoC", "poc_request_info": {"path": "/vuln"}},
            phase1_output=technical_analysis.model_dump(),
            phase2a_output=attack_mapping.model_dump(),
            cve_id=cve_core.cve_id,
        )
    )

    assert result["is_attack_chain"] is True
    assert result["confidence"] == "low"
    assert result["attack_chain"] == [
        {"step": 1, "tactic_id": "TA0001", "technique_id": "T1190", "description": "Exploit", "reasoning": "Initial access"}
    ]
    assert result["mapping_reasons"] == ["T1190 selected - Initial access", "T9999 selected - Should be filtered"]
    payload = extract_prompt_json(service.client.call_llm.await_args.kwargs["user_prompt"])
    assert payload["cve_id"] == cve_core.cve_id
    assert payload["poc_evidence"] == "/vuln"
    assert payload["tactics"] == attack_mapping.tactics


@pytest.mark.parametrize("response_text", ["", None])
def test_phase2b_rejects_empty_response(fake_ai_client, monkeypatch, cve_core, technical_analysis, attack_mapping, response_text):
    monkeypatch.setattr(Settings, "get_phase2_api_keys", lambda self: ["k"])
    monkeypatch.setattr(Settings, "get_phase2_base_url", lambda self: "https://example.test")
    monkeypatch.setattr(Settings, "get_phase2_model", lambda self: "phase2b-model")

    service = AIPhase2BService(fake_ai_client(response=response_text))

    with pytest.raises(AIServiceError):
        asyncio.run(
            service.reason_chain(
                step1_output={"description": cve_core.description},
                phase1_output=technical_analysis.model_dump(),
                phase2a_output=attack_mapping.model_dump(),
                cve_id=cve_core.cve_id,
            )
        )


def test_phase2b_wraps_ai_exception(fake_ai_client, monkeypatch, cve_core, technical_analysis, attack_mapping):
    monkeypatch.setattr(Settings, "get_phase2_api_keys", lambda self: ["k"])
    monkeypatch.setattr(Settings, "get_phase2_base_url", lambda self: "https://example.test")
    monkeypatch.setattr(Settings, "get_phase2_model", lambda self: "phase2b-model")

    service = AIPhase2BService(fake_ai_client(side_effect=RuntimeError("boom")))

    with pytest.raises(AIServiceError):
        asyncio.run(
            service.reason_chain(
                step1_output={"description": cve_core.description},
                phase1_output=technical_analysis.model_dump(),
                phase2a_output=attack_mapping.model_dump(),
                cve_id=cve_core.cve_id,
            )
        )