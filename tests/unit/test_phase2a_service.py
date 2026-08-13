from __future__ import annotations

import asyncio

import pytest

from config.settings import Settings
from src.infrastructure.ai.core import AIServiceError
from src.usecases.step_2_analysis.services.phase2a_service import AIBehaviorService
from conftest import extract_prompt_json


def test_phase2a_builds_payload_from_phase1_and_parses_valid_json(fake_ai_client, monkeypatch, cve_core, technical_analysis):
    monkeypatch.setattr(Settings, "get_phase2_api_keys", lambda self: ["k"])
    monkeypatch.setattr(Settings, "get_phase2_base_url", lambda self: "https://example.test")
    monkeypatch.setattr(Settings, "get_phase2_model", lambda self: "phase2-model")

    response = '{"tactics":["TA0001"],"techniques":["T1190"],"subtechniques":["T1190.001"]}'
    service = AIBehaviorService(fake_ai_client(response=response))

    result = asyncio.run(
        service.fetch_attack_mapping(
            cve_id=cve_core.cve_id,
            description=cve_core.description or "",
            phase1_output={**technical_analysis.model_dump(), "poc_request_info": {"path": "/vuln"}},
        )
    )

    assert result == {"tactics": ["TA0001"], "techniques": ["T1190"], "subtechniques": ["T1190.001"]}
    call = service.client.call_llm.await_args.kwargs
    assert call["model"] == "phase2-model"
    payload = extract_prompt_json(call["user_prompt"])
    assert payload["exec_surface"] == technical_analysis.execution_surface
    assert payload["delivery_vector"] == technical_analysis.delivery_vector
    assert payload["poc_evidence"] == "/vuln"


@pytest.mark.parametrize("response_text", ["", None])
def test_phase2a_rejects_empty_response(fake_ai_client, monkeypatch, cve_core, technical_analysis, response_text):
    monkeypatch.setattr(Settings, "get_phase2_api_keys", lambda self: ["k"])
    monkeypatch.setattr(Settings, "get_phase2_base_url", lambda self: "https://example.test")
    monkeypatch.setattr(Settings, "get_phase2_model", lambda self: "phase2-model")

    service = AIBehaviorService(fake_ai_client(response=response_text))

    with pytest.raises(Exception):
        asyncio.run(service.fetch_attack_mapping(cve_core.cve_id, cve_core.description or "", technical_analysis.model_dump()))


def test_phase2a_rejects_schema_validation_error(fake_ai_client, monkeypatch, cve_core, technical_analysis):
    monkeypatch.setattr(Settings, "get_phase2_api_keys", lambda self: ["k"])
    monkeypatch.setattr(Settings, "get_phase2_base_url", lambda self: "https://example.test")
    monkeypatch.setattr(Settings, "get_phase2_model", lambda self: "phase2-model")

    response = '{"tactics":123,"techniques":[],"subtechniques":[]}'
    service = AIBehaviorService(fake_ai_client(response=response))

    with pytest.raises(AIServiceError):
        asyncio.run(service.fetch_attack_mapping(cve_core.cve_id, cve_core.description or "", technical_analysis.model_dump()))


def test_phase2a_wraps_ai_exception(fake_ai_client, monkeypatch, cve_core, technical_analysis):
    monkeypatch.setattr(Settings, "get_phase2_api_keys", lambda self: ["k"])
    monkeypatch.setattr(Settings, "get_phase2_base_url", lambda self: "https://example.test")
    monkeypatch.setattr(Settings, "get_phase2_model", lambda self: "phase2-model")

    service = AIBehaviorService(fake_ai_client(side_effect=RuntimeError("boom")))

    with pytest.raises(AIServiceError):
        asyncio.run(service.fetch_attack_mapping(cve_core.cve_id, cve_core.description or "", technical_analysis.model_dump()))