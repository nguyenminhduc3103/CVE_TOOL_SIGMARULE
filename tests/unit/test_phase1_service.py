from __future__ import annotations

import asyncio
import json

import pytest

from config.settings import Settings
from src.infrastructure.ai.core import AIServiceError
from src.usecases.step_2_analysis.services.phase1_service import AIPhase1Service
from conftest import extract_prompt_json


def test_phase1_builds_payload_and_parses_valid_fenced_json(fake_ai_client, monkeypatch, cve_core):
    monkeypatch.setattr(Settings, "get_phase1_api_keys", lambda self: ["phase1-key"])
    monkeypatch.setattr(Settings, "get_api_keys", lambda self: ["main-key"])
    monkeypatch.setattr(Settings, "get_phase1_base_url", lambda self: None)
    monkeypatch.setattr(Settings, "get_phase1_model", lambda self: "phase1-model")

    client = fake_ai_client(
        response='```json\n{"execution_surface":"client_side","delivery_vector":"email_attachment","mandatory_behaviors":["process_creation"],"evasive_indicators":[],"exploit_requirements":["open file"],"reasoning":["user opens file"],"confidence":0.8}\n```'
    )
    service = AIPhase1Service(client)

    result = asyncio.run(
        service.fetch_behavior(
            cve_id=cve_core.cve_id,
            description=cve_core.description or "",
            cvss_score=cve_core.cvss_score or 0.0,
            cvss_vector=cve_core.cvss_vector or "",
            cwe_ids=cve_core.cwe_ids or [],
            poc_description="PoC summary",
            poc_request_info={"method": "POST", "path": "/vuln"},
        )
    )

    assert result["execution_surface"] == "client_side"
    assert result["delivery_vector"] == "email_attachment"
    assert result["mandatory_behaviors"] == ["process_creation"]
    assert client.call_llm.await_count == 1
    call = client.call_llm.await_args.kwargs
    payload = extract_prompt_json(call["user_prompt"])
    assert payload["cve_id"] == cve_core.cve_id
    assert payload["poc_description"] == "PoC summary"
    assert payload["poc_request_info"] == {"method": "POST", "path": "/vuln"}
    assert call["override_api_key"] == "phase1-key"


@pytest.mark.parametrize(
    "response_text",
    [
        '  {"execution_surface":"server_side","delivery_vector":"network_protocol","mandatory_behaviors":[],"evasive_indicators":[],"exploit_requirements":[],"reasoning":[],"confidence":0.5}  ',
        'prefix text {"execution_surface":"server_side","delivery_vector":"network_protocol","mandatory_behaviors":[],"evasive_indicators":[],"exploit_requirements":[],"reasoning":[],"confidence":0.5} suffix text',
    ],
)
def test_phase1_cleans_supported_json_variants(fake_ai_client, monkeypatch, response_text, cve_core):
    monkeypatch.setattr(Settings, "get_phase1_api_keys", lambda self: ["k"])
    monkeypatch.setattr(Settings, "get_api_keys", lambda self: ["k"])
    monkeypatch.setattr(Settings, "get_phase1_base_url", lambda self: None)
    monkeypatch.setattr(Settings, "get_phase1_model", lambda self: "phase1-model")

    service = AIPhase1Service(fake_ai_client(response=response_text))
    result = asyncio.run(
        service.fetch_behavior(cve_core.cve_id, cve_core.description or "", 9.8, cve_core.cvss_vector or "", cve_core.cwe_ids or [])
    )

    assert result["execution_surface"] == "server_side"


@pytest.mark.parametrize(
    "response_text",
    ["", None],
)
def test_phase1_rejects_empty_or_none_response(fake_ai_client, monkeypatch, response_text, cve_core):
    monkeypatch.setattr(Settings, "get_phase1_api_keys", lambda self: ["k"])
    monkeypatch.setattr(Settings, "get_api_keys", lambda self: ["k"])
    monkeypatch.setattr(Settings, "get_phase1_base_url", lambda self: None)
    monkeypatch.setattr(Settings, "get_phase1_model", lambda self: "phase1-model")

    service = AIPhase1Service(fake_ai_client(response=response_text))

    with pytest.raises(AIServiceError):
        asyncio.run(service.fetch_behavior(cve_core.cve_id, cve_core.description or "", 9.8, cve_core.cvss_vector or "", cve_core.cwe_ids or []))


def test_phase1_rejects_invalid_schema(fake_ai_client, monkeypatch, cve_core):
    monkeypatch.setattr(Settings, "get_phase1_api_keys", lambda self: ["k"])
    monkeypatch.setattr(Settings, "get_api_keys", lambda self: ["k"])
    monkeypatch.setattr(Settings, "get_phase1_base_url", lambda self: None)
    monkeypatch.setattr(Settings, "get_phase1_model", lambda self: "phase1-model")

    bad_response = '{"execution_surface":"client_side","delivery_vector":"email_attachment","mandatory_behaviors":[],"evasive_indicators":[],"exploit_requirements":[],"reasoning":[],"confidence":1.5}'
    service = AIPhase1Service(fake_ai_client(response=bad_response))

    with pytest.raises(AIServiceError):
        asyncio.run(service.fetch_behavior(cve_core.cve_id, cve_core.description or "", 9.8, cve_core.cvss_vector or "", cve_core.cwe_ids or []))


def test_phase1_wraps_ai_exception(fake_ai_client, monkeypatch, cve_core):
    monkeypatch.setattr(Settings, "get_phase1_api_keys", lambda self: ["k"])
    monkeypatch.setattr(Settings, "get_api_keys", lambda self: ["k"])
    monkeypatch.setattr(Settings, "get_phase1_base_url", lambda self: None)
    monkeypatch.setattr(Settings, "get_phase1_model", lambda self: "phase1-model")

    service = AIPhase1Service(fake_ai_client(side_effect=RuntimeError("boom")))

    with pytest.raises(AIServiceError):
        asyncio.run(service.fetch_behavior(cve_core.cve_id, cve_core.description or "", 9.8, cve_core.cvss_vector or "", cve_core.cwe_ids or []))