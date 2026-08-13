from __future__ import annotations

import asyncio

import pytest

from config.settings import Settings
from src.usecases.step_4_telemetry.models.telemetry_plan import TelemetryPlan
from src.usecases.step_4_telemetry.services.ai_telemetry_service import TelemetryPlanAI
from conftest import extract_prompt_json


def test_telemetry_plan_ai_builds_input_and_resolves_logsources(fake_ai_client, monkeypatch, cve_core, telemetry_plan, enriched_context):
    monkeypatch.setattr(Settings, "get_step4_model", lambda self: "step4-model")
    monkeypatch.setattr("src.usecases.step_4_telemetry.services.ai_telemetry_service.load_telemetry_concepts", lambda: {"TELEMETRY": ["process_creation", "network_connection", "file_change"]})
    monkeypatch.setattr("src.usecases.step_4_telemetry.services.ai_telemetry_service.load_statistics", lambda: None)

    # resolver is tested independently; here we stub it to keep the service unit-focused.
    monkeypatch.setattr(
        "src.usecases.step_4_telemetry.services.ai_telemetry_service.extract_categories",
        lambda candidate_features: [feature.telemetry_concept for feature in candidate_features.stable],
    )
    monkeypatch.setattr(
        "src.usecases.step_4_telemetry.services.ai_telemetry_service.resolve",
        lambda knowledge, target_env, categories: telemetry_plan.sigma_logsources,
    )

    response = (
        '{"target_environment":{"platforms":["windows"],"deployment":["endpoint"],"application_types":["web_application"],"technologies":["Apache"],"special_environments":[]},'
        '"detection_axis":{"primary":"initial_access","secondary":["post_exploitation"]},'
        '"detection_strategy":"Detect malicious process creation and callback",'
        '"correlation_required":true,'
        '"candidate_features":{"stable":[{"semantic":"Suspicious process creation","telemetry_concept":"process_creation","evidence":["spawned child process"]}],"conditional":[],"optional":[]},'
        '"telemetry_gaps":[],"gap_severity":"medium","telemetry_confidence":0.8}'
    )
    service = TelemetryPlanAI(fake_ai_client(response=response))

    result = asyncio.run(service.plan(enriched_context))

    assert isinstance(result, TelemetryPlan)
    assert result.cve_id == cve_core.cve_id
    assert result.ai_model == "step4-model"
    assert result.sigma_logsources == telemetry_plan.sigma_logsources
    call = service.client.call_llm.await_args.kwargs
    assert call["response_format_json"] is True
    payload = extract_prompt_json(call["user_prompt"])
    assert payload["context"]["cve_id"] == cve_core.cve_id
    assert payload["target"]["applications"] == ["Apache"]
    assert payload["telemetry_concepts_kb"]["TELEMETRY"] == ["process_creation", "network_connection", "file_change"]


@pytest.mark.parametrize("response_text", ["", None])
def test_telemetry_plan_ai_rejects_empty_response(fake_ai_client, monkeypatch, enriched_context, response_text):
    monkeypatch.setattr(Settings, "get_step4_model", lambda self: "step4-model")
    monkeypatch.setattr("src.usecases.step_4_telemetry.services.ai_telemetry_service.load_telemetry_concepts", lambda: {"TELEMETRY": ["process_creation"]})
    monkeypatch.setattr("src.usecases.step_4_telemetry.services.ai_telemetry_service.load_statistics", lambda: None)
    monkeypatch.setattr("src.usecases.step_4_telemetry.services.ai_telemetry_service.resolve", lambda knowledge, target_env, categories: [])

    service = TelemetryPlanAI(fake_ai_client(response=response_text))

    with pytest.raises(Exception):
        asyncio.run(service.plan(enriched_context))


def test_telemetry_plan_ai_rejects_schema_validation(fake_ai_client, monkeypatch, enriched_context):
    monkeypatch.setattr(Settings, "get_step4_model", lambda self: "step4-model")
    monkeypatch.setattr("src.usecases.step_4_telemetry.services.ai_telemetry_service.load_telemetry_concepts", lambda: {"TELEMETRY": ["process_creation"]})
    monkeypatch.setattr("src.usecases.step_4_telemetry.services.ai_telemetry_service.load_statistics", lambda: None)
    monkeypatch.setattr("src.usecases.step_4_telemetry.services.ai_telemetry_service.resolve", lambda knowledge, target_env, categories: [])

    bad_response = (
        '{"target_environment":{"platforms":["windows"],"deployment":[],"application_types":[],"technologies":[],"special_environments":[]},'
        '"detection_axis":{"primary":"initial_access","secondary":["initial_access"]},'
        '"detection_strategy":"x","correlation_required":true,'
        '"candidate_features":{"stable":[],"conditional":[],"optional":[]},'
        '"telemetry_gaps":[],"gap_severity":"medium","telemetry_confidence":0.8}'
    )
    service = TelemetryPlanAI(fake_ai_client(response=bad_response))

    with pytest.raises(Exception):
        asyncio.run(service.plan(enriched_context))