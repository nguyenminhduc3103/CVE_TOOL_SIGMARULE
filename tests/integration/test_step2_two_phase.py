"""Integration test: 2-phase Step 2 flow.

Goal: verify the 2-phase refactor fixes the AV:N → T1190 bias.

CVE patterns covered:
  1. CVE-2021-40444 (MSHTML client-side) — Phase 1=client_side, Phase 2 picks T1204.002/T1566.001.
  2. CVE-2013-4365 (Apache server-side) — Phase 1=server_side, Phase 2 picks T1190, subtechniques=[].
  3. CVE-2024-3094 (XZ supply chain) — Phase 1=multi_hop, Phase 2 picks T1195.002.

Tests use a mock AI client (no real API key required).
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest

from app.shared.ai.core import BaseAIClient
from app.steps.step_2_tech_analysis.orchestrator import run_step2_tech_analysis
from app.steps.step_2_tech_analysis.services.ai_service import AIBehaviorService


# ---------------------------------------------------------------------------
# Mock client
# ---------------------------------------------------------------------------
class MockTwoPhaseClient(BaseAIClient):
    """Mock AI client that returns canned Phase 1 + Phase 2 responses."""

    def __init__(
        self,
        phase1_output: dict,
        phase2_output: dict,
    ):
        self.phase1_output = phase1_output
        self.phase2_output = phase2_output
        self.call_count = 0
        self.calls = []

    async def call_llm(self, system_prompt, user_prompt, model, **kwargs):
        self.call_count += 1
        self.calls.append({
            "system_first_50": system_prompt[:50],
            "system_first_200": system_prompt[:200],
            "user_first_200": user_prompt[:200],
            "model": model,
        })
        if "BEHAVIOR ANALYSIS ONLY" in system_prompt:
            return json.dumps(self.phase1_output)
        if "ATT&CK MAPPING ONLY" in system_prompt:
            return json.dumps(self.phase2_output)
        return "{}"


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------
PHASE1_MSHTML = {
    "family": "mshtml_rce",
    "vulnerability_type": "memory_corruption",
    "vulnerability_class": "remote_code_execution",
    "exploit_vector": "remote",
    "pre_auth": True,
    "remote_exploitable": True,
    "exploit_complexity": "low",
    "confidence": 0.95,
    "execution_surface": "client_side",
    "delivery_vector": "email_attachment",
    "user_interaction_required": True,
    "attack_flow": {
        "entry_vector": "Crafted .docx with embedded ActiveX control",
        "execution_mechanism": "MSHTML ActiveX rendering in Word",
        "observable_side_effects": ["Word spawning unusual children"],
    },
    "mandatory_behaviors": ["process_creation", "file_write"],
    "evasive_indicators": ["MOTW bypass"],
    "exploit_requirements": ["Microsoft Office"],
    "cwe_metadata": {
        "cwe_ids": ["CWE-787"],
        "cwe_names": ["Out-of-bounds Write"],
        "mapping_confidence": 0.85,
    },
    "reasoning": ["Client-side exploitation chain"],
}

PHASE2_MSHTML = {
    "tactics": ["TA0001"],
    "techniques": ["T1204", "T1566"],
    "subtechniques": ["T1204.002", "T1566.001"],
    "attack_confidence": 0.9,
    "mapping_reasons": [
        "execution_surface=client_side → T1204/T1566 (NOT T1190)"
    ],
}

PHASE1_APACHE = {
    "family": "apache_fcgid_overflow",
    "vulnerability_type": "memory_corruption",
    "vulnerability_class": "remote_code_execution",
    "exploit_vector": "remote",
    "pre_auth": True,
    "remote_exploitable": True,
    "exploit_complexity": "medium",
    "confidence": 0.8,
    "execution_surface": "server_side",
    "delivery_vector": "network_protocol",
    "user_interaction_required": False,
    "attack_flow": {
        "entry_vector": "HTTP request with crafted headers",
        "execution_mechanism": "Heap-based buffer overflow in mod_fcgid",
        "observable_side_effects": ["new process creation"],
    },
    "mandatory_behaviors": ["process_creation"],
    "evasive_indicators": [
        "HTTP chunked transfer encoding to bypass length-based WAF",
        "URL/hex encoding of oversized header payload",
        "ROP chains to bypass DEP after heap corruption",
    ],
    "exploit_requirements": ["Apache HTTP Server with mod_fcgid < 2.3.9"],
    "cwe_metadata": {
        "cwe_ids": ["CWE-787"],
        "cwe_names": ["Out-of-bounds Write"],
        "mapping_confidence": 0.9,
    },
    "reasoning": ["Server-side heap overflow"],
}

PHASE2_APACHE = {
    "tactics": ["TA0001", "TA0002", "TA0040"],
    "techniques": ["T1190", "T1203", "T1499"],
    "subtechniques": ["T1499.004"],
    "attack_confidence": 0.85,
    "mapping_reasons": [
        "execution_surface=server_side → T1190 (HTTP endpoint RCE)",
        "CWE-787 memory corruption → T1203 (Exploitation for Client Execution)",
        "Process crash observable → T1499.004 (Endpoint DoS: App Exploitation)",
    ],
}

PHASE1_XZ = {
    "family": "supply_chain_backdoor",
    "vulnerability_type": "backdoor",
    "vulnerability_class": "remote_code_execution",
    "exploit_vector": "remote",
    "pre_auth": True,
    "remote_exploitable": True,
    "exploit_complexity": "high",
    "confidence": 0.9,
    "execution_surface": "multi_hop",
    "delivery_vector": "local_execution",
    "user_interaction_required": False,
    "attack_flow": {
        "entry_vector": "Malicious code in xz tarball (supply chain compromise)",
        "execution_mechanism": "Backdoor in liblzma triggered by SSH service",
        "observable_side_effects": ["SSH auth bypass", "backdoor execution"],
    },
    "mandatory_behaviors": ["process_creation", "network_callback"],
    "evasive_indicators": ["obfuscated ifunc resolver"],
    "exploit_requirements": ["xz-utils 5.6.0+", "systemd + sshd"],
    "cwe_metadata": {
        "cwe_ids": ["CWE-829"],
        "cwe_names": ["Inclusion of Functionality from Untrusted Control Sphere"],
        "mapping_confidence": 0.95,
    },
    "reasoning": ["Supply chain compromise"],
}

PHASE2_XZ = {
    "tactics": ["TA0001", "TA0003"],
    "techniques": ["T1195"],
    "subtechniques": ["T1195.002"],
    "attack_confidence": 0.9,
    "mapping_reasons": [
        "execution_surface=multi_hop → T1195.002 (Supply Chain Compromise)"
    ],
}


def _run_2phase(monkeypatch, phase1: dict, phase2: dict, cve_id: str):
    """Helper: enable 2-phase mode and run run_step2_tech_analysis."""
    monkeypatch.setenv("CVE_TI_STEP2_TWO_PHASE", "1")
    client = MockTwoPhaseClient(phase1, phase2)
    ai_service = AIBehaviorService(client)
    return asyncio.run(run_step2_tech_analysis(
        ai_service=ai_service,
        base_client=client,
        cve_id=cve_id,
        description="test description",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe_ids=["CWE-787"],
        cpes=[],
        references=[],
        published_at="2024-01-01",
        modified_at="2024-01-01",
    )), client


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestTwoPhaseFlow:
    """Verify 2-phase AI flow produces correct execution_surface + ATT&CK mapping."""

    def test_mshtml_client_side_avoids_t1190(self, monkeypatch):
        """CVE-2021-40444 (MSHTML client-side): Phase 2 must NOT pick T1190."""
        (tech, attack, validation), client = _run_2phase(
            monkeypatch, PHASE1_MSHTML, PHASE2_MSHTML, "CVE-2021-40444"
        )

        # Verify 2 AI calls.
        assert client.call_count == 2, f"Expected 2 AI calls, got {client.call_count}"

        # Phase 1 was called first, Phase 2 second (system prompt marker).
        assert "BEHAVIOR ANALYSIS ONLY" in client.calls[0]["system_first_200"]
        assert "ATT&CK MAPPING ONLY" in client.calls[1]["system_first_200"]

        # Key outcome: execution_surface = client_side.
        assert tech.execution_surface.value == "client_side"
        assert tech.delivery_vector.value == "email_attachment"
        assert tech.user_interaction_required is True

        # Phase 2 picks T1204/T1566 (NOT T1190).
        assert "T1190" not in (attack.techniques or []), \
            "BIAS: AI picked T1190 for client-side CVE"
        assert "T1204" in attack.techniques
        assert "T1566" in attack.techniques
        assert "T1204.002" in attack.subtechniques
        assert "T1566.001" in attack.subtechniques

        # Verdict reflects 2-phase pass.
        assert validation["verdict"] == "PASS_TWO_PHASE"
        assert validation["phase1_execution_surface"] == "client_side"

    def test_apache_server_side_full_kill_chain(self, monkeypatch):
        """CVE-2013-4365 (Apache mod_fcgid heap overflow): multi-tactic kill chain.

        Memory-corruption CVE phải emit đầy đủ:
          - T1190 (Initial Access) + TA0001
          - T1203 (Execution via memory corruption) + TA0002
          - T1499 + T1499.004 (Impact: process crash) + TA0040
        Evasive indicators không được trống (memory-corruption + HTTP → WAF bypass).
        """
        (tech, attack, validation), client = _run_2phase(
            monkeypatch, PHASE1_APACHE, PHASE2_APACHE, "CVE-2013-4365"
        )

        assert client.call_count == 2

        # Phase 1 anchors
        assert tech.execution_surface.value == "server_side"
        assert tech.delivery_vector.value == "network_protocol"
        assert tech.user_interaction_required is False

        # 3 tactics covering kill chain
        assert set(attack.tactics or []) >= {"TA0001", "TA0002", "TA0040"}

        # 3 techniques: initial access + execution + impact
        assert set(attack.techniques or []) >= {"T1190", "T1203", "T1499"}

        # Subtechnique for Impact
        assert "T1499.004" in (attack.subtechniques or [])

        # Evasive indicators non-empty (memory corruption + HTTP delivery)
        assert tech.evasive_indicators, \
            "evasive_indicators must be populated for HTTP memory-corruption CVE"
        assert len(tech.evasive_indicators) >= 1

    def test_xz_supply_chain_uses_t1195(self, monkeypatch):
        """CVE-2024-3094 (XZ backdoor): Phase 2 picks T1195.002 (supply chain)."""
        (tech, attack, validation), client = _run_2phase(
            monkeypatch, PHASE1_XZ, PHASE2_XZ, "CVE-2024-3094"
        )

        assert tech.execution_surface.value == "multi_hop"
        assert "T1195" in attack.techniques
        assert "T1195.002" in attack.subtechniques
        # NOT T1190 (server-side) or T1204 (client-side).
        assert "T1190" not in (attack.techniques or [])

    def test_two_phase_disabled_by_default(self, monkeypatch):
        """Backward compat: env unset → 1-shot mode (one AI call)."""
        monkeypatch.delenv("CVE_TI_STEP2_TWO_PHASE", raising=False)
        client = MockTwoPhaseClient(PHASE1_MSHTML, PHASE2_MSHTML)
        ai_service = AIBehaviorService(client)

        # Mock returns legacy 1-shot shape.
        async def legacy_call(system_prompt, user_prompt, model, **kwargs):
            client.call_count += 1
            return json.dumps({
                "technical_analysis": {"family": "legacy", "confidence": 0.5},
                "attack_mapping": {"tactics": ["TA0001"], "techniques": ["T1190"]}
            })
        client.call_llm = legacy_call

        asyncio.run(run_step2_tech_analysis(
            ai_service=ai_service, base_client=client,
            cve_id="CVE-LEGACY", description="test",
            cvss_score=5.0, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            cwe_ids=[], cpes=[], references=[],
            published_at="2024-01-01", modified_at="2024-01-01",
        ))

        # 1-shot mode invokes AI at least once (rule-based fallback may also fire).
        assert client.call_count >= 1


class TestPhase1AndPhase2Imports:
    """Verify services + enums import cleanly without circular deps."""

    def test_execution_surface_enum(self):
        from app.shared.types.execution_surface import ExecutionSurface, DeliveryVector

        assert ExecutionSurface.CLIENT_SIDE.value == "client_side"
        assert ExecutionSurface.SERVER_SIDE.value == "server_side"
        assert ExecutionSurface.LOCAL.value == "local"
        assert ExecutionSurface.MULTI_HOP.value == "multi_hop"
        assert ExecutionSurface.UNKNOWN.value == "unknown"

        assert DeliveryVector.EMAIL_ATTACHMENT.value == "email_attachment"
        assert DeliveryVector.NETWORK_PROTOCOL.value == "network_protocol"

    def test_rule_based_classifier(self):
        """Smoke test: rule-based classifier maps CVE patterns to the right surface."""
        from app.steps.step_2_tech_analysis.rule_based.exploit_classifier import (
            classify_execution_surface,
            classify_delivery_vector,
        )
        from app.shared.types.execution_surface import ExecutionSurface, DeliveryVector

        # MSHTML client-side
        s = classify_execution_surface(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
            "Microsoft MSHTML ActiveX vulnerability in Office Word",
            ["CWE-787"],
        )
        assert s == ExecutionSurface.CLIENT_SIDE

        # Apache server-side
        s = classify_execution_surface(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Apache HTTP Server mod_fcgid heap overflow",
            ["CWE-787"],
        )
        assert s == ExecutionSurface.SERVER_SIDE

        # XZ supply chain
        s = classify_execution_surface(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "XZ Utils supply chain backdoor",
            ["CWE-829"],
        )
        assert s == ExecutionSurface.MULTI_HOP

        # Local kernel
        s = classify_execution_surface(
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "Windows kernel driver privilege escalation",
            ["CWE-264"],
        )
        assert s == ExecutionSurface.LOCAL

    def test_phase1_service_import(self):
        from app.steps.step_2_tech_analysis.services.phase1_service import (
            AIPhase1Service,
        )
        assert AIPhase1Service.__name__ == "AIPhase1Service"

    def test_phase2_method_exists(self):
        """AIBehaviorService must expose fetch_attack_mapping (Phase 2)."""
        from app.steps.step_2_tech_analysis.services.ai_service import AIBehaviorService
        assert hasattr(AIBehaviorService, "fetch_attack_mapping")
        assert hasattr(AIBehaviorService, "fetch_raw_response")  # backward compat


class TestPhase1SeparateProvider:
    """Verify Phase 1 may use a separate provider (e.g. OpenRouter) than Phase 2."""

    def test_phase1_separate_provider(self, monkeypatch):
        """When PHASE1_AI_* env set, Phase 1 builds separate AsyncOpenAI client."""
        import os
        # Clear list-form first; PHASE1_AI_KEYS (if set in .env) takes priority.
        monkeypatch.setenv("PHASE1_AI_KEYS", "")
        monkeypatch.setenv("PHASE1_AI_MODEL", "meta-llama/llama-3.3-70b-instruct:free")
        monkeypatch.setenv("PHASE1_AI_BASE_URL", "https://openrouter.ai/api/v1")
        monkeypatch.setenv("PHASE1_AI_API_KEY", "sk-or-test-fake")

        # Reload settings after env override.
        from importlib import reload
        from app.core import config as cfg_module
        reload(cfg_module)
        from app.steps.step_2_tech_analysis.services import phase1_service
        reload(phase1_service)
        from app.steps.step_2_tech_analysis.services.phase1_service import AIPhase1Service
        from app.core.config import settings

        # Getters must return Phase 1 specific config.
        assert "free" in settings.get_phase1_model(), \
            f"Expected free model, got {settings.get_phase1_model()}"
        assert settings.get_phase1_base_url() == "https://openrouter.ai/api/v1"
        assert settings.get_phase1_api_keys() == ["sk-or-test-fake"], \
            f"Expected ['sk-or-test-fake'], got {settings.get_phase1_api_keys()}"

        # CaptureClient records call_llm kwargs for assertion.
        class CaptureClient(BaseAIClient):
            def __init__(self):
                super().__init__()
                self.captured_kwargs = None
            async def call_llm(self, system_prompt, user_prompt, model, **kwargs):
                self.captured_kwargs = kwargs
                return json.dumps({
                    "execution_surface": "client_side",
                    "delivery_vector": "email_attachment",
                    "user_interaction_required": True,
                    "attack_flow": {
                        "entry_vector": "test",
                        "execution_mechanism": "test",
                        "observable_side_effects": ["test"],
                    },
                    "reasoning": ["test"],
                })

        client = CaptureClient()
        client.ai_enabled = True
        svc = AIPhase1Service(client)

        # Model must be Phase 1 specific (not default Groq).
        assert "free" in svc._MODEL, f"Expected free model, got {svc._MODEL}"

        # Call fetch_behavior.
        asyncio.run(svc.fetch_behavior(
            cve_id="TEST", description="d", cvss_score=5.0,
            cvss_vector="CVSS:3.1/AV:N", cwe_ids=[], cpes=[],
            references=[], published_at="2024-01-01", modified_at="2024-01-01",
        ))

        # call_llm MUST receive override (separate provider path).
        assert client.captured_kwargs is not None
        assert "override_api_key" in client.captured_kwargs, \
            "Expected override_api_key when Phase 1 has separate provider"
        assert client.captured_kwargs["override_api_key"] == "sk-or-test-fake"
        assert client.captured_kwargs["override_base_url"] == "https://openrouter.ai/api/v1"

        # Cleanup: reload to restore .env values for subsequent tests.
        reload(cfg_module)
        reload(phase1_service)

    def test_phase1_default_uses_main_client(self, monkeypatch):
        """When PHASE1_AI_* unset, Phase 1 shares primary client (no override)."""
        # Empty string overrides .env (delenv fails: pydantic-settings reads .env at Settings() init).
        monkeypatch.setenv("PHASE1_AI_MODEL", "")
        monkeypatch.setenv("PHASE1_AI_BASE_URL", "")
        monkeypatch.setenv("PHASE1_AI_API_KEY", "")
        monkeypatch.setenv("PHASE1_AI_KEYS", "")

        from importlib import reload
        from app.core import config as cfg_module
        reload(cfg_module)
        from app.steps.step_2_tech_analysis.services import phase1_service
        reload(phase1_service)
        from app.steps.step_2_tech_analysis.services.phase1_service import AIPhase1Service
        from app.core.config import settings

        # Phase 1 config must fall back to main (Groq).
        phase1_model = settings.get_phase1_model()
        main_model = settings.get_analyze_model()
        assert phase1_model == main_model, \
            f"Expected Phase 1 == main, got Phase 1={phase1_model}, main={main_model}"
        assert settings.get_phase1_base_url() == getattr(settings, "ai_base_url", None), \
            "Expected Phase 1 base_url == main base_url"

        class CaptureClient(BaseAIClient):
            def __init__(self):
                super().__init__()
                self.captured_kwargs = None
            async def call_llm(self, system_prompt, user_prompt, model, **kwargs):
                self.captured_kwargs = kwargs
                return json.dumps({
                    "execution_surface": "server_side",
                    "attack_flow": {
                        "entry_vector": "test",
                        "execution_mechanism": "test",
                        "observable_side_effects": ["test"],
                    },
                    "reasoning": ["test"],
                })

        client = CaptureClient()
        client.ai_enabled = True
        svc = AIPhase1Service(client)

        # Model must be Groq default (fallback).
        assert svc._MODEL == "llama-3.3-70b-versatile", \
            f"Expected Groq default, got {svc._MODEL}"

        asyncio.run(svc.fetch_behavior(
            cve_id="TEST", description="d", cvss_score=5.0,
            cvss_vector="CVSS:3.1/AV:N", cwe_ids=[], cpes=[],
            references=[], published_at="2024-01-01", modified_at="2024-01-01",
        ))

        # No override — Phase 1 shares primary client.
        assert client.captured_kwargs is not None
        assert "override_api_key" not in client.captured_kwargs, \
            "Should use primary client when Phase 1 config matches main config"