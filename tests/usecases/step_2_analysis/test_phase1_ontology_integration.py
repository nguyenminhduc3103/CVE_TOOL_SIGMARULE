"""Integration tests for AIPhase1Service + mandatory_behavior_ontology injection.

These tests verify the system_prompt assembly path end-to-end:
- ontology block is rendered and injected at {mandatory_behaviors_block}
- ontology file failure modes (missing/invalid) degrade gracefully
- output schema (7 fields) remains backward-compatible
- LLM client is called with the resolved prompt (not the raw template)

Mocks BaseAIClient.call_llm so no real API is hit.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


ONTOLOGY_PATH = ROOT / ".cache" / "ontology" / "mandatory_behavior_ontology.json"


def _make_mock_client(response_text: str) -> MagicMock:
    """Build a BaseAIClient subclass that records calls and returns canned JSON."""
    client = MagicMock()
    client.call_llm = AsyncMock(return_value=response_text)
    return client


def _minimal_valid_response() -> str:
    return json.dumps(
        {
            "execution_surface": "server_side",
            "delivery_vector": "network_protocol",
            "mandatory_behaviors": ["sql_injection", "command_execution"],
            "evasive_indicators": [],
            "exploit_requirements": ["Network access to DB port"],
            "reasoning": ["CVE describes SQL injection in login form"],
            "confidence": 0.85,
        }
    )


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) if False else asyncio.run(coro)


class TestOntologyBlockInjection:
    """Verify the rendered bullet list appears in the system prompt sent to LLM."""

    def test_prompt_contains_all_primitive_tokens(self) -> None:
        pytest.importorskip("pydantic")
        from src.usecases.step_2_analysis.services.phase1_service import AIPhase1Service

        client = _make_mock_client(_minimal_valid_response())
        svc = AIPhase1Service(client)

        result = _run(svc.fetch_behavior(
            cve_id="CVE-2024-0001",
            description="A SQL injection vulnerability.",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe_ids=["CWE-89"],
        ))

        # LLM was called exactly once.
        assert client.call_llm.await_count == 1
        # Capture the resolved system_prompt that was sent.
        sent_system = client.call_llm.await_args.kwargs["system_prompt"]
        # The template placeholder must be RESOLVED (not present as literal text).
        assert "{mandatory_behaviors_block}" not in sent_system
        # All 110 primitive tokens appear in the rendered prompt.
        tokens = {
            e["primitive"]
            for e in json.loads(ONTOLOGY_PATH.read_text(encoding="utf-8"))["entries"]
        }
        missing = [t for t in tokens if f"`{t}`" not in sent_system]
        assert not missing, f"Missing {len(missing)} tokens in prompt, e.g. {missing[:3]}"
        # Output dict still passes the 7-field schema.
        assert result["mandatory_behaviors"] == ["sql_injection", "command_execution"]
        assert result["execution_surface"] == "server_side"
        assert 0.0 <= result["confidence"] <= 1.0

    def test_backward_compat_output_with_optional_call_kwargs(self) -> None:
        """fetch_behavior should not break when caller passes only base kwargs."""
        pytest.importorskip("pydantic")
        from src.usecases.step_2_analysis.services.phase1_service import AIPhase1Service

        client = _make_mock_client(_minimal_valid_response())
        svc = AIPhase1Service(client)

        result = _run(svc.fetch_behavior(
            cve_id="CVE-2024-0001",
            description="desc",
            cvss_score=5.0,
            cvss_vector="CVSS:3.1/AV:N",
            cwe_ids=[],
            poc_description=None,  # explicit None
            poc_request_info=None,
        ))
        assert "mandatory_behaviors" in result


class TestOntologyFailureModes:
    """Service must not crash when ontology file is missing or invalid."""

    def test_missing_ontology_file(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Point _ONTOLOGY_FILE at a non-existent path; service should still run."""
        pytest.importorskip("pydantic")
        from src.usecases.step_2_analysis.services import phase1_service

        monkeypatch.setattr(phase1_service, "_ONTOLOGY_FILE", tmp_path / "nope.json")
        # Rebuild the service after monkeypatch so __init__ picks up the new path.
        client = _make_mock_client(_minimal_valid_response())
        svc = phase1_service.AIPhase1Service(client)

        # __init__ did not raise; the block has an explicit placeholder.
        assert "no behaviors available" in svc._mandatory_behaviors_block.lower()
        sent_system = client.call_llm.call_args_list  # call_args_list before invoke
        _run(svc.fetch_behavior(
            cve_id="CVE-2024-0002",
            description="x",
            cvss_score=1.0,
            cvss_vector="CVSS:3.1/AV:L",
            cwe_ids=[],
        ))
        sent_system = client.call_llm.await_args.kwargs["system_prompt"]
        # Placeholder substituted with the empty-vocab message, no literal { } left.
        assert "{mandatory_behaviors_block}" not in sent_system
        assert "no behaviors available" in sent_system.lower()

    def test_invalid_ontology_json(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        pytest.importorskip("pydantic")
        from src.usecases.step_2_analysis.services import phase1_service

        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json", encoding="utf-8")
        monkeypatch.setattr(phase1_service, "_ONTOLOGY_FILE", bad)

        client = _make_mock_client(_minimal_valid_response())
        svc = phase1_service.AIPhase1Service(client)

        assert "no behaviors available" in svc._mandatory_behaviors_block.lower()
        _run(svc.fetch_behavior(
            cve_id="CVE-2024-0003",
            description="y",
            cvss_score=1.0,
            cvss_vector="CVSS:3.1/AV:L",
            cwe_ids=[],
        ))
        # Service still resolved the placeholder without raising.
        sent = client.call_llm.await_args.kwargs["system_prompt"]
        assert "{mandatory_behaviors_block}" not in sent


class TestPerformanceSmoke:
    """Construct service and resolve the prompt - timing budget sanity check."""

    def test_init_loads_ontology_quickly(self) -> None:
        pytest.importorskip("pydantic")
        from time import perf_counter

        from src.usecases.step_2_analysis.services.phase1_service import AIPhase1Service

        # Mock client so __init__ doesn't try to read API keys.
        client = MagicMock()
        client.api_keys = ["test"]
        client.api_key = "test"

        start = perf_counter()
        AIPhase1Service(client)
        elapsed = perf_counter() - start
        # Init should be fast - ontology file is ~15KB; bound tightly.
        assert elapsed < 2.0, f"AIPhase1Service.__init__ took {elapsed:.2f}s"
