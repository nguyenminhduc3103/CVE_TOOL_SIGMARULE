"""Tests for TelemetryPlanAI post-pass wiring — sigma_logsources is populated deterministically."""
from __future__ import annotations

from typing import Any

import pytest

from src.usecases.step_4_telemetry import (
    SigmaLogsource,
    TelemetryPlan,
    TelemetryPlanAI,
    invalidate_statistics_cache,
    load_statistics,
)
from src.usecases.step_4_telemetry.models.telemetry_plan import (
    CandidateFeature,
    CandidateFeatures,
    DetectionAxis,
    TargetEnvironment,
)


class _StubClient:
    """Stub LLM client — we test the post-pass directly, never reaching `call_llm`."""

    async def call_llm(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover
        raise AssertionError("LLM should not be called in post-pass tests")


@pytest.fixture
def ai_service() -> TelemetryPlanAI:
    return TelemetryPlanAI(base_client=_StubClient())  # type: ignore[arg-type]


@pytest.fixture(autouse=True)
def _reset_cache():
    invalidate_statistics_cache()
    yield
    invalidate_statistics_cache()


def _feature(concept: str) -> CandidateFeature:
    return CandidateFeature(semantic="s", telemetry_concept=concept, evidence=[])


def _build_plan(target_env: TargetEnvironment, concepts: dict[str, list[str]]) -> TelemetryPlan:
    return TelemetryPlan(
        cve_id="CVE-2021-44228",
        target_environment=target_env,
        detection_axis=DetectionAxis(primary="initial_access", secondary=["post_exploitation"]),
        detection_strategy="Detect JNDI lookups correlated with outbound LDAP/RMI.",
        correlation_required=True,
        candidate_features=CandidateFeatures(
            stable=[_feature(c) for c in concepts.get("stable", [])],
            conditional=[_feature(c) for c in concepts.get("conditional", [])],
            optional=[],
        ),
        telemetry_gaps=["Encrypted HTTPS"],
        gap_severity="medium",
        telemetry_confidence=0.95,
        ai_model="test",
    )


def test_post_pass_populates_sigma_logsources(ai_service: TelemetryPlanAI):
    target_env = TargetEnvironment(platforms=["windows", "linux"])
    plan = _build_plan(
        target_env,
        concepts={"stable": ["process_creation"], "conditional": ["webserver"]},
    )
    assert plan.sigma_logsources == []  # initial state

    result = ai_service._resolve_sigma_logsources(plan)

    assert result.sigma_logsources == [
        SigmaLogsource(product="windows", category="process_creation"),
        SigmaLogsource(product="linux", category="process_creation"),
        SigmaLogsource(product=None, category="webserver"),
    ]


def test_post_pass_uses_injected_knowledge(ai_service: TelemetryPlanAI):
    """Real knowledge file drives the resolver."""
    target_env = TargetEnvironment(platforms=["windows", "linux"])
    plan = _build_plan(
        target_env,
        concepts={"stable": ["network_connection"], "conditional": ["webserver"]},
    )
    result = ai_service._resolve_sigma_logsources(plan)
    knowledge = load_statistics()
    nw = knowledge.get("network_connection")
    assert nw is not None
    expected: list[SigmaLogsource] = []
    for p in target_env.platforms:
        if p in nw.platforms:
            expected.append(SigmaLogsource(product=p, category="network_connection"))
    expected.append(SigmaLogsource(product=None, category="webserver"))
    assert result.sigma_logsources == expected


def test_post_pass_is_idempotent(ai_service: TelemetryPlanAI):
    target_env = TargetEnvironment(platforms=["windows"])
    plan = _build_plan(
        target_env,
        concepts={"stable": ["process_creation"], "conditional": ["webserver"]},
    )
    once = ai_service._resolve_sigma_logsources(plan)
    twice = ai_service._resolve_sigma_logsources(once)
    assert once.sigma_logsources == twice.sigma_logsources


def test_post_pass_does_not_mutate_original_plan(ai_service: TelemetryPlanAI):
    target_env = TargetEnvironment(platforms=["windows"])
    plan = _build_plan(
        target_env,
        concepts={"stable": ["process_creation"]},
    )
    original_logsources = list(plan.sigma_logsources)
    ai_service._resolve_sigma_logsources(plan)
    assert plan.sigma_logsources == original_logsources  # original untouched