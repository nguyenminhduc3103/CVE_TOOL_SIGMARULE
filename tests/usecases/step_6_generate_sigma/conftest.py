"""Shared fixtures for Step 6 tests.

Architect v9:
  - `TelemetryPlan` is the Step 4 search space (5 candidate logsources for
    Log4Shell-style fixtures).
  - `SigmaRuleAI` takes a stub `call_llm` to avoid real LLM calls.
  - Tests build `Step6Result` objects directly (without LLM) and run them
    through `Step6Validator` to assert business-rule behavior.

NOTE on async tests: the project has no pytest-asyncio dependency. Sync tests
use `asyncio.run(...)` via the `run_async` helper below.
"""
from __future__ import annotations

import asyncio
from typing import Any, Awaitable, TypeVar

import pytest

from src.domain.models.cve import CoreCVEData
from src.usecases.step_4_telemetry.models.sigma_logsource import SigmaLogsource
from src.usecases.step_4_telemetry.models.telemetry_plan import (
    CandidateFeature,
    CandidateFeatures,
    DetectionAxis,
    TargetEnvironment,
    TelemetryPlan,
)

T = TypeVar("T")


def run_async(coro: Awaitable[T]) -> T:
    """Run an async coroutine from sync test code (no pytest-asyncio plugin)."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# TelemetryPlan fixture: 5-logsource surface (Log4Shell-style)
# ---------------------------------------------------------------------------


def _log4shell_logsources() -> list[SigmaLogsource]:
    """5 candidate logsources for a Log4Shell-shaped CVE.

    - webserver: cs-uri-query contains JNDI strings
    - process_creation/windows: CommandLine + Image
    - process_creation/linux: CommandLine + Image
    - network_connection/windows: DestinationPort + DestinationIp
    - application: Message
    """
    return [
        SigmaLogsource(category="webserver", product=None, allowed_fields={
            "cs-uri-query": ["contains"],
            "cs-uri-stem": ["contains"],
        }),
        SigmaLogsource(category="process_creation", product="windows", allowed_fields={
            "CommandLine": ["contains", "startswith", "endswith"],
            "Image": ["contains", "endswith"],
        }),
        SigmaLogsource(category="process_creation", product="linux", allowed_fields={
            "CommandLine": ["contains", "startswith", "endswith"],
            "Image": ["contains", "endswith"],
        }),
        SigmaLogsource(category="network_connection", product="windows", allowed_fields={
            "DestinationPort": ["equals"],
            "DestinationIp": ["equals", "cidr"],
        }),
        SigmaLogsource(category="application", product=None, allowed_fields={
            "Message": ["contains"],
        }),
    ]


@pytest.fixture
def log4shell_telemetry_plan() -> TelemetryPlan:
    """Realistic Log4Shell-shaped TelemetryPlan: 5 candidate logsources."""
    return TelemetryPlan(
        cve_id="CVE-2021-44228",
        target_environment=TargetEnvironment(platforms=["windows", "linux"]),
        detection_axis=DetectionAxis(primary="initial_access", secondary=["post_exploitation"]),
        detection_strategy="Watch JNDI lookup strings + outbound LDAP/RMI from Java.",
        correlation_required=True,
        candidate_features=CandidateFeatures(
            stable=[CandidateFeature(semantic="JNDI lookup", telemetry_concept="webserver", evidence=[])],
        ),
        sigma_logsources=_log4shell_logsources(),
        telemetry_gaps=["process_access not enabled"],
        gap_severity="medium",
        telemetry_confidence=0.95,
        ai_model="test",
    )


@pytest.fixture
def empty_telemetry_plan() -> TelemetryPlan:
    """TelemetryPlan with zero candidate logsources (edge case for empty-selection test)."""
    return TelemetryPlan(
        cve_id="CVE-2024-00000",
        target_environment=TargetEnvironment(platforms=[]),
        detection_axis=DetectionAxis(primary="initial_access"),
        detection_strategy="No telemetry available.",
        correlation_required=False,
        candidate_features=CandidateFeatures(),
        sigma_logsources=[],
        telemetry_gaps=["all telemetry layers missing"],
        gap_severity="high",
        telemetry_confidence=0.0,
        ai_model="test",
    )


# ---------------------------------------------------------------------------
# CVE core fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def log4shell_core() -> CoreCVEData:
    return CoreCVEData(
        cve_id="CVE-2021-44228",
        description="Apache Log4j2 JNDI lookup RCE.",
        cwe_ids=["CWE-502", "CWE-917"],
        references=["https://logging.apache.org/log4j/2.x/security.html"],
    )


# ---------------------------------------------------------------------------
# Stub AI client (mirrors tests/unit/usecases/step_4_telemetry pattern)
# ---------------------------------------------------------------------------


class StubAIClient:
    """Stub LLM client — tests can set `.next_response` to drive SigmaRuleAI."""

    def __init__(self, next_response: str | None = None) -> None:
        self.next_response = next_response
        self.calls: list[dict[str, Any]] = []

    async def call_llm(self, *args: Any, **kwargs: Any) -> str:
        self.calls.append({"args": args, "kwargs": kwargs})
        if self.next_response is None:
            raise AssertionError(
                "StubAIClient.next_response not set; LLM should not be called "
                "in tests that bypass `.plan()`"
            )
        return self.next_response


@pytest.fixture
def stub_client() -> StubAIClient:
    return StubAIClient()