from __future__ import annotations

import json
from collections.abc import Callable

import pytest

from src.domain.models.attack import AttackMapping, TechnicalAnalysis
from src.domain.models.cve import CoreCVEData
from src.domain.models.enriched import EnrichedCVEContext
from src.domain.models.telemetry_discovery import PoCSummary
from src.usecases.step_4_telemetry.models.sigma_logsource import SigmaLogsource
from src.usecases.step_4_telemetry.models.telemetry_plan import (
    CandidateFeature,
    CandidateFeatures,
    DetectionAxis,
    TelemetryPlan,
    TargetEnvironment,
)
from src.usecases.step_6_generate_sigma.models.correlation import (
    Correlation,
    CorrelationBody,
    CorrelationReasoning,
    CorrelationRule,
)
from src.usecases.step_6_generate_sigma.models.detection import (
    Detection,
    DetectionBody,
    DetectionRule,
    LogsourceRef,
    SelectedField,
)
from src.usecases.step_6_generate_sigma.models.result import Step6Result


def extract_prompt_json(prompt: str) -> dict:
    start = prompt.find("{")
    end = prompt.rfind("}")
    assert start != -1 and end != -1 and end > start, prompt
    return json.loads(prompt[start : end + 1])


@pytest.fixture()
def cve_core() -> CoreCVEData:
    return CoreCVEData(
        cve_id="CVE-2024-0001",
        description="Malicious document parsing issue leading to code execution",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R",
        cwe_ids=["CWE-79"],
        affected_products=["[APP] Apache", "[OS] Windows"],
    )


@pytest.fixture()
def poc_summary() -> PoCSummary:
    return PoCSummary(
        public_poc=True,
        poc_references=["https://example.test/poc"],
        poc_description="PoC document describing the exploit chain",
        poc_network_payloads=[
            {
                "method": "POST",
                "path": "/vuln",
                "body": "cmd=whoami",
            }
        ],
    )


@pytest.fixture()
def technical_analysis() -> TechnicalAnalysis:
    return TechnicalAnalysis(
        execution_surface="client_side",
        delivery_vector="email_attachment",
        mandatory_behaviors=["process_creation", "file_write"],
        evasive_indicators=["base64"],
        exploit_requirements=["Victim opens crafted file"],
        reasoning=["User opens a crafted document and code executes locally"],
        confidence=0.91,
        ai_used=True,
        ai_model="phase1-model",
    )


@pytest.fixture()
def attack_mapping() -> AttackMapping:
    return AttackMapping(
        tactics=["TA0001"],
        techniques=["T1190"],
        subtechniques=["T1190.001"],
        mapping_reasons=["Initial exploitation over HTTP"],
        is_attack_chain=True,
        attack_chain=[
            {
                "step": 1,
                "tactic_id": "TA0001",
                "technique_id": "T1190",
                "description": "Attacker sends malicious request",
                "reasoning": "Network delivery into a public-facing service",
            }
        ],
        chain_reasoning=["Single-stage chain"],
        confidence_level="high",
        ai_used=True,
        ai_model="phase2-model",
    )


@pytest.fixture()
def telemetry_plan() -> TelemetryPlan:
    return TelemetryPlan(
        cve_id="CVE-2024-0001",
        target_environment=TargetEnvironment(
            platforms=["windows"],
            deployment=["endpoint"],
            application_types=["web_application"],
            technologies=["Apache"],
            special_environments=[],
        ),
        detection_axis=DetectionAxis(
            primary="initial_access",
            secondary=["post_exploitation"],
        ),
        detection_strategy="Detect malicious request and follow-on execution",
        correlation_required=True,
        candidate_features=CandidateFeatures(
            stable=[
                CandidateFeature(
                    semantic="Suspicious process creation",
                    telemetry_concept="process_creation",
                    evidence=["child process spawned after exploitation"],
                )
            ],
            conditional=[
                CandidateFeature(
                    semantic="Outbound network callback",
                    telemetry_concept="network_connection",
                    evidence=["callback to attacker infrastructure"],
                )
            ],
            optional=[
                CandidateFeature(
                    semantic="Optional file artifact",
                    telemetry_concept="file_change",
                    evidence=["artifact written to disk"],
                )
            ],
        ),
        sigma_logsources=[
            SigmaLogsource(
                category="process_creation",
                product="windows",
                allowed_fields={
                    "CommandLine": ["contains"],
                    "Image": ["contains"],
                },
            ),
            SigmaLogsource(
                category="network_connection",
                product="windows",
                allowed_fields={
                    "DestinationPort": ["equals"],
                },
            ),
        ],
        telemetry_gaps=["No endpoint telemetry on Linux"],
        gap_severity="medium",
        telemetry_confidence=0.87,
        ai_model="telemetry-model",
    )


@pytest.fixture()
def step6_detection_one() -> Detection:
    return Detection(
        id="rule_1",
        rule=DetectionRule(
            description="Detect malicious process creation",
            logsource=LogsourceRef(category="process_creation", product="windows"),
            detection=DetectionBody(
                selection=[
                    SelectedField(
                        name="CommandLine",
                        modifier="contains",
                        value="jndi:",
                        reason="JNDI abuse in command line",
                    )
                ],
                condition="selection",
            ),
            falsepositives=["Admin troubleshooting"],
            level="high",
        ),
    )


@pytest.fixture()
def step6_detection_two() -> Detection:
    return Detection(
        id="rule_2",
        rule=DetectionRule(
            description="Detect outbound network callback",
            logsource=LogsourceRef(category="network_connection", product="windows"),
            detection=DetectionBody(
                selection=[
                    SelectedField(
                        name="DestinationPort",
                        modifier="equals",
                        value="389",
                        reason="LDAP callback is part of the exploit chain",
                    )
                ],
                condition="selection",
            ),
            falsepositives=[],
            level="medium",
        ),
    )


@pytest.fixture()
def step6_correlation() -> Correlation:
    return Correlation(
        rule=CorrelationRule(
            description="Correlate process creation with network callback",
            correlation=CorrelationBody(
                rules=["rule_1", "rule_2"],
                type="temporal",
                window="5m",
            ),
            level="high",
        ),
        reasoning=CorrelationReasoning(
            correlation_strategy="Process activity followed by outbound callback",
            parameter_reasoning=[
                {
                    "parameter": "window",
                    "value": "5m",
                    "reason": "Exploit chain unfolds quickly",
                }
            ],
        ),
    )


@pytest.fixture()
def step6_result(step6_detection_one: Detection, step6_detection_two: Detection, step6_correlation: Correlation) -> Step6Result:
    return Step6Result(
        cve_id="CVE-2024-0001",
        ai_model="sigma-model",
        detections=[step6_detection_one, step6_detection_two],
        correlations=[step6_correlation],
        reasoning="Two-stage detection strategy",
    )


@pytest.fixture()
def enriched_context(
    cve_core: CoreCVEData,
    technical_analysis: TechnicalAnalysis,
    attack_mapping: AttackMapping,
    telemetry_plan: TelemetryPlan,
    poc_summary: PoCSummary,
) -> EnrichedCVEContext:
    return EnrichedCVEContext(
        core=cve_core,
        triage={"cve_id": cve_core.cve_id, "status": "triaged"},
        analysis=technical_analysis,
        attack=attack_mapping,
        telemetry=telemetry_plan,
        intel=poc_summary,
    )


@pytest.fixture()
def fake_ai_client() -> Callable[[str | None, Exception | None], object]:
    from unittest.mock import AsyncMock

    _unset = object()

    class Client:
        def __init__(self, response: str | None = _unset, side_effect: Exception | None = None) -> None:
            self.call_llm = AsyncMock()
            if side_effect is not None:
                self.call_llm.side_effect = side_effect
            else:
                self.call_llm.return_value = "{}" if response is _unset else response

    return Client