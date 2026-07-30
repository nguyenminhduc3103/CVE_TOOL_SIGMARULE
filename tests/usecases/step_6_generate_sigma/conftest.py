"""Fixtures for Step 6 Sigma generation regression tests.

Tests cover the Log4Shell multi-source correlation case end-to-end at the
deterministic Builder level (no AI, no network calls).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# Invalidate KB lru_cache before any test reads it — KB YAML may be edited
# between runs and we want fresh content.
@pytest.fixture(autouse=True, scope="session")
def _invalidate_kb_cache() -> None:
    from src.usecases.step_6_generate_sigma._knowledge import loader

    loader.invalidate_cache()


@pytest.fixture
def log4shell_telemetry() -> dict:
    """Telemetry dict mirroring a Step 4 ``TelemetryAssessment.model_dump()``
    for a Log4Shell-like CVE: web request + outbound network + process spawn.
    """
    return {
        "sigma_logsources": [
            {"category": "webserver", "product": "linux"},
            {"category": "network_connection", "product": "windows"},
            {"category": "process_creation", "product": "windows"},
        ],
        "field_name_map": {
            "request_uri": "cs-uri-stem",
            "cs_uri_stem": "cs-uri-stem",
            "uri_query": "cs-uri-stem",
            "destination_port": "DestinationPort",
            "process_image": "Image",
            "command_line": "CommandLine",
        },
        "correlation_required": True,
        "validated_fields": ["cs_uri_stem", "destination_port", "process_image"],
    }


@pytest.fixture
def log4shell_analysis():
    from src.domain.models.attack import TechnicalAnalysis

    return TechnicalAnalysis(
        family="log4shell",
        signature="log4shell",
        vulnerability_type="rce",
    )


@pytest.fixture
def log4shell_attack():
    from src.domain.models.attack import AttackMapping

    return AttackMapping(techniques=["T1190"])


@pytest.fixture
def core_cve():
    from src.domain.models.cve import CoreCVEData

    return CoreCVEData(
        cve_id="CVE-2021-44228",
        description="Log4j JNDI lookup RCE",
        cvss_score=10.0,
        severity="critical",
        author="tester",
    )


@pytest.fixture
def log4shell_plan():
    from src.usecases.step_6_generate_sigma.domain.detection_plan import (
        DetectionIntent,
        DetectionLogic,
        DetectionPlan,
    )

    return DetectionPlan(
        detections=[
            DetectionIntent(
                intent="jndi_payload_lookup",
                priority="high",
                rationale="inbound JNDI payload in HTTP request",
                selection_hint={
                    "request_uri|contains": ["jndi:"],
                    "cs_uri_stem|contains": ["${${lower:j}ndi:"],
                },
            ),
            DetectionIntent(
                intent="outbound_ldap_rmi",
                priority="high",
                rationale="Java process initiating LDAP/RMI callback",
                selection_hint={
                    "destination_port": ["389", "636", "1099"],
                },
            ),
        ],
        logic=DetectionLogic(operator="at_least", operands=[0, 1], threshold=1),
        falsepositives=["legitimate administrative activity"],
        risk_bias="neutral",
        rationale="Log4Shell multi-stage correlation",
        planner_confidence=0.85,
        source="rule_based",
    )
