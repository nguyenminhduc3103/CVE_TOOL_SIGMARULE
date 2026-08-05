"""Log4Shell synthetic end-to-end: 3 detections chosen from 5-logsource surface.

Architect v9: AI chooses the MINIMUM SUBSET. From 5 candidate logsources,
the canned AI response picks 3 (webserver + process_creation/windows +
network_connection/windows), ignores the other 2 (process_creation/linux,
application).

This test asserts:
  - The 3 detections are accepted by the validator.
  - The correlation between them resolves correctly.
  - Per-selection grammar (field ∈ allowed_fields, modifier ∈ allowed_fields[field])
    is respected for all 9 selections across the 3 detections.
"""
from __future__ import annotations

import json

from src.usecases.step_6_generate_sigma.models.result import Step6Result
from src.usecases.step_6_generate_sigma.services.sigma_rule_ai import SigmaRuleAI

from tests.usecases.step_6_generate_sigma.conftest import run_async


CANNED_LOG4SHELL_RESPONSE = {
    "detections": [
        {
            "id": "rule_1",
            "rule": {
                "description": "JNDI lookup in webserver URI",
                "logsource": {"category": "webserver", "product": None},
                "detection": {
                    "selection": [
                        {"name": "cs-uri-query", "modifier": "contains", "value": "${jndi:",
                         "reason": "JNDI lookup substring is the unique signature of initial-access payload, mentioned in CVE description."}
                    ],
                    "condition": "selection",
                },
                "falsepositives": ["legitimate JNDI queries by internal apps"],
                "level": "high",
            },
        },
        {
            "id": "rule_2",
            "rule": {
                "description": "Java process invoking LDAP callback",
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection": [
                        {"name": "CommandLine", "modifier": "contains", "value": "ldap://",
                         "reason": "Java processes spawned with LDAP callback strings indicate post-exploitation."},
                        {"name": "Image", "modifier": "endswith", "value": "\\java.exe",
                         "reason": "\\java.exe is the canonical JVM executable on Windows."},
                    ],
                    "condition": "selection",
                },
                "falsepositives": [],
                "level": "high",
            },
        },
        {
            "id": "rule_3",
            "rule": {
                "description": "Outbound LDAP/RMI from Windows process",
                "logsource": {"category": "network_connection", "product": "windows"},
                "detection": {
                    "selection": [
                        {"name": "DestinationPort", "modifier": "equals", "value": "389",
                         "reason": "LDAP callbacks to non-corporate servers indicate exploitation."},
                        {"name": "DestinationPort", "modifier": "equals", "value": "636",
                         "reason": "Secure LDAP (636) is also commonly abused by Java JNDI references."},
                    ],
                    "condition": "selection",
                },
                "falsepositives": [],
                "level": "medium",
            },
        },
    ],
    "correlations": [
        {
            "rule": {
                "description": "JNDI request → Java process → outbound LDAP/RMI",
                "correlation": {
                    "rules": ["rule_1", "rule_2", "rule_3"],
                    "type": "temporal",
                    "window": "5m",
                },
                "level": "high",
            },
            "reasoning": {
                "correlation_strategy": "Full chain JNDI request followed by Java process and outbound LDAP/RMI within 5 minutes.",
                "parameter_reasoning": [
                    {"parameter": "window", "value": "5m",
                     "reason": "Java process spawn → outbound LDAP/RMI happens within seconds of the initial JNDI request based on observed PoC behavior."}
                ],
            },
        }
    ],
    "reasoning": "Log4Shell detection requires web server JNDI lookups, Java process invocations, and outbound LDAP/RMI from the same host within a short window.",
}


async def _log4shell_3_detections_pass_validator(
    log4shell_telemetry_plan, log4shell_core, stub_client
):
    """Canned AI response drives the service end-to-end through the validator."""
    stub_client.next_response = json.dumps(CANNED_LOG4SHELL_RESPONSE)

    service = SigmaRuleAI(ai_client=stub_client)
    result = await service.plan(
        cve=log4shell_core,
        behavior=None,
        telemetry=log4shell_telemetry_plan,
    )

    assert isinstance(result, Step6Result)
    assert result.cve_id == "CVE-2021-44228"
    assert len(result.detections) == 3
    assert [d.id for d in result.detections] == ["rule_1", "rule_2", "rule_3"]
    assert len(result.correlations) == 1
    assert result.correlations[0].rule.correlation.rules == ["rule_1", "rule_2", "rule_3"]

    # Per-detection sanity: each selection's field/modifier must be in Step 4 search space.
    space_by_ls = {
        (ls.category, ls.product): ls.allowed_fields
        for ls in log4shell_telemetry_plan.sigma_logsources
    }
    for det in result.detections:
        ls_key = (det.rule.logsource.category, det.rule.logsource.product)
        allowed_fields = space_by_ls[ls_key]
        for sel in det.rule.detection.selection:
            assert sel.name in allowed_fields, f"field {sel.name} not in {allowed_fields}"
            if sel.modifier is not None:
                assert sel.modifier in allowed_fields[sel.name], (
                    f"modifier {sel.modifier} not in {allowed_fields[sel.name]}"
                )

    # Validator runs as part of `.plan()` — if it didn't raise, this test passes.


async def _log4shell_minimum_subset_1_detection(log4shell_telemetry_plan, log4shell_core, stub_client):
    """MINIMUM SUBSET philosophy: 1 detection is also valid (CVE reachable via
    webserver only)."""
    minimal_response = {
        "detections": [
            {
                "id": "rule_1",
                "rule": {
                    "description": "JNDI lookup in webserver URI (only signal)",
                    "logsource": {"category": "webserver", "product": None},
                    "detection": {
                        "selection": [
                            {"name": "cs-uri-query", "modifier": "contains", "value": "${jndi:",
                             "reason": "JNDI lookup substring is the unique signature of Log4Shell initial-access payload."}
                        ],
                        "condition": "selection",
                    },
                    "falsepositives": [],
                    "level": "high",
                },
            }
        ],
        "correlations": [],
        "reasoning": "Single-logsource detection: webserver JNDI lookup substring is the sole meaningful signal.",
    }
    stub_client.next_response = json.dumps(minimal_response)

    service = SigmaRuleAI(ai_client=stub_client)
    result = await service.plan(
        cve=log4shell_core,
        behavior=None,
        telemetry=log4shell_telemetry_plan,
    )

    assert len(result.detections) == 1
    assert result.detections[0].id == "rule_1"
    assert result.correlations == []


def test_log4shell_3_detections_pass_validator(log4shell_telemetry_plan, log4shell_core, stub_client):
    run_async(_log4shell_3_detections_pass_validator(
        log4shell_telemetry_plan, log4shell_core, stub_client
    ))


def test_log4shell_minimum_subset_1_detection(log4shell_telemetry_plan, log4shell_core, stub_client):
    run_async(_log4shell_minimum_subset_1_detection(
        log4shell_telemetry_plan, log4shell_core, stub_client
    ))
