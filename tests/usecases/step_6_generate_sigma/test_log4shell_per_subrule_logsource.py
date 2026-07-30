"""Regression test: each sub-rule in a correlation set gets its own logsource.

Before the fix, ``_pick_logsource`` was called once and the same dict was
stamped onto every sub-rule + the parent — so the webserver intent was
mislabeled ``process_creation/windows``.

For Log4Shell we expect:
  - sub-rule 0 (jndi_payload_lookup)  -> logsource.category == 'webserver'
  - sub-rule 1 (outbound_ldap_rmi)    -> logsource.category == 'network_connection'
  - parent rule                        -> action: correlation
"""
from __future__ import annotations

import yaml as pyyaml

from src.usecases.step_6_generate_sigma.builders.sigma_builder import build_sigma_rule


def _load_yaml_docs(yaml_text: str) -> list[dict]:
    return [doc for doc in pyyaml.safe_load_all(yaml_text) if doc]


def test_log4shell_subrules_have_own_logsource(
    log4shell_plan,
    core_cve,
    log4shell_analysis,
    log4shell_attack,
    log4shell_telemetry,
):
    _rules, yaml_output, _level = build_sigma_rule(
        plan=log4shell_plan,
        core=core_cve,
        analysis=log4shell_analysis,
        attack=log4shell_attack,
        telemetry=log4shell_telemetry,
        family_signature="log4shell",
    )

    docs = _load_yaml_docs(yaml_output)
    assert len(docs) >= 3, f"Expected 2 sub-rules + 1 parent, got {len(docs)}"

    subrule_docs = [d for d in docs if d.get("action") != "correlation"]
    parent_docs = [d for d in docs if d.get("action") == "correlation"]
    assert len(subrule_docs) == 2, f"Expected 2 sub-rules, got {len(subrule_docs)}"
    assert len(parent_docs) == 1, f"Expected 1 parent, got {len(parent_docs)}"

    # Sub-rule 0: inbound JNDI payload — webserver
    assert subrule_docs[0]["logsource"]["category"] == "webserver", (
        f"Sub-rule 0 should be webserver, got {subrule_docs[0]['logsource']}"
    )

    # Sub-rule 1: outbound LDAP/RMI — network_connection
    assert subrule_docs[1]["logsource"]["category"] == "network_connection", (
        f"Sub-rule 1 should be network_connection, got {subrule_docs[1]['logsource']}"
    )

    # Parent rule has correlation block referencing both sub-rule IDs
    parent = parent_docs[0]
    assert "correlation" in parent
    assert "rules" in parent["correlation"]
    assert len(parent["correlation"]["rules"]) == 2
