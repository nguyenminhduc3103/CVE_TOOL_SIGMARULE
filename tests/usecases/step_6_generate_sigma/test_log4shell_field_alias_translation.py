"""Regression test: ``selection_hint`` keys are translated via Step 4 ``field_name_map``.

For Log4Shell we expect:
  - ``Uri|contains`` -> ``cs-uri-stem|contains``  (alias + modifier preserved)
  - ``cs_uri_query|contains`` -> ``cs-uri-stem|contains`` (canonical form alias)
  - ``DestinationPort`` passes through (already a Sigma field)
"""
from __future__ import annotations

import yaml as pyyaml

from src.usecases.step_6_generate_sigma.builders.sigma_builder import build_sigma_rule


def _load_subrule_detections(yaml_text: str) -> list[dict]:
    docs = [d for d in pyyaml.safe_load_all(yaml_text) if d]
    return [d for d in docs if d.get("action") != "correlation"]


def test_uri_field_translated_with_modifier(
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

    subrules = _load_subrule_detections(yaml_output)
    assert len(subrules) == 2

    # Sub-rule 0 has the inbound payload selection. Both keys should collapse
    # to the same Sigma field via field_name_map.
    sel0 = subrules[0]["detection"]["sel_0"]
    assert "cs-uri-stem|contains" in sel0, f"Missing translated field; got keys: {list(sel0)}"
    assert "jndi:" in sel0["cs-uri-stem|contains"]

    # Both original keys ("request_uri|contains" canonical + "cs_uri_stem|contains"
    # alias) should collapse to a single cs-uri-stem|contains entry.
    assert "request_uri|contains" not in sel0, "Canonical key should be aliased"
    # Both lists of values should be merged under the single translated key.
    all_values = sel0["cs-uri-stem|contains"]
    assert any("jndi:" in v for v in all_values)
    assert any("${${lower:j}ndi:" in v for v in all_values)

    # Sub-rule 1: DestinationPort values preserved verbatim (YAML coerces to ints).
    sel1 = subrules[1]["detection"]["sel_1"]
    assert "DestinationPort" in sel1
    assert sorted(int(v) for v in sel1["DestinationPort"]) == [389, 636, 1099]


def test_resolve_intent_field_alias_unit():
    """Direct unit test on the helper — case-insensitive, modifier preserved, idempotent."""
    from src.usecases.step_6_generate_sigma.builders.sigma_builder import (
        _resolve_intent_field_alias,
    )

    # Realistic Step 4 field_name_map: canonical key + aliases with mixed case.
    fnm = {
        "request_uri": "cs-uri-stem",
        "cs_uri_stem": "cs-uri-stem",      # canonical-derived entries
        "destination_port": "DestinationPort",
        "Image": "Image",                   # alias
        "image": "Image",                   # lower-cased alias
    }

    # Plain key with alias
    assert _resolve_intent_field_alias("request_uri", fnm) == "cs-uri-stem"

    # Already Sigma form -> idempotent
    assert _resolve_intent_field_alias("cs-uri-stem", fnm) == "cs-uri-stem"

    # Canonical name resolves to Sigma backend name
    assert _resolve_intent_field_alias("destination_port", fnm) == "DestinationPort"

    # Modifier preserved through alias
    assert _resolve_intent_field_alias("request_uri|contains", fnm) == "cs-uri-stem|contains"

    # Unknown key passthrough
    assert _resolve_intent_field_alias("Bogus|endswith", fnm) == "Bogus|endswith"

    # Built-in fallback: common vendor names that Step 4 may not have mapped
    # translate via the built-in alias table.
    assert _resolve_intent_field_alias("Uri", None) == "cs-uri-stem"
    assert _resolve_intent_field_alias("Uri|contains", {}) == "cs-uri-stem|contains"
    assert _resolve_intent_field_alias("DestinationPort", {}) == "DestinationPort"
    assert _resolve_intent_field_alias("Image", {}) == "Image"

    # Truly unknown key still passes through.
    assert _resolve_intent_field_alias("Totally|Made|Up", None) == "Totally|Made|Up"
