from __future__ import annotations

import pytest

from src.usecases.step_2_analysis.rule_based import attack_validator


@pytest.fixture()
def mapping(monkeypatch):
    attack_validator._mapped = {
        "T1001": {"tactic_id": "TA0001", "children": {"T1001.001": {}, "T1001.002": {}}},
        "T2000": {"tactic_id": "TA0002", "children": {}},
    }
    yield attack_validator._mapped
    attack_validator._mapped = None


def test_validate_attack_mapping_accepts_valid_ids(mapping):
    invalid = attack_validator.validate_attack_mapping(
        tactics=["TA0001"],
        techniques=["T1001"],
        subtechniques=["T1001.001"],
    )

    assert invalid == []


@pytest.mark.parametrize(
    ("tactics", "techniques", "subtechniques", "expected"),
    [
        (["TA9999"], ["T1001"], ["T1001.001"], ["TA9999"]),
        (["TA0001"], ["T9999"], ["T1001.001"], ["T9999"]),
        (["TA0001"], ["T1001"], ["T9999"], ["T9999"]),
    ],
)
def test_validate_attack_mapping_rejects_invalid_entries(
    mapping,
    tactics,
    techniques,
    subtechniques,
    expected,
):
    invalid = attack_validator.validate_attack_mapping(tactics, techniques, subtechniques)

    assert invalid == expected


def test_validate_attack_mapping_ignores_non_string_and_empty_values(mapping):
    invalid = attack_validator.validate_attack_mapping(
        tactics=[None, "", " TA0001 "],
        techniques=[None, "", "T1001"],
        subtechniques=[None, "", "T1001.002"],
    )

    assert invalid == []


def test_validate_attack_mapping_handles_missing_mapping(monkeypatch):
    monkeypatch.setattr(attack_validator, "_mapped", {})

    invalid = attack_validator.validate_attack_mapping(["TA0001"], ["T1001"], ["T1001.001"])

    assert invalid == ["TA0001", "T1001", "T1001.001"]