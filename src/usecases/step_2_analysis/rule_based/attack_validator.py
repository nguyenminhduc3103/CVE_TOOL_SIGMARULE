"""ATT&CK Validator - Simple validation for tactics/techniques/subtechniques.

Returns list of invalid TTPs. Empty list = all valid.
Validates against TTP_mapping.json.
"""
from __future__ import annotations

import json
from pathlib import Path


_MAPPING_FILE = Path(__file__).resolve().parents[4] / "TTPs_mapping.json"
_mapped: dict | None = None


def _get_mapping() -> dict:
    """Load TTP mapping (singleton)."""
    global _mapped
    if _mapped is None:
        if _MAPPING_FILE.exists():
            with open(_MAPPING_FILE, "r", encoding="utf-8") as f:
                _mapped = json.load(f)
        else:
            _mapped = {}
    return _mapped


def validate_attack_mapping(
    tactics: list[str] | None,
    techniques: list[str] | None,
    subtechniques: list[str] | None = None,
) -> list[str]:
    """Validate TTPs against TTP_mapping.json. Return list of invalid ones."""
    mapping = _get_mapping()
    valid_tactics = {v.get("tactic_id") for v in mapping.values() if v.get("tactic_id")}
    valid_techniques = set(mapping.keys())

    invalid: list[str] = []

    # Validate tactics
    for t in tactics or []:
        normalized = _normalize(t)
        if normalized and normalized not in valid_tactics:
            invalid.append(normalized)

    # Validate techniques
    for t in techniques or []:
        normalized = _normalize(t)
        if normalized and normalized not in valid_techniques:
            invalid.append(normalized)

    # Validate subtechniques - check children of each technique
    for t in subtechniques or []:
        normalized = _normalize(t)
        if normalized:
            is_valid_sub = False
            for tech in mapping.values():
                if normalized in tech.get("children", {}):
                    is_valid_sub = True
                    break
            if not is_valid_sub:
                invalid.append(normalized)

    return invalid


def _normalize(value: str) -> str | None:
    """Normalize ID to uppercase."""
    if not isinstance(value, str):
        return None
    text = value.strip().upper()
    if text.startswith("ATTACK."):
        text = text[7:]
    return text or None
