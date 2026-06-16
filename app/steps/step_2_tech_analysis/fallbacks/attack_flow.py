"""Fallback cho attack_flow 3 MANDATORY fields.

Khi AI trả null 2 fields (entry_vector, execution_mechanism), hoặc khi
cần derive rule-based từ vulnerability_class + exploit_vector + behaviors.

Single source of truth: app.services.ai.core.derivers
"""
from __future__ import annotations

from typing import Any

from app.shared.ai import (
    derive_attack_flow,
    fill_missing_attack_flow,
)


def apply_attack_flow_fallback(
    current: dict[str, Any] | None,
    exploit_vector: str | None = None,
    vulnerability_class: str | None = None,
    mandatory_behaviors: list[str] | None = None,
) -> dict[str, Any]:
    """Apply fallback cho 3 trường MANDATORY.

    Args:
        current: dict hiện tại (e.g. {"entry_vector": null, "execution_mechanism": "x", ...})
        exploit_vector: từ CVSS
        vulnerability_class: từ AI/rule-based
        mandatory_behaviors: từ AI/rule-based

    Returns:
        dict với 3 fields đầy đủ (entry_vector, execution_mechanism, observable_side_effects).
        Input KHÔNG bị mutate.
    """
    return fill_missing_attack_flow(
        current=current,
        exploit_vector=exploit_vector,
        vulnerability_class=vulnerability_class,
        mandatory_behaviors=mandatory_behaviors,
    )


def derive_from_scratch(
    exploit_vector: str | None = None,
    vulnerability_class: str | None = None,
    mandatory_behaviors: list[str] | None = None,
) -> dict[str, Any]:
    """Derive từ đầu (không có current). Wrapper cho derive_attack_flow."""
    return derive_attack_flow(
        exploit_vector=exploit_vector,
        vulnerability_class=vulnerability_class,
        mandatory_behaviors=mandatory_behaviors,
    )
