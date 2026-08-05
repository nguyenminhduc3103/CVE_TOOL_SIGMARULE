"""Deterministic UUID v5 helpers for Sigma rule IDs.

UUIDs derive only from (cve_id, rule_id) — never from title or description,
so AI rewrites of metadata don't change rule identity.
"""
from __future__ import annotations

import uuid

SIGMA_NAMESPACE = uuid.NAMESPACE_URL


def rule_uuid(cve_id: str, rule_id: str) -> str:
    """Deterministic UUID for a detection rule: uuid5(NAMESPACE_URL, f"{cve_id}:{rule_id}")."""
    return str(uuid.uuid5(SIGMA_NAMESPACE, f"{cve_id}:{rule_id}"))


def correlation_uuid(cve_id: str, index: int) -> str:
    """Deterministic UUID for a correlation rule: uuid5(NAMESPACE_URL, f"{cve_id}:correlation_{index}").

    index is the 1-based position in the correlations list.
    """
    return str(uuid.uuid5(SIGMA_NAMESPACE, f"{cve_id}:correlation_{index}"))


__all__ = ["SIGMA_NAMESPACE", "rule_uuid", "correlation_uuid"]
