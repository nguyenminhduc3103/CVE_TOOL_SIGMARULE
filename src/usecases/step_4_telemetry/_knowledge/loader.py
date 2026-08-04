# Telemetry concept ontology loader. LRU-cached — YAML read at most once per process.
#
# Schema (post-rewrite):
#   telemetry_concept:
#     - antivirus
#     - application
#     - process_creation
#     ...
#
# All 35 concepts live in a single flat list. Group classification
# (PROCESS / FILE / NETWORK / ...) is decided downstream by the AI
# service using the system-prompt ontology, NOT stored here. This keeps
# the KB a single flat whitelist with no redundancy.
from __future__ import annotations

import functools
from pathlib import Path

import yaml


_KB_PATH = Path(__file__).parent / "telemetry_concepts.yaml"

# Concepts in the whitelist that don't naturally fit a process / file /
# network / etc. group are bucketed into a single sentinel group. This
# preserves the `{group: [concepts]}` shape of `load_telemetry_concepts`
# while honouring the new flat-list YAML.
_DEFAULT_GROUP = "TELEMETRY"


@functools.lru_cache(maxsize=1)
def _load_raw() -> list[str]:
    """Read + parse the YAML once per process. Returns flat concept list."""
    raw = yaml.safe_load(_KB_PATH.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        # New schema: {"telemetry_concept": [concept, ...]}.
        return list(raw.get("telemetry_concept", []))
    if isinstance(raw, list):
        return list(raw)
    return []


def load_telemetry_concepts() -> dict[str, list[str]]:
    """Return {group_name: [concept_name, ...]} mapping from the KB YAML.

    Flat-list schema → all concepts live under a single group. Callers
    expecting group-level granularity should iterate `load_concept_to_group()`
    instead.
    """
    return {_DEFAULT_GROUP: list(_load_raw())}


@functools.lru_cache(maxsize=1)
def load_concept_to_group() -> dict[str, str]:
    """Return flat {concept_name: group_name} mapping for validator whitelist."""
    return {concept: _DEFAULT_GROUP for concept in _load_raw()}


def is_valid_concept(concept: str) -> bool:
    """Quick check whether `concept` is in the KB whitelist."""
    return concept in load_concept_to_group()


def invalidate_cache() -> None:
    """Clear the LRU cache (test-only)."""
    _load_raw.cache_clear()
    load_concept_to_group.cache_clear()