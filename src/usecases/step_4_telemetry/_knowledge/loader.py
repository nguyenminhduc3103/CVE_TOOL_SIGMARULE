# Telemetry concept ontology loader. LRU-cached — YAML read at most once per process.
from __future__ import annotations

import functools
from pathlib import Path

import yaml


_KB_PATH = Path(__file__).parent / "telemetry_concepts.yaml"


@functools.lru_cache(maxsize=1)
def _load_raw() -> dict:
    """Read + parse the YAML once per process."""
    return yaml.safe_load(_KB_PATH.read_text(encoding="utf-8"))


def load_telemetry_concepts() -> dict[str, list[str]]:
    """Return {group_name: [concept_name, ...]} mapping from the KB YAML."""
    raw = _load_raw()
    return {
        group["name"]: list(group["concepts"])
        for group in raw.get("groups", [])
    }


@functools.lru_cache(maxsize=1)
def load_concept_to_group() -> dict[str, str]:
    """Return flat {concept_name: group_name} mapping for validator whitelist."""
    raw = _load_raw()
    mapping: dict[str, str] = {}
    for group in raw.get("groups", []):
        group_name = group["name"]
        for concept in group["concepts"]:
            mapping[concept] = group_name
    return mapping


def is_valid_concept(concept: str) -> bool:
    """Quick check whether `concept` is in the KB whitelist."""
    return concept in load_concept_to_group()