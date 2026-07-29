"""YAML knowledge base loader for Step 6 detection KB.

Module-level lru_cache; tests call `invalidate_cache()` between fixtures.
Mirrors step_4_telemetry/_knowledge/loader.py.
"""
from __future__ import annotations

import functools
from pathlib import Path
from typing import Any

import yaml

_KB_DIR = Path(__file__).parent


@functools.lru_cache(maxsize=1)
def load_detection_kb() -> dict[str, Any]:
    """Step 6 detection KB (families, signatures, behaviors, level_translation, ...)."""
    return _load_yaml("sigma_detection_kb.yaml")


def get_level_translation() -> dict[str, Any]:
    """Convenience accessor cho LevelResolver."""
    kb = load_detection_kb()
    return kb.get("level_translation", {}) or {}


def get_correlation_hints() -> dict[str, Any]:
    kb = load_detection_kb()
    return kb.get("correlation_hints", {}) or {}


def get_completeness_thresholds() -> dict[str, Any]:
    kb = load_detection_kb()
    return kb.get("completeness_thresholds", {}) or {}


def get_family(signature_or_family: str | None) -> dict[str, Any] | None:
    """Lookup family entry by signature or family slug."""
    if not signature_or_family:
        return None
    kb = load_detection_kb()
    families = kb.get("families", {}) or {}
    slug = signature_or_family.strip().lower().replace(".", "_").replace("-", "_")
    return families.get(slug) or families.get(signature_or_family)


def get_signature(name: str | None) -> dict[str, Any] | None:
    if not name:
        return None
    kb = load_detection_kb()
    sigs = kb.get("signatures", {}) or {}
    return sigs.get(name)


def get_behavior(name: str | None) -> dict[str, Any] | None:
    if not name:
        return None
    kb = load_detection_kb()
    behaviors = kb.get("behaviors", {}) or {}
    return behaviors.get(name)


def get_explanation_templates() -> dict[str, Any]:
    kb = load_detection_kb()
    return kb.get("explanation_templates", {}) or {}


def get_planner_confidence_thresholds() -> dict[str, Any]:
    kb = load_detection_kb()
    return kb.get("planner_confidence", {}) or {}


def _load_yaml(filename: str) -> dict[str, Any]:
    path = _KB_DIR / filename
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if data is None:
        return {}
    return data


def invalidate_cache() -> None:
    load_detection_kb.cache_clear()


__all__ = [
    "load_detection_kb",
    "get_level_translation",
    "get_correlation_hints",
    "get_completeness_thresholds",
    "get_family",
    "get_signature",
    "get_behavior",
    "get_explanation_templates",
    "get_planner_confidence_thresholds",
    "invalidate_cache",
]