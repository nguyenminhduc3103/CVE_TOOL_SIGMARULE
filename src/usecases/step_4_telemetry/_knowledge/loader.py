# YAML knowledge base loader with LRU cache; tests call invalidate_cache() to reload from disk.
from __future__ import annotations

import functools
from pathlib import Path
from typing import Any

import yaml

_KB_DIR = Path(__file__).parent


@functools.lru_cache(maxsize=1)
def load_telemetry_domains() -> dict[str, Any]:
    """18 canonical semantic domains (identity, process, network, ...)."""
    return _load_yaml("telemetry_domains.yaml")


@functools.lru_cache(maxsize=1)
def load_canonical_telemetry() -> dict[str, Any]:
    """Domain × execution_surface × vendor → Canonical Telemetry list."""
    return _load_yaml("canonical_telemetry.yaml")


@functools.lru_cache(maxsize=1)
def load_canonical_fields() -> dict[str, Any]:
    """Canonical field names + backend aliases (sigma/ecs/splunk/sentinel)."""
    return _load_yaml("canonical_fields.yaml")


@functools.lru_cache(maxsize=1)
def load_vendor_profiles() -> dict[str, Any]:
    """Vendor detection coverage matrix."""
    return _load_yaml("vendor_profiles.yaml")


def _load_yaml(filename: str) -> dict[str, Any]:
    path = _KB_DIR / filename
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if data is None:
        return {}
    return data


def invalidate_cache() -> None:
    """Reset all cached KB — dùng trong tests khi fixtures thay đổi."""
    load_telemetry_domains.cache_clear()
    load_canonical_telemetry.cache_clear()
    load_canonical_fields.cache_clear()
    load_vendor_profiles.cache_clear()