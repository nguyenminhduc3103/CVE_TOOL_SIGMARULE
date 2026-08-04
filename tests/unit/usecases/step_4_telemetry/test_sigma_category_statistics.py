"""Tests for SigmaCategoryStatistics loader."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.usecases.step_4_telemetry import (
    SigmaCategoryInfo,
    SigmaCategoryStatistics,
    SigmaFieldStats,
    invalidate_statistics_cache,
    load_statistics,
)


def _fresh_knowledge() -> SigmaCategoryStatistics:
    """Build a small fixture matching the real JSON shape."""
    return SigmaCategoryStatistics.from_dict(
        {
            "webserver": {
                "platforms": [],
                "technologies": [],
                "services": [],
                "fields": {
                    "cs-method": {"count": 3, "operators": ["exact"]},
                },
            },
            "process_creation": {
                "platforms": ["windows", "linux", "macos"],
                "technologies": [],
                "services": [],
                "fields": {
                    "Image": {"count": 5, "operators": ["endswith", "exact"]},
                },
            },
            "application": {
                "platforms": [],
                "technologies": ["django", "jvm", "kubernetes"],
                "services": ["audit"],
                "fields": {},
            },
        }
    )


class TestFromDict:
    def test_returns_frozen_pydantic(self):
        k = _fresh_knowledge()
        assert isinstance(k, SigmaCategoryStatistics)
        info = k.get("webserver")
        assert isinstance(info, SigmaCategoryInfo)
        # `frozen=True` freezes outer model attribute assignment. Inner
        # mutable containers are still mutable, which is the Pydantic default —
        # we rely on the contract that callers don't mutate them.
        assert info.model_config.get("frozen") is True
        with pytest.raises(ValidationError):
            info.platforms = ["windows"]  # outer attribute assignment is forbidden

    def test_get_returns_none_for_unknown(self):
        k = _fresh_knowledge()
        assert k.get("does_not_exist") is None

    def test_membership(self):
        k = _fresh_knowledge()
        assert "webserver" in k
        assert "does_not_exist" not in k
        assert 42 not in k  # type: ignore[operator]

    def test_categories_sorted(self):
        k = _fresh_knowledge()
        assert k.categories() == ["application", "process_creation", "webserver"]


class TestFieldStats:
    def test_field_roundtrip(self):
        k = _fresh_knowledge()
        info = k.get("process_creation")
        assert info is not None
        image = info.fields["Image"]
        assert isinstance(image, SigmaFieldStats)
        assert image.count == 5
        assert image.operators == ["endswith", "exact"]


class TestLoadStatisticsRealFile:
    def test_real_file_loads_35_categories(self):
        invalidate_statistics_cache()
        k = load_statistics()
        assert len(k.categories()) == 35

    def test_real_webserver_is_global(self):
        invalidate_statistics_cache()
        k = load_statistics()
        webserver = k.get("webserver")
        assert webserver is not None
        assert webserver.platforms == []

    def test_real_process_creation_includes_linux(self):
        invalidate_statistics_cache()
        k = load_statistics()
        pc = k.get("process_creation")
        assert pc is not None
        assert "windows" in pc.platforms
        assert "linux" in pc.platforms

    def test_singleton_caches(self):
        invalidate_statistics_cache()
        first = load_statistics()
        second = load_statistics()
        assert first is second  # lru_cache hit