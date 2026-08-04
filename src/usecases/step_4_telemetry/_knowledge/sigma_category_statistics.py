# Sigma category statistics — typed loader for `sigma_category_statistics.json`.
#
# Data-driven knowledge: each Sigma logsource category carries its own
# `products`, `services`, and `fields` facts. The resolver consumes only
# `products`, but Step 6 (and any future consumer) gets the full structure
# from a single load — no re-reading the JSON.
#
# Single source of truth: <repo_root>/sigma_category_statistics.json
from __future__ import annotations

import functools
import json
from pathlib import Path
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr


# Project root is four levels up from this file:
#   _knowledge/ -> step_4_telemetry/ -> usecases/ -> src/ -> repo_root.
_DEFAULT_STATS_PATH = Path(__file__).resolve().parents[4] / "sigma_category_statistics.json"


class SigmaFieldStats(BaseModel):
    """Per-field occurrence stats in the SigmaHQ corpus."""

    model_config = ConfigDict(frozen=True)

    count: int = Field(ge=0)
    operators: list[str] = Field(default_factory=list)


class SigmaCategoryInfo(BaseModel):
    """Per-category facts pulled from `sigma_category_statistics.json`.

    Schema mirrors the JSON file 1:1:
      - `platforms`  → operating-system / cloud vendors that produce this
                       category's events (e.g. windows, linux, macos, aws).
                       Empty list = category is platform-agnostic
                       (e.g. webserver, proxy, application).
      - `technologies` → vendor/framework names associated with this category
                         (e.g. django, jvm, kubernetes under `application`).
      - `services`   → service-layer names (rare; only `application` uses it).
      - `fields`     → per-field Sigma match operator stats.
    """

    model_config = ConfigDict(frozen=True)

    platforms: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    fields: dict[str, SigmaFieldStats] = Field(default_factory=dict)


class SigmaCategoryStatistics(BaseModel):
    """All Sigma logsource categories and their facts.

    Lookup API is `knowledge.get(category) -> SigmaCategoryInfo | None`.
    Plain attribute access on the returned `SigmaCategoryInfo` gives
    `info.products`, `info.services`, `info.fields`.
    """

    model_config = ConfigDict(frozen=True)

    _categories: dict[str, SigmaCategoryInfo] = PrivateAttr(default_factory=dict)

    def __init__(self, categories: dict[str, SigmaCategoryInfo] | None = None) -> None:
        super().__init__()
        # PrivateAttr is set after super().__init__ to keep frozen semantics.
        object.__setattr__(self, "_categories", dict(categories or {}))

    @classmethod
    def from_dict(cls, data: dict[str, dict]) -> Self:
        """Build directly from a plain dict — used by tests."""
        return cls(
            categories={
                name: SigmaCategoryInfo.model_validate(payload)
                for name, payload in data.items()
            }
        )

    @classmethod
    def from_json(cls, path: Path | str) -> Self:
        """Read and parse the JSON file at `path`."""
        text = Path(path).read_text(encoding="utf-8")
        return cls.from_dict(json.loads(text))

    def get(self, category: str) -> SigmaCategoryInfo | None:
        """Return the info for `category`, or None if unknown."""
        return self._categories.get(category)

    def __contains__(self, category: object) -> bool:
        return isinstance(category, str) and category in self._categories

    def categories(self) -> list[str]:
        """Sorted list of all known categories (test/debug use)."""
        return sorted(self._categories)


@functools.lru_cache(maxsize=1)
def _load_raw(path: str = str(_DEFAULT_STATS_PATH)) -> SigmaCategoryStatistics:
    """Read + parse the JSON once per process (path-keyed cache for tests)."""
    return SigmaCategoryStatistics.from_json(path)


def load_statistics(path: Path | str | None = None) -> SigmaCategoryStatistics:
    """Singleton accessor. `path` is honored on first call only (LRU-cached).

    Mirrors `load_telemetry_concepts()` in `_knowledge/loader.py`.
    """
    if path is None:
        return _load_raw()
    return _load_raw(str(path))


def invalidate_cache() -> None:
    """Clear the LRU cache (test-only)."""
    _load_raw.cache_clear()