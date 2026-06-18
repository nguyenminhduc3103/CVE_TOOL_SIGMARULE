"""File-based response cache for CVE provider HTTP calls.

Stdlib-only (json, os, time) — no Redis, no SQLite. Cache entries are JSON
files keyed by (provider, key). TTL is enforced via file mtime; on miss or
expired entry we leave the stale file alone and overwrite atomically via
`.tmp` + rename.

Failures (429 / 503 / Cloudflare blocks) are cached for a short 60s window
so the pipeline doesn't hammer a struggling upstream while still recovering
quickly when the upstream heals.
"""
from __future__ import annotations

import json
import os
import threading
import time
from typing import Any

from app.core.config import settings


# Short TTL for transient failures (429 / 503 / Cloudflare) so we don't
# pound a struggling upstream, but recover quickly when it heals.
FAILURE_TTL_SECONDS = 60


def _cache_enabled() -> bool:
    """Cache is on by default; CVE_TI_CACHE=0 disables it (for tests)."""
    if os.environ.get("CVE_TI_CACHE") == "0":
        return False
    return bool(getattr(settings, "cache_enabled", True))


class ResponseCache:
    """Per-(provider, key) JSON file cache with TTL."""

    def __init__(
        self,
        cache_dir: str | None = None,
        ttl_seconds: int | None = None,
    ) -> None:
        self._cache_dir = cache_dir or getattr(
            settings, "cache_dir", ".cache/cve_responses"
        )
        self._default_ttl = ttl_seconds if ttl_seconds is not None else int(
            getattr(settings, "cache_ttl_seconds", 86400)
        )
        self._lock = threading.Lock()
        os.makedirs(self._cache_dir, exist_ok=True)

    # ---------- public API ----------

    def get(self, provider: str, key: str) -> Any | None:
        """Return cached payload if present and fresh, else None."""
        if not _cache_enabled():
            return None
        path = self._path_for(provider, key)
        if not os.path.exists(path):
            return None
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return None
        # File-system mtime gives us cheap TTL — no need to re-open the file.
        if (time.time() - mtime) > self._default_ttl:
            return None
        try:
            with open(path, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, json.JSONDecodeError):
            # Corrupt cache file — treat as miss so the caller re-fetches.
            return None
        return payload

    def set(
        self,
        provider: str,
        key: str,
        data: Any,
        ttl_seconds: int | None = None,
    ) -> None:
        """Atomically write payload to disk with given TTL."""
        if not _cache_enabled():
            return
        path = self._path_for(provider, key)
        tmp_path = f"{path}.tmp"
        # ttl_seconds overrides per-call; defaults to instance default. We
        # still write the file with current mtime so the TTL check on read
        # works without per-entry metadata parsing.
        with self._lock:
            try:
                with open(tmp_path, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, ensure_ascii=False, default=str)
                os.replace(tmp_path, path)
                # Touch mtime when caller passes a custom (typically short)
                # TTL so the read-side check (now - mtime > ttl) behaves
                # as expected — i.e. the entry expires after `ttl_seconds`
                # from this write, not after the default 24h.
                if ttl_seconds is not None and ttl_seconds != self._default_ttl:
                    target_age = max(0.0, float(self._default_ttl) - float(ttl_seconds))
                    new_mtime = time.time() - target_age
                    try:
                        os.utime(path, (new_mtime, new_mtime))
                    except OSError:
                        pass
            except OSError:
                # Cache write failure shouldn't break the pipeline — just
                # skip caching and let the caller proceed.
                try:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                except OSError:
                    pass

    def clear(self, provider: str, key: str) -> None:
        """Remove a single cache entry. Missing files are fine."""
        if not _cache_enabled():
            return
        path = self._path_for(provider, key)
        with self._lock:
            try:
                os.remove(path)
            except OSError:
                pass

    def is_enabled(self) -> bool:
        return _cache_enabled()

    # ---------- internals ----------

    def _path_for(self, provider: str, key: str) -> str:
        # Keep filenames filesystem-safe; replace path separators and other
        # punctuation that would break some OSes (Windows forbids : * ? " < > |).
        safe_key = "".join(
            ch if (ch.isalnum() or ch in ("-", "_", ".")) else "_"
            for ch in key
        )
        return os.path.join(self._cache_dir, f"{provider}__{safe_key}.json")
