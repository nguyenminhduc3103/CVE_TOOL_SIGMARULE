"""CLI: download / refresh MITRE ATT&CK STIX bundle.

Usage:
    python -m src.shared.mitre.fetch_stix             # download if missing/stale
    python -m src.shared.mitre.fetch_stix --force     # always re-download

After download, run a smoke import to verify parsing:
    python -c "from src.shared.mitre.loader import MitreAttackWhitelist; \
        w = MitreAttackWhitelist.get(); \
        print(f'{len(w.tactics)} tactics, {len(w.techniques)} techniques, {len(w.subtechniques)} subtechniques')"
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# Allow `python -m src.shared.mitre.fetch_stix` to bootstrap sys.path.
_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from config.settings import settings  # noqa: E402
from src.shared.mitre.loader import (  # noqa: E402
    _ENTERPRISE_ATTACK_URL,
    _HTTP_TIMEOUT,
    _USER_AGENT,
    MitreAttackWhitelist,
)

logger = logging.getLogger("mitre.fetch_stix")


def _download(url: str, dest: Path) -> bool:
    """Atomic download URL → dest. Returns True on success."""
    try:
        import httpx
    except ImportError:
        logger.error("httpx not installed; cannot download")
        return False

    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = dest.with_suffix(dest.suffix + ".tmp")
        logger.info("Downloading %s → %s", url, dest)
        with httpx.Client(
            timeout=_HTTP_TIMEOUT,
            follow_redirects=True,
            headers={"User-Agent": _USER_AGENT},
        ) as client:
            with client.stream("GET", url) as response:
                response.raise_for_status()
                with open(tmp_path, "wb") as out:
                    for chunk in response.iter_bytes(chunk_size=64 * 1024):
                        out.write(chunk)
        # Atomic rename (POSIX) / replace (Windows) to avoid partial files.
        import os
        os.replace(tmp_path, dest)
        size_mb = dest.stat().st_size / (1024 * 1024)
        logger.info("OK: %s (%.2f MB)", dest, size_mb)
        return True
    except Exception as exc:
        logger.error("FAILED: %s — %s", url, exc)
        tmp_path = dest.with_suffix(dest.suffix + ".tmp")
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except OSError:
            pass
        return False


def _validate_stix_attack(path: Path) -> bool:
    """Sanity check: parse + count techniques/tactics. Logs warnings on oddities."""
    try:
        with open(path, encoding="utf-8") as f:
            bundle = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("Invalid JSON: %s — %s", path, exc)
        return False
    objects = bundle.get("objects") if isinstance(bundle, dict) else None
    if not isinstance(objects, list) or not objects:
        logger.error("Empty or missing 'objects' list in %s", path)
        return False

    # Count attack-pattern objects
    n_attack_pattern = sum(
        1 for o in objects if isinstance(o, dict) and o.get("type") == "attack-pattern"
    )
    if n_attack_pattern < 100:
        logger.warning(
            "Only %d attack-pattern objects in %s (expected 500+). Bundle may be incomplete.",
            n_attack_pattern, path,
        )
        return False
    logger.info("Validated: %d attack-pattern objects in %s", n_attack_pattern, path)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Download / refresh MITRE ATT&CK STIX bundle"
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Re-download even if cache is fresh",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable DEBUG logging",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )

    cache_dir = Path(settings.mitre_cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)

    dest = cache_dir / "enterprise-attack.json"
    if not args.force and dest.exists():
        import time
        age_days = (time.time() - dest.stat().st_mtime) / 86400
        logger.info(
            "ATT&CK cache exists (age=%.1f days, ttl=%d days) — skipping (use --force to override)",
            age_days, settings.mitre_cache_ttl_seconds // 86400,
        )
    else:
        if _download(_ENTERPRISE_ATTACK_URL, dest):
            if not _validate_stix_attack(dest):
                return 1
        else:
            return 1

    # Verify loader can parse what we just downloaded.
    try:
        MitreAttackWhitelist.reset()
        wl = MitreAttackWhitelist.get()
        print(
            f"OK: {len(wl.tactics)} tactics, {len(wl.techniques)} techniques, "
            f"{len(wl.subtechniques)} subtechniques "
            f"(source={wl.source}, baseline_fallback={wl.is_baseline_fallback})"
        )
    except Exception as exc:
        logger.error("Loader smoke-test failed: %s", exc)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())