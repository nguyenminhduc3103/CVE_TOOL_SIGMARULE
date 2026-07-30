"""Stage: fetch nuclei-templates YAML evidence for a CVE.

Bypasses AI — calls tools.crawl_evidence.crawl(cve_id) directly.
Each pipeline run calls the upstream GitHub raw URL fresh (no cache).

NEVER raises — nuclei is a non-critical enhancement; any failure is
returned as status="error" so the orchestrator can log + continue.
"""
from __future__ import annotations

import logging
from typing import Any

from config.settings import settings
from tools.crawl_evidence import crawl as nuclei_crawl

logger = logging.getLogger(__name__)


def _dedup_refs(refs: list[Any]) -> list[Any]:
    """Deduplicate by URL. First occurrence wins; full ref object preserved."""
    seen: set[str] = set()
    out: list[Any] = []
    for r in refs or []:
        url = r.get("url") if isinstance(r, dict) else r
        if isinstance(url, str) and url and url not in seen:
            seen.add(url)
            out.append(r)
    return out


async def run_nuclei_crawl_stage(cve_id: str) -> dict:
    """Return a dict with status + evidence + references. NEVER raises.

    Behavior:
      * disabled → status="disabled" empty
      * else fetch via tools.crawl_evidence.crawl(cve_id), dedup refs
      * any error → return status="error" (do not raise)
    """
    if not settings.nuclei_crawl_enabled:
        return {
            "status": "disabled",
            "cve_id": cve_id,
            "evidence": [],
            "references": [],
            "error": None,
        }

    try:
        raw = await nuclei_crawl(
            cve_id,
            max_evidence=settings.nuclei_crawl_max_evidence,
        )
        return {
            "status": "success",
            "cve_id": raw["cve_id"],
            "evidence": raw.get("evidence", []),
            "references": _dedup_refs(raw.get("references", [])),
            "error": None,
        }
    except Exception as exc:                       # noqa: BLE001 — best-effort
        logger.warning("[nuclei_crawl] fetch failed for %s: %s", cve_id, exc)
        return {
            "status": "error",
            "cve_id": cve_id,
            "evidence": [],
            "references": [],
            "error": str(exc)[:200],
        }
