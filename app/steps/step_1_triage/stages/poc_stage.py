"""Stage wrapper for PoC enrichment — pass-through (enrichment done at provider layer)."""
from __future__ import annotations


async def run_poc_stage(cve_id: str, poc_raw: dict) -> dict:
    """Return the PoC provider output as-is into the pipeline."""
    return poc_raw
