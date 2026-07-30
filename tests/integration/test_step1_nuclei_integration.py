"""Run Step 1 (Triage) for a CVE — nuclei crawl auto-fires in the fan-out.

CLI mirrors `main.py`: pass `--cve CVE-XXXX-YYYY` (default CVE-2026-0926).
The nuclei evidence JSON is written to `.cache/nuclei_evidence/{cve_id}.json`
(delete to refetch).

Requires the same API keys / network access as `main.py --cve`:
  NVD_API_KEY, optional KE/EPSS/OTX (or run without for partial data).

Run:
    python -X utf8 -m tests.integration.test_step1_nuclei_integration --cve CVE-2026-0926
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


DEFAULT_CVE = "CVE-2026-0926"


def _section(title: str) -> None:
    print("\n" + "=" * 80)
    print(f" {title}")
    print("=" * 80)


def wait_for_user(step: str) -> None:
    if os.getenv("CVE_TI_NONINTERACTIVE", "0").lower() in ("1", "true", "yes"):
        return
    print(f"\n👉 [ENTER] {step}")
    try:
        input()
    except EOFError:
        pass


async def _run_step1(cve_id: str) -> dict:
    from src.usecases.step_1_triage.orchestrator import TriageOrchestrator
    from src.adapters.presenters.cli_presenter import (
        print_step1_triage,
        print_metadata_footer,
    )

    orchestrator = TriageOrchestrator()
    enriched = await orchestrator.orchestrate(cve_id)
    print_step1_triage(enriched)
    print_metadata_footer(enriched, total_ms=int((time.perf_counter() - _t0) * 1000))
    return enriched.model_dump(mode="json")


async def _report_nuclei(cve_id: str) -> None:
    from config.settings import settings
    cache_path = Path(settings.nuclei_evidence_cache_dir) / f"{cve_id.lower()}.json"
    if not cache_path.exists():
        print(f"  [!] nuclei cache not written: {cache_path}")
        return
    data = json.loads(cache_path.read_text(encoding="utf-8"))
    _section(f"Nuclei cache: {cache_path}")
    print(f"  status     : {data['status']}")
    print(f"  cache_hit  : {data['metadata']['cache_hit']}")
    print(f"  evidence   : {len(data['evidence'])} records")
    for rec in data["evidence"]:
        if rec["type"] == "documentation":
            print(f"    - documentation: {rec['request'][:80]}...")
        else:
            ri = rec.get("request_info") or {}
            print(f"    - network     : {ri.get('method', '?')} {ri.get('path', '?')[:80]}")
    print(f"  references : {[r.get('url') if isinstance(r, dict) else r for r in data['references']]}")


_t0 = time.perf_counter()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run Step 1 (Triage) for a single CVE — nuclei crawl included."
    )
    parser.add_argument("--cve", default=DEFAULT_CVE, help="CVE id (default: CVE-2026-0926)")
    args = parser.parse_args()
    cve_id: str = args.cve

    if not re.match(r"^CVE-\d{4}-\d+$", cve_id, re.I):
        print(f"  [!] '{cve_id}' doesn't match CVE-YYYY-NNNN", flush=True)

    print("\n" + "#" * 80)
    print(f"# Step 1 (Triage) runner — {cve_id}")
    print("#" * 80)

    wait_for_user("run orchestrate()")
    enriched = asyncio.run(_run_step1(cve_id))

    wait_for_user("print nuclei cache report")
    asyncio.run(_report_nuclei(cve_id))

    print("\n" + "=" * 80)
    print(" DONE")
    print("=" * 80)


if __name__ == "__main__":
    main()