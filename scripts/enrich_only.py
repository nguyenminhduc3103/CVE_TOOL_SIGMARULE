"""Step 1 ONLY — chỉ enrichment (NVD + KEV + EPSS), KHÔNG gọi AI, KHÔNG analysis.

In đầy đủ tất cả các trường của Step 1:
- CoreCVEData (NVD)
- TriageContext (KEV + EPSS)
- Capability assessment + priority + decision (tính từ rule-based)

Dùng để verify Step 1 chạy đúng trước khi chạy full pipeline (Step 1+2+3+4).

Run: python -X utf8 scripts/enrich_only.py CVE-2021-44228
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.shared.models.triage import TriageContext
from app.shared.providers.nvd.provider import NVDProvider
from app.shared.providers.kev.provider import KEVProvider
from app.shared.providers.epss.provider import EPSSProvider
from app.shared.providers.poc.provider import PoCProvider
from app.steps.step_1_triage.priority_engine import PriorityEngine
from app.steps.step_1_triage.capability_checker import CapabilityChecker


def _print_list(items, indent: str = "    ", none_label: str = "none") -> None:
    if not items:
        print(f"{indent}- {none_label}")
        return
    for item in items:
        print(f"{indent}- {item}")


async def enrich(cve_id: str) -> None:
    print("=" * 80)
    print(f" STEP 1 ONLY (ENRICH) — {cve_id}")
    print("=" * 80)

    t0 = time.perf_counter()
    nvd = NVDProvider()
    kev = KEVProvider()
    epss = EPSSProvider()
    poc = PoCProvider()

    # ---- NVD ----
    print("\n[NVD] fetching...")
    core = await nvd.enrich(cve_id)
    print(f"  ✓ {cve_id} fetched ({len(core.references or [])} refs, {len(core.cpes or [])} cpes)")

    print("\n" + "=" * 80)
    print("[CORE - CoreCVEData]")
    print("=" * 80)
    print(f"  cve_id:         {core.cve_id}")
    print(f"  severity:       {core.severity}")
    print(f"  cvss_score:     {core.cvss_score}")
    print(f"  cvss_vector:    {core.cvss_vector}")
    print(f"  cwe_ids:        {core.cwe_ids or []}")
    print(f"  published_at:   {core.published_at.isoformat() if core.published_at else None}")
    print(f"  modified_at:    {core.modified_at.isoformat() if core.modified_at else None}")
    print(f"  description:")
    desc = (core.description or "").strip()
    if desc:
        for line in desc.splitlines():
            print(f"    {line}")
    else:
        print("    (empty)")
    print(f"  references ({len(core.references or [])}):")
    _print_list(core.references or [])
    print(f"  cpes ({len(core.cpes or [])}):")
    _print_list(core.cpes or [])

    # ---- KEV ----
    print("\n[KEV] fetching...")
    kev_raw = await kev.enrich(cve_id)
    print(f"  ✓ done")

    # ---- EPSS ----
    print("\n[EPSS] fetching...")
    epss_raw = await epss.enrich(cve_id)
    print(f"  ✓ done")

    # ---- PoC ----
    print("\n[PoC] fetching...")
    poc_raw = await poc.enrich(cve_id)
    print(f"   done")

    # ---- Build TriageContext ----
    _poc_refs = poc_raw.get("poc_references") if poc_raw else None
    triage = TriageContext(
        in_kev=bool(kev_raw.get("in_kev")),
        kev_added_date=kev_raw.get("kev_added_date"),
        ransomware_usage=bool(kev_raw.get("known_ransomware_campaign_use", False)),
        epss_score=epss_raw.get("epss_score"),
        epss_percentile=epss_raw.get("epss_percentile"),
        poc_references=_poc_refs,
        public_poc=bool(_poc_refs),
    )

    # ---- Priority + Capability (rule-based) ----
    priority_engine = PriorityEngine()
    priority, score = await priority_engine.assess(core, triage)
    triage.priority = priority
    triage.priority_score = score

    capability_checker = CapabilityChecker()
    capability = await capability_checker.assess(core, triage)
    triage.capability_assessment = (
        capability.capability_classification.value
        if hasattr(capability, "capability_classification")
        else str(capability)
    )
    classification = capability_checker.classify(core)
    triage.decision = "GO" if classification.value == "in_scope" else "NO-GO"
    triage.decision_reason = (
        f"Capability assessment={classification.value} "
        f"(confidence_modifier={classification.confidence_modifier}); "
        f"{'proceed to technical analysis and rule generation.' if triage.decision == 'GO' else 'pipeline stops at triage; rule generation skipped.'}"
    )

    print("\n" + "=" * 80)
    print("[TRIAGE - TriageContext]")
    print("=" * 80)
    print(f"  in_kev:                 {triage.in_kev}")
    print(f"  kev_added_date:         {triage.kev_added_date.isoformat() if triage.kev_added_date else None}")
    print(f"  ransomware_usage:       {triage.ransomware_usage}")
    print(f"  epss_score:             {triage.epss_score}")
    print(f"  epss_percentile:        {triage.epss_percentile}")
    print(f"  public_poc:             {triage.public_poc}")
    print(f"  observed_in_the_wild:   {triage.observed_in_the_wild}")
    print(f"  threat_actors:")
    _print_list(triage.threat_actors or [])
    print(f"  poc_references:")
    _print_list(triage.poc_references or [])
    print(f"  capability_assessment:  {triage.capability_assessment}")
    print(f"  priority:               {triage.priority}")
    print(f"  priority_score:         {triage.priority_score}")
    print(f"  decision:               {triage.decision}")
    print(f"  decision_reason:")
    print(f"    {triage.decision_reason}")

    duration_ms = int((time.perf_counter() - t0) * 1000)
    print("\n" + "=" * 80)
    print(f" Step 1 done in {duration_ms} ms — no AI, no analysis, no telemetry, no coverage.")
    print("=" * 80)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    asyncio.run(enrich(target))
