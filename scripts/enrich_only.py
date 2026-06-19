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

from app.core.config import settings
from app.shared.models.core import CoreCVEData
from app.shared.models.triage import TriageContext
from app.shared.providers.nvd.provider import NVDProvider
from app.shared.providers.kev.provider import KEVProvider
from app.shared.providers.epss.provider import EPSSProvider
from app.shared.providers.otx.provider import OTXProvider
from app.shared.providers.opencti import OpenCTIProvider
from app.steps.step_1_triage.priority_engine import PriorityEngine
from app.steps.step_1_triage.capability_checker import CapabilityChecker
from app.shared.parsers.cvss_parser import parse_cvss
from app.shared.parsers.reference_parser import extract_urls


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
    otx = OTXProvider()

    # ---- NVD ----
    print("\n[NVD] fetching...")
    try:
        core = await nvd.enrich(cve_id)
        print(f"  ✓ {cve_id} fetched ({len(core.references or [])} refs, {len(core.cpes or [])} cpes)")
    except Exception as exc:
        error_msg = next(iter(str(exc).splitlines()), type(exc).__name__)
        print(f"  ✗ NVD fetch failed: {error_msg}")
        core = CoreCVEData(cve_id=cve_id)

    # ---- KEV ----
    print("\n[KEV] fetching...")
    kev_raw = await kev.enrich(cve_id)
    print(f"  ✓ done")

    # ---- EPSS ----
    print("\n[EPSS] fetching...")
    epss_raw = await epss.enrich(cve_id)
    print(f"  ✓ done")

    # ---- OTX ----
    print("\n[OTX] fetching...")
    otx_raw = await otx.enrich(cve_id)
    print(f"  ✓ done")

    # ---- Enrich Core CWEs from KEV if noinfo ----
    if not core.cwe_ids or core.cwe_ids == ["NVD-CWE-noinfo"]:
        if kev_raw and kev_raw.get("cwes"):
            core.cwe_ids = kev_raw.get("cwes")

    print("\n" + "=" * 80)
    print("[CORE - CoreCVEData]")
    print("=" * 80)
    print(f"  cve_id:         {core.cve_id}")
    print(f"  severity:       {core.severity}")
    print(f"  cvss_score:     {core.cvss_score}")
    print(f"  cvss_vector:    {core.cvss_vector}")
    if core.cvss_vector:
        try:
            details = parse_cvss(core.cvss_vector)
            print(f"    - Attack Vector (AV):   {details.get('attack_vector')}")
            print(f"    - Complexity (AC):      {details.get('attack_complexity')}")
            print(f"    - Privileges (PR/Au):   {details.get('privileges_required')}")
            print(f"    - User Interaction (UI):{details.get('user_interaction')}")
            print(f"    - Scope (S):            {details.get('scope')}")
            print(f"    - Confidentiality (C):  {details.get('confidentiality_impact')}")
            print(f"    - Integrity (I):        {details.get('integrity_impact')}")
            print(f"    - Availability (A):     {details.get('availability_impact')}")
        except Exception:
            pass
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

    # Extract and enrich reference URLs once
    enriched_refs = []
    if core.references:
        try:
            enriched_refs = extract_urls(core.references)
        except Exception:
            pass

    print(f"  references ({len(core.references or [])}):")
    if enriched_refs:
        for ref in enriched_refs:
            category = ref.get("category", "General Reference")
            url = ref.get("url", "")
            print(f"    - [{category}] {url}")
    elif core.references:
        _print_list(core.references)
    else:
        print("    - none")

    print(f"  cpes ({len(core.affected_products or [])}):")
    _print_list(core.affected_products or [])

    # Extract public PoC references using the already enriched references
    public_poc = False
    poc_references = []
    for ref in enriched_refs:
        if ref.get("is_exploit"):
            public_poc = True
            poc_references.append(ref.get("url"))

    # ---- Build TriageContext ----
    in_kev_val = bool(kev_raw.get("in_kev"))
    triage = TriageContext(
        in_kev=in_kev_val,
        kev_added_date=kev_raw.get("kev_added_date"),
        ransomware_usage=bool(kev_raw.get("known_ransomware_campaign_use", False)),
        observed_in_the_wild=in_kev_val,
        epss_score=epss_raw.get("epss_score"),
        epss_percentile=epss_raw.get("epss_percentile"),
        threat_actors=otx_raw.get("threat_actors", []),
        public_poc=public_poc,
        poc_references=poc_references or None,
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

    if classification.value != "in_scope":
        triage.decision = "NO-GO"
        triage.decision_reason = (
            f"Capability assessment={classification.value} (out of scope); "
            f"reason={classification.reasoning}. Pipeline stops at triage; "
            f"rule generation skipped (even with in_kev={triage.in_kev}, "
            f"epss_percentile={f'{triage.epss_percentile*100:.3f}%' if triage.epss_percentile is not None else 'None'}, "
            f"public_poc={triage.public_poc})."
        )
    else:
        if triage.in_kev is True:
            triage.decision = "GO"
            triage.decision_reason = (
                f"Capability assessment=in_scope, with active exploitation confirmed in CISA KEV. "
                f"Proceed to technical analysis with high priority (epss_percentile={f'{triage.epss_percentile*100:.3f}%' if triage.epss_percentile is not None else 'None'})."
            )
        elif triage.public_poc is True:
            triage.decision = "GO"
            triage.decision_reason = (
                f"Capability assessment=in_scope, and while in_kev is False/None, "
                f"a public PoC/exploit was detected in references. Proceed to technical analysis "
                f"(epss_percentile={f'{triage.epss_percentile*100:.3f}%' if triage.epss_percentile is not None else 'None'})."
            )
        else:
            triage.decision = "NO-GO"
            triage.decision_reason = (
                f"Capability assessment=in_scope, but no active threat or exploit detected "
                f"(in_kev={triage.in_kev}, epss_percentile={f'{triage.epss_percentile*100:.3f}%' if triage.epss_percentile is not None else 'None'}, "
                f"public_poc={triage.public_poc}). Pipeline stops at triage to conserve resources."
            )

    print("\n" + "=" * 80)
    print("[TRIAGE - TriageContext]")
    print("=" * 80)
    print(f"  in_kev:                 {triage.in_kev}")
    print(f"  kev_added_date:         {triage.kev_added_date.isoformat() if triage.kev_added_date else None}")
    print(f"  ransomware_usage:       {triage.ransomware_usage}")
    epss_score_str = f"{triage.epss_score:.5f} ({triage.epss_score * 100:.3f}%)" if triage.epss_score is not None else "None"
    epss_percentile_str = f"{triage.epss_percentile:.5f} ({triage.epss_percentile * 100:.3f}%)" if triage.epss_percentile is not None else "None"
    print(f"  epss_score:             {epss_score_str}")
    print(f"  epss_percentile:        {epss_percentile_str}")
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


def wait_for_user(step_description: str) -> None:
    """Yêu cầu người dùng nhấn phím Enter để tiếp tục thực hiện bước tiếp theo."""
    print(f"\n👉 [BẤM ENTER] để thực hiện: {step_description}")
    input()


async def enrich_opencti_flow() -> None:
    """Thu thập 5 CVE từ OpenCTI TAXII và làm giàu dữ liệu từng CVE có tương tác."""
    print("==========================================================")
    print(" HỆ THỐNG INGEST CVE TỪ OPENCTI & LÀM GIÀU DỮ LIỆU (TRIAGE)")
    print("==========================================================\n")

    # Kiểm tra cấu hình kết nối từ file cấu hình/env
    print("----------------------------------------------------------")
    print("KIỂM TRA CẤU HÌNH KẾT NỐI OPENCTI")
    print("----------------------------------------------------------")
    print(f"  - OpenCTI URL:               {settings.opencti_url}")
    print(f"  - TAXII Collection ID:       {settings.opencti_taxii_collection_id or 'CHƯA CẤU HÌNH'}")
    print(f"  - Basic Auth Username:       {settings.opencti_username or 'None'}")
    print()

    # Kiểm tra sơ bộ trước khi chạy (Pre-flight check)
    if not settings.opencti_taxii_collection_id:
        print("[!] LỖI: OPENCTI_TAXII_COLLECTION_ID chưa được thiết lập trong file .env!")
        print("    Vui lòng cấu hình đầy đủ thông tin trước khi tiếp tục.")
        sys.exit(1)

    print("✅ Cấu hình OpenCTI hợp lệ.")

    # Bước 1: Thu thập 5 CVE từ OpenCTI
    wait_for_user("Tải 5 CVE từ OpenCTI TAXII Collection")
    print("\n[1] Khởi tạo OpenCTI Provider...")
    provider = OpenCTIProvider()
    print("\n[2] Tải dữ liệu và chuẩn hóa từ OpenCTI TAXII Collection (limit=5)...")
    try:
        raw_bundle = await provider.client.fetch_raw_collection(limit=5)
        cves = provider.parser.parse_bundle(raw_bundle)[:5]
        print(f"    -> Tải và chuẩn hóa thành công {len(cves)} CVE từ OpenCTI:")
        for idx, cve in enumerate(cves, 1):
            print(f"       + CVE #{idx}: {cve.cve_id}")
    except Exception as exc:
        print(f"\n[!] LỖI KHI TẢI DỮ LIỆU TỪ OPENCTI:")
        print(f"    Chi tiết: {exc}")
        print()
        sys.exit(1)

    if not cves:
        print("\n[!] Không tìm thấy CVE nào từ OpenCTI. Kết thúc.")
        return

    # Bước 2: Làm giàu dữ liệu lần lượt cho từng CVE
    print(f"\n[3] Bắt đầu quá trình làm giàu dữ liệu cho {len(cves)} CVE vừa tải...")
    for idx, cve in enumerate(cves, 1):
        wait_for_user(f"Làm giàu dữ liệu (Step 1 Triage) cho {cve.cve_id} (CVE {idx}/{len(cves)})")
        try:
            await enrich(cve.cve_id)
        except Exception as exc:
            print(f"\n[!] LỖI khi làm giàu cho {cve.cve_id}: {exc}")

    print("\n==========================================================")
    print(" HOÀN THÀNH QUÁ TRÌNH LÀM GIÀU BATCH TỪ OPENCTI")
    print("==========================================================")


if __name__ == "__main__":
    # Đảm bảo Windows xử lý vòng lặp bất đồng bộ chính xác
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    if len(sys.argv) > 1:
        # Chạy làm giàu đơn lẻ cho một CVE cụ thể truyền vào
        target = sys.argv[1]
        asyncio.run(enrich(target))
    else:
        # Chạy chế độ Batch lấy dữ liệu từ OpenCTI
        asyncio.run(enrich_opencti_flow())
