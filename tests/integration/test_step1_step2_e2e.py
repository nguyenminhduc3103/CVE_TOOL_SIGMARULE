"""Test end-to-end Bước 1 (Triage) + Bước 2 (Behavior + ATT&CK) có tương tác từng bước và batch.

Khác với test_behavior.py (hardcode CoreCVEData, chỉ test Bước 2):
- File này gọi orchestrator thật -> Bước 1 gọi NVD/KEV/EPSS/OTX API thật
- Bước 2 nhận data từ Bước 1 -> gọi AI (nếu enabled) hoặc fallback rule-based
- Tách output thành từng khối riêng và yêu cầu bấm Enter để tiếp tục qua từng bước.
- Có thêm coverage % so với ground truth rule-based
- Hỗ trợ tải 5 CVE từ OpenCTI TAXII nếu không truyền tham số, hoặc chạy đơn lẻ.

Run: python -X utf8 -m tests.integration.test_step1_step2_e2e CVE-2021-44228
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from time import perf_counter

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.steps.step_1_triage.orchestrator import TriageOrchestrator
from app.steps.step_2_tech_analysis.gap_analysis import (
    compute_coverage,
    compute_ground_truth,
)


def _print_list(items, indent: str = "    ") -> None:
    if not items:
        print(f"{indent}- none")
        return
    for item in items:
        print(f"{indent}- {item}")


def _section(title: str) -> None:
    print("\n" + "=" * 80)
    print(f" {title}")
    print("=" * 80)


def wait_for_user(step_description: str) -> None:
    """Yêu cầu người dùng nhấn phím Enter để tiếp tục thực hiện bước tiếp theo."""
    print(f"\n👉 [BẤM ENTER] để thực hiện: {step_description}")
    input()


async def run_interactive_pipeline(cve_id: str) -> bool:
    print("=" * 80)
    print(f" BẮT ĐẦU QUY TRÌNH KIỂM THỬ INTERACTIVE (STEP 1 + 2) — {cve_id}")
    print("=" * 80)

    from app.steps.step_1_triage.stages.core_stage import run_core_stage
    from app.steps.step_1_triage.stages.epss_stage import run_epss_stage
    from app.steps.step_1_triage.stages.kev_stage import run_kev_stage
    from app.steps.step_1_triage.stages.exposure_stage import run_exposure_stage
    from app.shared.parsers.reference_parser import extract_urls
    from app.shared.models.triage import TriageContext
    from app.shared.models.enriched import EnrichedCVEContext
    from app.steps.step_1_triage.orchestrator import _safe_get_first_line
    import httpx

    orch = TriageOrchestrator()
    pipeline_started = perf_counter()

    # =========================================================================
    # BƯỚC 1 — ENRICHMENT
    # =========================================================================
    wait_for_user(f"Bước 1: Thu thập dữ liệu từ NVD, KEV, EPSS, OTX & Triage sơ bộ cho {cve_id}")
    
    provider_started = perf_counter()
    provider_status = {}
    provider_errors = {}
    provider_durations = {}

    provider_tasks = {
        "nvd": orch._run_provider("nvd", orch.nvd, orch.nvd.fetch, cve_id, provider_status, provider_errors, provider_durations),
        "kev": orch._run_provider("kev", orch.kev, orch.kev.fetch, cve_id, provider_status, provider_errors, provider_durations),
        "epss": orch._run_provider("epss", orch.epss, orch.epss.fetch, cve_id, provider_status, provider_errors, provider_durations),
        "otx": orch._run_provider("otx", orch.otx, orch.otx.fetch, cve_id, provider_status, provider_errors, provider_durations),
    }
    provider_results = await asyncio.gather(*provider_tasks.values(), return_exceptions=True)

    nvd_raw = kev_raw = epss_raw = otx_raw = None
    for name, result in zip(provider_tasks.keys(), provider_results):
        if isinstance(result, Exception):
            provider_status[name] = "failed"
            provider_errors[name] = _safe_get_first_line(result)
            provider_durations.setdefault(name, int((perf_counter() - provider_started) * 1000))
        elif name == "nvd":
            nvd_raw = result
        elif name == "kev":
            kev_raw = result
        elif name == "epss":
            epss_raw = result
        elif name == "otx":
            otx_raw = result

    # Trích xuất các stage
    nvd_core_raw, _ = await orch._run_stage("core_stage", run_core_stage, cve_id, nvd_raw or {}, {})
    epss_stage_raw, _ = await orch._run_stage("epss_stage", run_epss_stage, cve_id, epss_raw or {}, {})
    kev_stage_raw, _ = await orch._run_stage("kev_stage", run_kev_stage, cve_id, kev_raw or {}, {})
    exposure_raw, _ = await orch._run_stage("exposure_stage", run_exposure_stage, cve_id, nvd_core_raw, {"internet_exposure": None})

    internet_exposure = exposure_raw.get("internet_exposure") if isinstance(exposure_raw, dict) else None
    threat_actors = otx_raw.get("threat_actors") or [] if isinstance(otx_raw, dict) else []

    core = orch._build_core_context(cve_id, nvd_core_raw, otx_raw)

    # Lọc PoC
    public_poc = False
    poc_references = []
    if core.references:
        try:
            enriched_refs = extract_urls(core.references)
            for ref in enriched_refs:
                if ref.get("is_exploit"):
                    public_poc = True
                    poc_references.append(ref.get("url"))
        except Exception:
            pass

    # Build TriageContext
    in_kev_val = orch._get_optional_bool(kev_stage_raw, "in_kev")
    triage = TriageContext(
        in_kev=in_kev_val,
        kev_added_date=orch._get_optional_datetime(kev_stage_raw, "kev_added_date"),
        ransomware_usage=orch._get_optional_bool(kev_stage_raw, "known_ransomware_campaign_use") or False,
        observed_in_the_wild=in_kev_val or False,
        epss_score=orch._get_optional_float(epss_stage_raw, "epss_score"),
        epss_percentile=orch._get_optional_float(epss_stage_raw, "epss_percentile"),
        internet_exposure=internet_exposure,
        threat_actors=threat_actors,
        public_poc=public_poc,
        poc_references=poc_references or None,
    )

    if not core.cwe_ids or core.cwe_ids == ["NVD-CWE-noinfo"]:
        if isinstance(kev_stage_raw, dict) and kev_stage_raw.get("cwes"):
            core.cwe_ids = kev_stage_raw.get("cwes")

    priority, score = await orch.priority_engine.assess(core, triage)
    triage.priority = priority
    triage.priority_score = score

    capability = await orch.capability_checker.assess(core, triage)
    triage.capability_assessment = capability
    capability_classification = orch.capability_checker.classify(core)

    # Quyết định Triage tự động
    if capability_classification.value != "in_scope":
        triage.decision = "NO-GO"
        triage.decision_reason = (
            f"Capability assessment={capability_classification.value} (out of scope); "
            f"reason={capability_classification.reasoning}."
        )
    else:
        if triage.in_kev is True:
            triage.decision = "GO"
            triage.decision_reason = "Capability assessment=in_scope, with active exploitation confirmed in CISA KEV."
        elif triage.public_poc is True:
            triage.decision = "GO"
            triage.decision_reason = "Capability assessment=in_scope, and while in_kev is False/None, a public PoC/exploit was detected in references."
        else:
            triage.decision = "NO-GO"
            triage.decision_reason = "Capability assessment=in_scope, but no active threat or exploit detected."

    enriched = EnrichedCVEContext(
        core=core,
        triage=triage,
        provider_status=provider_status,
        provider_errors=provider_errors,
    )

    # In kết quả STEP 1
    _section(f"STEP 1 — ENRICHMENT (NVD + KEV + EPSS) for {cve_id}")
    print(f"  Severity:       {core.severity}")
    print(f"  CVSS Score:     {core.cvss_score}")
    print(f"  CVSS Vector:    {core.cvss_vector}")
    print(f"  CWE IDs:        {core.cwe_ids or []}")
    print(f"  Published:      {core.published_at.isoformat() if core.published_at else None}")
    print(f"  Modified:       {core.modified_at.isoformat() if core.modified_at else None}")
    print(f"  Description:    {(core.description or '')[:200]}{'...' if len(core.description or '') > 200 else ''}")
    print(f"  References:     {len(core.references or [])} URLs")
    print(f"  CPEs:           {len(core.cpes or [])} entries")

    print(f"  In KEV:         {triage.in_kev}")
    print(f"  KEV added:      {triage.kev_added_date.isoformat() if triage.kev_added_date else None}")
    print(f"  Ransomware:     {triage.ransomware_usage}")
    print(f"  EPSS score:     {triage.epss_score}")
    print(f"  EPSS %ile:      {triage.epss_percentile}")
    print(f"  Capability:     {triage.capability_assessment}")
    print(f"  Priority:       {triage.priority} (score={triage.priority_score})")
    print(f"  Decision:       {triage.decision}")
    print(f"  Reason:         {triage.decision_reason}")

    # In STEP 1 PROVIDER STATUS
    _section("STEP 1 — PROVIDER STATUS")
    for provider, status in provider_status.items():
        print(f"  {provider:6s}: {status}")
    if provider_errors:
        print("  Errors:")
        for provider, error in provider_errors.items():
            print(f"    - {provider}: {error}")

    if triage.decision == "NO-GO":
        print("\nℹ️ Quyết định lỗ hổng là NO-GO. Bỏ qua bước gọi AI phân tích sâu.")
        # In Metadata
        _section("METADATA")
        print(f"  Partial enrichment:  {any(status != 'success' for status in provider_status.values())}")
        print(f"  Pipeline duration:   {int((perf_counter() - pipeline_started) * 1000)} ms")
        print(f"  AI steps used:       []")
        print("=" * 80 + "\n")
        return True

    # =========================================================================
    # BƯỚC 2 — TECH ANALYSIS (AI Agent)
    # =========================================================================
    wait_for_user(f"Bước 2: Gửi thông tin cho AI Agent để phân tích sâu hành vi kỹ thuật của {cve_id}")
    
    print("\n[AI] Đang gọi LLM phân tích...")
    analysis_context, attack_context, stage_failed = await orch._run_analysis_stage(enriched, capability_classification)
    enriched.analysis = analysis_context
    enriched.attack = attack_context

    _section("STEP 2 — TECH ANALYSIS (Behavior + CWE + ATT&CK)")
    if enriched.analysis is None:
        print("  No analysis produced.")
    else:
        a = enriched.analysis
        print(f"  Family:             {a.family}")
        print(f"  Signature:          {a.signature}")
        print(f"  Vulnerability type: {a.vulnerability_type}")
        print(f"  Vulnerability class:{a.vulnerability_class}")
        print(f"  Exploit vector:     {a.exploit_vector}")
        print(f"  Pre-auth:           {a.pre_auth}")
        print(f"  Remote exploitable: {a.remote_exploitable}")
        print(f"  Exploit complexity: {a.exploit_complexity}")
        print(f"  Confidence:         {a.confidence}")
        print(f"  Likely outcome:     {a.likely_outcome}")

        print(f"  CWE metadata:")
        if a.cwe_metadata:
            print(f"    cwe_ids:           {a.cwe_metadata.cwe_ids or []}")
            print(f"    cwe_names:         {a.cwe_metadata.cwe_names or []}")
            print(f"    mapping_confidence:{a.cwe_metadata.mapping_confidence}")
        else:
            print("    - none")

        print(f"  Attack flow:")
        if a.attack_flow:
            print(f"    entry_vector:           {a.attack_flow.entry_vector}")
            print(f"    execution_mechanism:    {a.attack_flow.execution_mechanism}")
            print(f"    observable_side_effects:")
            _print_list(a.attack_flow.observable_side_effects or [], indent="      ")
        else:
            print("    - none")

        print(f"  Mandatory behaviors ({len(a.mandatory_behaviors or [])}):")
        _print_list(a.mandatory_behaviors or [])
        print(f"  Evasive indicators:")
        _print_list(a.evasive_indicators or [])
        print(f"  Exploit requirements:")
        _print_list(a.exploit_requirements or [])
        print(f"  Reasoning ({len(a.reasoning or [])} items):")
        _print_list(a.reasoning or [])

    # =========================================================================
    # BƯỚC 3 — ATT&CK MAPPING
    # =========================================================================
    wait_for_user(f"Bước 3: Thực hiện ánh xạ MITRE ATT&CK cho {cve_id}")
    
    _section("STEP 2 — ATT&CK MAPPING")
    if enriched.attack is None:
        print("  No attack mapping produced.")
    else:
        atk = enriched.attack
        print(f"  Tactics ({len(atk.tactics or [])}):")
        _print_list(atk.tactics or [])
        print(f"  Techniques ({len(atk.techniques or [])}):")
        _print_list(atk.techniques or [])
        print(f"  Subtechniques ({len(atk.subtechniques or [])}):")
        _print_list(atk.subtechniques or [])
        print(f"  Confidence:         {atk.confidence}")
        print(f"  Mapping reasons ({len(atk.mapping_reasons or [])}):")
        _print_list(atk.mapping_reasons or [])

    _section("STEP 2 — AI USAGE")
    ai_steps = orch._ai_steps_used or []
    if ai_steps:
        print(f"  AI steps used: {list(ai_steps)}")
        if enriched.analysis:
            print(f"  Retries:       {enriched.analysis.ai_retry_count}")
    else:
        print("  AI not used in Bước 2 — fell back to rule-based")

    # =========================================================================
    # BƯỚC 4 — COVERAGE vs GROUND TRUTH
    # =========================================================================
    wait_for_user(f"Bước 4: Đánh giá độ phủ (CWE / Behavior / TTP) so với Ground Truth của {cve_id}")

    _section("STEP 2 — COVERAGE vs GROUND TRUTH (rule-based)")
    ai_output = {
        "cve_id": enriched.core.cve_id,
        "cwe_ids": enriched.core.cwe_ids or [],
        "technical_analysis": (
            enriched.analysis.model_dump(mode="json", exclude_none=True)
            if enriched.analysis else {}
        ),
        "attack_mapping": (
            enriched.attack.model_dump(mode="json", exclude_none=True)
            if enriched.attack else {}
        ),
    }
    ground_truth = compute_ground_truth(
        cve_id=enriched.core.cve_id,
        description=enriched.core.description,
        cwe_ids=enriched.core.cwe_ids,
        cvss_vector=enriched.core.cvss_vector,
    )
    cov = compute_coverage(ai_output, ground_truth)

    print(f"  CWE coverage:       {cov['cwe_coverage']:.0%}  "
          f"({len(ground_truth['expected_cwes'])} expected, "
          f"missing: {cov['missing_cwes']})")
    print(f"  Behavior coverage:  {cov['behavior_coverage']:.0%}  "
          f"({len(ground_truth['expected_behaviors'])} expected, "
          f"missing: {cov['missing_behaviors']})")
    print(f"  TTP coverage:       {cov['ttp_coverage']:.0%}  "
          f"({len(ground_truth['expected_techniques'])} expected, "
          f"missing: {cov['missing_techniques']})")
    print(f"  ─────────────────────────────────────")
    print(f"  Overall:            {cov['overall_coverage']:.0%}  → {cov['verdict']}")
    if cov["needs_retry"]:
        print(f"  Retry requested:    True (AI produced extras that hurt coverage)")

    if cov["extra_techniques"]:
        print(f"  Extra techniques (AI bịa?): {cov['extra_techniques']}")

    # METADATA
    _section("METADATA")
    partial_val = any(status != 'success' for status in provider_status.values()) or stage_failed
    print(f"  Partial enrichment:  {partial_val}")
    print(f"  Pipeline duration:   {int((perf_counter() - pipeline_started) * 1000)} ms")
    print(f"  AI steps used:       {list(ai_steps)}")
    print("=" * 80 + "\n")
    return True


async def main() -> None:
    from app.core.config import settings
    from app.shared.providers.opencti import OpenCTIProvider

    if len(sys.argv) > 1:
        # Chạy phân tích đơn lẻ cho một CVE cụ thể được truyền vào qua tham số
        target = sys.argv[1]
        await run_interactive_pipeline(target)
    else:
        # Chạy chế độ Batch lấy dữ liệu tự động từ OpenCTI
        print("==========================================================")
        print(" TEST BATCH STEP 1 & STEP 2 E2E TỪ OPENCTI (INTERACTIVE)")
        print("==========================================================\n")

        print("----------------------------------------------------------")
        print("KIỂM TRA CẤU HÌNH KẾT NỐI OPENCTI")
        print("----------------------------------------------------------")
        print(f"  - OpenCTI URL:               {settings.opencti_url}")
        print(f"  - TAXII Collection ID:       {settings.opencti_taxii_collection_id or 'CHƯA CẤU HÌNH'}")
        print(f"  - Basic Auth Username:       {settings.opencti_username or 'None'}")
        print()

        if not settings.opencti_taxii_collection_id:
            print("[!] LỖI: OPENCTI_TAXII_COLLECTION_ID chưa được thiết lập trong file .env!")
            sys.exit(1)

        wait_for_user("Tải 5 CVE mới nhất từ OpenCTI TAXII Collection")
        provider = OpenCTIProvider()
        try:
            raw_bundle = await provider.client.fetch_raw_collection(limit=5)
            cves = provider.parser.parse_bundle(raw_bundle)[:5]
            print(f"    -> Tải và chuẩn hóa thành công {len(cves)} CVE từ OpenCTI:")
            for idx, cve in enumerate(cves, 1):
                print(f"       + CVE #{idx}: {cve.cve_id}")
        except Exception as exc:
            print(f"\n[!] LỖI KHI TẢI DỮ LIỆU TỪ OPENCTI: {exc}\n")
            sys.exit(1)

        if not cves:
            print("\n[!] Không tìm thấy CVE nào từ OpenCTI. Kết thúc.")
            return

        for idx, cve in enumerate(cves, 1):
            print(f"\n[{idx}/{len(cves)}] Bắt đầu xử lý {cve.cve_id}...")
            await run_interactive_pipeline(cve.cve_id)
            
            # Cho người dùng lựa chọn sau mỗi CVE
            if idx < len(cves):
                print(f"\n" + "=" * 60)
                print(f"🎉 HOÀN THÀNH PHÂN TÍCH CHO {cve.cve_id}")
                print(f"Bạn có muốn tiếp tục xử lý CVE tiếp theo ({cves[idx].cve_id}) không?")
                print(f"   [1] Tiếp tục thực hiện quy trình cho CVE tiếp theo")
                print(f"   [2] Thoát quy trình")
                print("=" * 60)
                user_choice = input("Lựa chọn của bạn (mặc định là [1], nhấn Enter hoặc gõ '1' để tiếp tục, gõ '2' để thoát): ").strip()
                if user_choice == "2":
                    print("\n👋 Đã thoát quy trình theo yêu cầu của người dùng.")
                    break
        
        print("\n==========================================================")
        print(" HOÀN THÀNH QUÁ TRÌNH BATCH TEST TỪ OPENCTI")
        print("==========================================================")


if __name__ == "__main__":
    # Đảm bảo Windows xử lý vòng lặp bất đồng bộ chính xác
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    asyncio.run(main())
