"""Test end-to-end Bước 1 + Bước 2 + Bước 4.

Refactor 2026-07: extend test_step1_step2_e2e.py với Step 4 section.

Run:
  AI_ENABLED=true python -X utf8 -m tests.integration.test_step1_step2_step4_e2e CVE-2021-44228
  AI_ENABLED=false python -X utf8 -m tests.integration.test_step1_step2_step4_e2e CVE-2021-44228
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from time import perf_counter

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

debug_mode = "--debug" in sys.argv
if debug_mode:
    sys.argv.remove("--debug")
    print("[DEBUG MODE] required_fields & candidate_fields & legacy fields sẽ hiển thị")

from src.usecases.step_1_triage.orchestrator import TriageOrchestrator
from src.usecases.step_1_triage.orchestrator import _err_line


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
    """Nhấn Enter để tiếp tục. Set CVE_TI_NONINTERACTIVE=1 để auto-skip."""
    print(f"\n👉 [BẤM ENTER] để thực hiện: {step_description}")
    if os.getenv("CVE_TI_NONINTERACTIVE", "0").lower() in ("1", "true", "yes"):
        return
    input()


async def run_interactive_pipeline(cve_id: str) -> bool:
    print("=" * 80)
    print(f" BẮT ĐẦU QUY TRÌNH KIỂM THỬ INTERACTIVE (STEP 1 + 2 + 4) — {cve_id}")
    print("=" * 80)

    from src.usecases.step_1_triage.stages.core_stage import run_core_stage
    from src.usecases.step_1_triage.stages.epss_stage import run_epss_stage
    from src.usecases.step_1_triage.stages.kev_stage import run_kev_stage
    from src.usecases.step_1_triage.stages.exposure_stage import run_exposure_stage
    from src.domain.models.triage import TriageContext
    from src.domain.models.enriched import EnrichedCVEContext

    orch = TriageOrchestrator()
    pipeline_started = perf_counter()

    # BƯỚC 1 — ENRICHMENT
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
        "poc": orch._run_provider("poc", orch.poc, orch.poc.fetch, cve_id, provider_status, provider_errors, provider_durations),
    }
    provider_results = await asyncio.gather(*provider_tasks.values(), return_exceptions=True)

    nvd_raw = kev_raw = epss_raw = otx_raw = poc_raw = None
    for name, result in zip(provider_tasks.keys(), provider_results):
        if isinstance(result, Exception):
            provider_status[name] = "failed"
            provider_errors[name] = _err_line(result)
            provider_durations.setdefault(name, int((perf_counter() - provider_started) * 1000))
        elif name == "nvd":
            nvd_raw = result
        elif name == "kev":
            kev_raw = result
        elif name == "epss":
            epss_raw = result
        elif name == "otx":
            otx_raw = result
        elif name == "poc":
            poc_raw = result

    from src.usecases.step_1_triage.stages.poc_stage import run_poc_stage
    nvd_core_raw, _ = await orch._run_stage("core_stage", run_core_stage, cve_id, nvd_raw or {}, {})
    epss_stage_raw, _ = await orch._run_stage("epss_stage", run_epss_stage, cve_id, epss_raw or {}, {})
    kev_stage_raw, _ = await orch._run_stage("kev_stage", run_kev_stage, cve_id, kev_raw or {}, {})
    exposure_raw, _ = await orch._run_stage("exposure_stage", run_exposure_stage, cve_id, nvd_core_raw, {"internet_exposure": None})
    poc_stage_raw, _ = await orch._run_stage("poc_stage", run_poc_stage, cve_id, poc_raw or {}, {"poc_references": None, "public_poc": False})

    internet_exposure = exposure_raw.get("internet_exposure") if isinstance(exposure_raw, dict) else None
    threat_actors = otx_raw.get("threat_actors") or [] if isinstance(otx_raw, dict) else []

    core = orch._build_core_context(cve_id, nvd_core_raw, otx_raw)

    from src.shared.parsers.reference_parser import resolve_poc_context
    public_poc, poc_references = resolve_poc_context(core.references, poc_stage_raw)

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

    orch.decision_engine.evaluate(core, triage, capability_classification)

    enriched = EnrichedCVEContext(
        core=core,
        triage=triage,
        provider_status=provider_status,
        provider_errors=provider_errors,
    )

    _section(f"STEP 1 — ENRICHMENT for {cve_id}")
    print(f"  Severity:       {core.severity}")
    print(f"  CVSS Score:     {core.cvss_score}")
    print(f"  CVSS Vector:    {core.cvss_vector}")
    print(f"  CWE IDs:        {core.cwe_ids or []}")
    print(f"  Decision:       {triage.decision}")

    _section("STEP 1 — PROVIDER STATUS")
    for provider, status in provider_status.items():
        print(f"  {provider:6s}: {status}")

    if triage.decision == "NO-GO":
        print("\nℹ️ NO-GO — bỏ qua Step 2/4.")
        return True

    # BƯỚC 2 — TECH ANALYSIS
    wait_for_user(f"Bước 2: Gửi thông tin cho AI Agent phân tích sâu {cve_id}")

    print("\n[AI] Đang gọi LLM phân tích...")
    analysis_context, attack_context, stage_failed = await orch._run_analysis_stage(enriched, capability_classification)
    enriched.analysis = analysis_context
    enriched.attack = attack_context

    _section("STEP 2 — TECH ANALYSIS (Behavior + CWE + ATT&CK)")
    if enriched.analysis is None:
        print("  No analysis produced.")
        return True
    a = enriched.analysis
    print(f"  Family:             {a.family}")
    print(f"  Vulnerability type: {a.vulnerability_type}")
    print(f"  Vulnerability class:{a.vulnerability_class}")
    print(f"  Execution surface:  {a.execution_surface if a.execution_surface else 'n/a'}")
    print(f"  Delivery vector:    {a.delivery_vector if a.delivery_vector else 'n/a'}")
    print(f"  Mandatory behaviors ({len(a.mandatory_behaviors or [])}):")
    _print_list(a.mandatory_behaviors or [])

    _section("STEP 2 — ATT&CK MAPPING")
    if enriched.attack is None:
        print("  No attack mapping produced.")
    else:
        atk = enriched.attack
        print(f"  Tactics ({len(atk.tactics or [])}):")
        _print_list(atk.tactics or [])
        print(f"  Techniques ({len(atk.techniques or [])}):")
        _print_list(atk.techniques or [])
        print(f"  Confidence:         {atk.confidence}")
        print(f"  AI used/model:      {atk.ai_used} / {atk.ai_model}")

    # BƯỚC 4 — TELEMETRY
    wait_for_user(f"Bước 4: Chạy AI Telemetry Selector cho {cve_id}")

    from src.usecases.step_1_triage.stages.telemetry_stage import run_telemetry_stage

    print("\n[AI] Đang chạy Step 4 — Telemetry Selector...")
    telemetry_assessment = await run_telemetry_stage(enriched, capability_classification)
    enriched.telemetry = telemetry_assessment

    _section(f"STEP 4 — TELEMETRY ASSESSMENT for {cve_id}")
    t = telemetry_assessment

    # Metadata
    print(f"  AI used:                 {t.ai_used}")
    print(f"  AI model:                {t.ai_model}")
    print(f"  AI retry count:          {t.ai_retry_count}")

    # ============ PHASE 7: 5-block restructured output ============
    _print_features = lambda items: [print(f"      - {f.field} = {f.value if f.value is not None else (f'pattern={f.pattern}' if f.pattern else '?')}" + (f"  [why: {f.rationale}]" if f.rationale else "")) for f in items]

    # BLOCK 1: AI Semantic Analysis
    print(f"\n  ╔══ AI Semantic Analysis ═══════════════════════════════╗")
    print(f"  Candidate Telemetry Domains ({len(t.candidate_telemetry_domains or [])}):")
    _print_list(t.candidate_telemetry_domains or [])
    if t.invalid_domains:
        print(f"  Invalid Domains (dropped):  {t.invalid_domains}")
    if t.telemetry_selection_rationale:
        print(f"  Reasoning per Domain:")
        _print_list(t.telemetry_selection_rationale)
    print(f"  Detection Axis:             {t.detection_axis}")
    print(f"  Primary Axis:               {t.primary_axis}")
    print(f"  Detection Strategy:         {t.recommended_rule_strategy or t.rule_strategy}")

    # BLOCK 2: Knowledge Resolution
    print(f"\n  ╠══ Knowledge Resolution ════════════════════════════════╣")
    print(f"  Canonical Telemetry ({len(t.canonical_telemetry or [])}):")
    _print_list(t.canonical_telemetry or [])
    print(f"  Canonical Fields    ({len(t.canonical_fields or [])}):")
    _print_list(t.canonical_fields or [])
    print(f"  Sigma Logsources ({len(t.sigma_logsources or [])}):")
    for ls in t.sigma_logsources or []:
        svc = f" service={ls.service}" if ls.service else ""
        print(f"      - {ls.category}/{ls.product}{svc}")
    if t.required_events:
        print(f"  Required Events:    {t.required_events}")
    if t.telemetry_requirements:
        print(f"  Telemetry Requirements: {t.telemetry_requirements}")
    if t.provenance:
        print(f"  Provenance (audit trail):")
        for step in t.provenance:
            print(f"      [{step.step}] {step.input} → {step.output}")
            if step.reason:
                print(f"          reason: {step.reason}")

    # BLOCK 3: Telemetry Quality Assessment
    valid_total = len(t.validated_fields or []) + len(t.invalid_fields or [])
    valid_pct = (len(t.validated_fields or []) / valid_total * 100) if valid_total else 0
    eff_conf = t.effective_confidence if t.effective_confidence is not None else (t.telemetry_confidence or 0.0)
    print(f"\n  ╠══ Telemetry Quality Assessment ═════════════════════════╣")
    print(f"  Validated Fields:          {len(t.validated_fields or [])}/{valid_total} ({valid_pct:.0f}%)")
    if t.invalid_fields:
        print(f"  Invalid Fields:            {t.invalid_fields}")
    print(f"  AI Hallucination Ratio:    {t.ai_hallucination_ratio}  (|required - validated| / max(required, 1))")
    print(f"  Effective AI Confidence:   {eff_conf:.2f}")
    print(f"  Pipeline Feasibility:      {t.telemetry_feasibility_score}")
    if t.telemetry_feasibility_breakdown:
        print(f"  Feasibility Breakdown:")
        for k, v in t.telemetry_feasibility_breakdown.items():
            print(f"      {k}: {v}")
    if t.telemetry_gaps:
        print(f"  Telemetry Gaps:            {t.telemetry_gaps}")
        print(f"  Gap Severity:              {t.gap_severity}")

    # BLOCK 4: Detection Features
    stable = t.stable_features or []
    cond = t.conditional_features or []
    opt = t.optional_features or []
    print(f"\n  ╠══ Detection Features ═════════════════════════════════╣")
    print(f"  Stable Features    ({len(stable)}): [Protocol invariant | attacker khó bypass]")
    _print_features(stable)
    print(f"  Conditional Features ({len(cond)}): [Attacker choice | context-dependent]")
    _print_features(cond)
    print(f"  Optional Features   ({len(opt)}): [Environment dependent | dễ spoof]")
    _print_features(opt)

    # BLOCK 5: Telemetry Summary
    print(f"\n  ╚══ Telemetry Summary ═══════════════════════════════════╝")
    print(f"  Stable Features:      {len(stable)}")
    print(f"  Conditional Features: {len(cond)}")
    print(f"  Optional Features:    {len(opt)}")
    print(f"  Sigma Logsources:     {len(t.sigma_logsources or [])}")
    print(f"  Validated Fields:     {len(t.validated_fields or [])}/{valid_total} ({valid_pct:.0f}%)")
    print(f"  Correlation:          {'YES' if t.correlation_required else 'NO'}")
    print(f"  Effective AI Confidence: {eff_conf:.2f}")
    print(f"  Pipeline Feasibility:    {t.telemetry_feasibility_score}")

    # DEBUG MODE (--debug flag): hide required_fields by default
    if debug_mode:
        print(f"\n  [DEBUG MODE]")
        print(f"  required_fields ({len(t.required_fields or [])}):")
        _print_list(t.required_fields or [])
        print(f"  candidate_fields ({len(t.candidate_fields or [])}):")
        _print_list(t.candidate_fields or [])
        print(f"  rule_strategy ({len(t.rule_strategy or [])}):")
        _print_list(t.rule_strategy or [])
        if t.observable_detection_features:
            df = t.observable_detection_features
            print(f"  observable_detection_features (legacy):")
            print(f"      stable: {len(df.stable_features)}, observable: {len(df.observable_features)}, optional: {len(df.optional_features)}")

    # Verdict
    _section("STEP 4 — VERDICT")
    if t.telemetry_feasibility_score is not None:
        if t.telemetry_feasibility_score >= 0.7:
            print(f"  ✅ PROCEED — feasibility_score = {t.telemetry_feasibility_score}")
        elif t.telemetry_feasibility_score >= 0.5:
            print(f"  ⚠️  REVIEW — feasibility_score = {t.telemetry_feasibility_score}")
        else:
            print(f"  ❌ NO-GO — feasibility_score = {t.telemetry_feasibility_score} (quá thấp)")

    if not t.ai_used:
        print(f"  ℹ️  AI not used — fell back to rule-based (set AI_ENABLED=true để test AI path)")

    # BƯỚC 5 — METADATA
    wait_for_user(f"Hoàn thành. Tổng kết metadata cho {cve_id}")

    _section("METADATA")
    print(f"  AI steps used:       {list(orch._ai_steps_used)}")
    print(f"  Pipeline duration:   {int((perf_counter() - pipeline_started) * 1000)} ms")
    print("=" * 80 + "\n")
    return True


async def main() -> None:
    from config.settings import settings
    from src.infrastructure.providers.opencti import OpenCTIProvider

    if len(sys.argv) > 1:
        target = sys.argv[1]
        await run_interactive_pipeline(target)
    else:
        print("==========================================================")
        print(" TEST BATCH STEP 1 + 2 + 4 E2E TỪ OPENCTI")
        print("==========================================================\n")

        if not settings.opencti_taxii_collection_id:
            print("[!] OPENCTI_TAXII_COLLECTION_ID chưa được thiết lập trong .env!")
            sys.exit(1)

        wait_for_user("Tải 5 CVE từ OpenCTI")
        provider = OpenCTIProvider()
        try:
            raw_bundle = await provider.client.fetch_raw_collection(limit=5)
            cves = provider.parser.parse_bundle(raw_bundle)[:5]
            for idx, cve in enumerate(cves, 1):
                print(f"       + CVE #{idx}: {cve.cve_id}")
        except Exception as exc:
            print(f"\n[!] LỖI KHI TẢI TỪ OPENCTI: {exc}\n")
            sys.exit(1)

        if not cves:
            print("\n[!] Không tìm thấy CVE nào.")
            return

        for idx, cve in enumerate(cves, 1):
            print(f"\n[{idx}/{len(cves)}] Bắt đầu {cve.cve_id}...")
            await run_interactive_pipeline(cve.cve_id)

            if idx < len(cves):
                user_choice = input("\nTiếp tục CVE tiếp theo? (1=tiếp, 2=thoát): ").strip()
                if user_choice == "2":
                    break


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    asyncio.run(main())
