"""Test end-to-end Step 1 + Step 2 + Step 4 + Step 6.

Refactor 2026-07: thêm Step 6 section (Detection Logic Planner + Sigma emission).

Run:
  STEP6_AI_ENABLED=true python -X utf8 -m tests.integration.test_step1_step2_step4_step6_e2e CVE-2021-44228
  STEP6_AI_ENABLED=false python -X utf8 -m tests.integration.test_step1_step2_step4_step6_e2e CVE-2021-44228

To inspect generated YAML (optional):
  set CVE_TI_DUMP_YAML=1
  Output: generated_rules/{cve_id}_step6.yaml

Add --debug flag to print the first 30 lines of YAML to stdout.
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

# Load .env if present (so CVE_TI_DUMP_YAML=1 in .env is honored)
try:
    from dotenv import load_dotenv  # type: ignore
    _env_path = ROOT / ".env"
    if _env_path.exists():
        load_dotenv(_env_path, override=False)
except ImportError:
    pass

debug_mode = "--debug" in sys.argv
if debug_mode:
    sys.argv.remove("--debug")
    print("[DEBUG MODE] plan / AI payload trace will be shown")

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


async def _run_step1_and_2(cve_id: str) -> tuple | None:
    """Run Step 1 + Step 2, return (enriched, capability_classification) or None."""
    from src.usecases.step_1_triage.stages.core_stage import run_core_stage
    from src.usecases.step_1_triage.stages.epss_stage import run_epss_stage
    from src.usecases.step_1_triage.stages.kev_stage import run_kev_stage
    from src.usecases.step_1_triage.stages.exposure_stage import run_exposure_stage
    from src.usecases.step_1_triage.stages.poc_stage import run_poc_stage
    from src.domain.models.triage import TriageContext
    from src.domain.models.enriched import EnrichedCVEContext

    orch = TriageOrchestrator()
    pipeline_started = perf_counter()

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
        print("\nℹ️ NO-GO — bỏ qua Step 2/4/6.")
        return None

    # BƯỚC 2 — TECH ANALYSIS
    wait_for_user(f"Bước 2: Gửi thông tin cho AI Agent phân tích sâu {cve_id}")

    print("\n[AI] Đang gọi LLM phân tích...")
    analysis_context, attack_context, stage_failed = await orch._run_analysis_stage(enriched, capability_classification)
    enriched.analysis = analysis_context
    enriched.attack = attack_context

    _section("STEP 2 — TECH ANALYSIS (Behavior + CWE + ATT&CK)")
    if enriched.analysis is None:
        print("  No analysis produced.")
        return None
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

    return enriched, capability_classification


async def _run_step4(enriched, capability_classification) -> dict:
    """Run Step 4 telemetry selector, return telemetry dict."""
    from src.usecases.step_1_triage.stages.telemetry_stage import run_telemetry_stage

    wait_for_user("Bước 4: Chạy AI Telemetry Selector")

    print("\n[AI] Đang chạy Step 4 — Telemetry Selector...")
    telemetry_assessment = await run_telemetry_stage(enriched, capability_classification)
    enriched.telemetry = telemetry_assessment

    _section("STEP 4 — TELEMETRY ASSESSMENT")
    t = telemetry_assessment
    print(f"  AI used:           {t.ai_used}")
    print(f"  AI model:          {t.ai_model}")
    print(f"  AI retry count:    {t.ai_retry_count}")
    print(f"  Detection Axis:    {t.detection_axis}")
    print(f"  Detection Strategy:{t.recommended_rule_strategy or t.rule_strategy}")
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
    valid_total = len(t.validated_fields or []) + len(t.invalid_fields or [])
    valid_pct = (len(t.validated_fields or []) / valid_total * 100) if valid_total else 0
    print(f"  Validated Fields:   {len(t.validated_fields or [])}/{valid_total} ({valid_pct:.0f}%)")
    print(f"  Pipeline Feasibility: {t.telemetry_feasibility_score}")
    print(f"  Correlation:        {'YES' if t.correlation_required else 'NO'}")
    if t.telemetry_gaps:
        print(f"  Telemetry Gaps:     {t.telemetry_gaps}")
    print(f"  Stable Features    ({len(t.stable_features or [])}):")
    _print_list(t.stable_features or [])
    print(f"  Conditional Features ({len(t.conditional_features or [])}):")
    _print_list(t.conditional_features or [])

    # Convert TelemetryAssessment to plain dict for Step 6
    telemetry_dict = t.model_dump() if hasattr(t, "model_dump") else dict(t)
    return telemetry_dict


async def _run_step6(enriched, telemetry_dict: dict) -> None:
    """Run Step 6 orchestrator (Phase A + Phase D only — per Step 6 scope)."""
    from config.settings import settings
    from src.infrastructure.ai.core import BaseAIClient
    from src.usecases.step_6_generate_sigma.orchestrator import Step6Orchestrator

    wait_for_user("Bước 6: Sinh Sigma rule (Detection Logic Planner + Builder)")

    step6_ai_enabled = bool(getattr(settings, "step6_ai_enabled", True))
    step6_model = settings.get_step6_model()
    step6_base = settings.get_step6_base_url()
    step6_keys = settings.get_step6_api_keys()

    print(f"\n[Step 6] AI enabled: {step6_ai_enabled}")
    print(f"[Step 6] Model:      {step6_model}")
    print(f"[Step 6] Base URL:   {step6_base}")
    print(f"[Step 6] API keys:   {len(step6_keys)} key(s)")

    ai_client: BaseAIClient | None = None
    if step6_ai_enabled and step6_keys:
        try:
            ai_client = BaseAIClient()
        except Exception as exc:
            print(f"[Step 6] ⚠️ Không tạo được AI client: {exc}")
            ai_client = None

    orch = Step6Orchestrator(ai_client=ai_client)

    started = perf_counter()
    references = list(getattr(enriched.core, "references", []) or [])

    result = await orch.run(
        core=enriched.core,
        analysis=enriched.analysis,
        attack=enriched.attack,
        telemetry=telemetry_dict,
        references=references,
    )
    duration_ms = int((perf_counter() - started) * 1000)

    _section(f"STEP 6 — DETECTION PLAN for {enriched.core.cve_id}")
    plan = result.detection_plan
    print(f"  Source:               {plan.source}")
    print(f"  AI model:             {plan.ai_model}")
    print(f"  Planner confidence:   {plan.planner_confidence:.2f}")
    print(f"  Risk bias:            {plan.risk_bias}")
    print(f"  Detections ({len(plan.detections)}):")
    for idx, intent in enumerate(plan.detections):
        print(f"      [{idx}] {intent.priority:8s} {intent.intent}")
        if intent.rationale:
            print(f"             rationale: {intent.rationale}")
    print(f"  Logic: operator={plan.logic.operator} operands={plan.logic.operands}"
          + (f" threshold={plan.logic.threshold}" if plan.logic.threshold else ""))
    print(f"  False positives ({len(plan.falsepositives)}):")
    _print_list(plan.falsepositives)
    if plan.rationale:
        print(f"  Plan rationale: {plan.rationale}")

    _section("STEP 6 — SIGMA OUTPUT")
    rule_count = len(result.rules)
    print(f"  Rule count:        {rule_count}")
    if rule_count > 0:
        for idx, rule in enumerate(result.rules):
            meta = getattr(rule, "metadata", None)
            rule_id = getattr(meta, "id", "?") if meta is not None else "?"
            rule_level = getattr(meta, "level", "?") if meta is not None else "?"
            rule_title = getattr(meta, "title", "?") if meta is not None else "?"
            logsource = getattr(rule, "logsource", None) or {}
            if isinstance(logsource, dict):
                ls_str = f" product={logsource.get('product', '')}" if logsource.get("product") else ""
                if logsource.get("service"):
                    ls_str += f" service={logsource['service']}"
            else:
                ls_str = ""
            # Show full title (no truncation)
            print(f"      [{idx}] {rule_level:<10} {rule_id}")
            print(f"          title:    '{rule_title}'")
            print(f"          logsource:{ls_str or ' (none)'}")

    print(f"  YAML length:       {len(result.yaml_output):,} bytes")
    print(f"  Duration:          {duration_ms:,} ms")
    print(f"  Plan source:       {plan.source}")
    if plan.source == "rule_based":
        print(f"  ℹ️  Plan fell back to rule-based (set STEP6_AI_ENABLED=true & valid key to test AI path)")

    # Verify YAML parseable (multi-document: Sigma correlation rules joined with '---')
    yaml_status = "FAILED"
    n_docs = 0
    try:
        import yaml
        parsed = list(yaml.safe_load_all(result.yaml_output))
        n_docs = sum(1 for d in parsed if d)
        yaml_status = "OK"
    except Exception as exc:
        yaml_status = f"FAILED ({exc})"
    print(f"  YAML parse:        {yaml_status} ({n_docs} document(s))")

    # YAML preview — first 40 lines per rule, indented for readability
    yaml_lines = result.yaml_output.splitlines()
    print(f"\n  --- YAML PREVIEW ---")
    rule_doc_start = 0
    for idx, line in enumerate(yaml_lines):
        if line.strip() == "---" or idx == len(yaml_lines) - 1:
            end = idx if line.strip() == "---" else idx + 1
            print(f"      [doc {rule_doc_start + 1}]")
            for sub_line in yaml_lines[rule_doc_start:end]:
                print(f"          {sub_line}")
            rule_doc_start = end + 1 if line.strip() == "---" else end
            print()

    if os.getenv("CVE_TI_DUMP_YAML", "0").lower() in ("1", "true", "yes"):
        out_path = ROOT / "generated_rules" / f"{enriched.core.cve_id}_step6.yaml"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(result.yaml_output, encoding="utf-8")
        print(f"  YAML dumped to:    {out_path}")

    # DEBUG MODE
    if debug_mode:
        print(f"\n  [DEBUG MODE]")
        print(f"  First 30 lines of YAML:")
        for line in result.yaml_output.splitlines()[:30]:
            print(f"      {line}")


async def run_interactive_pipeline(cve_id: str) -> bool:
    print("=" * 80)
    print(f" BẮT ĐẦU QUY TRÌNH KIỂM THỬ INTERACTIVE (STEP 1 + 2 + 4 + 6) — {cve_id}")
    print("=" * 80)

    step12 = await _run_step1_and_2(cve_id)
    if step12 is None:
        return True
    enriched, capability_classification = step12

    telemetry_dict = await _run_step4(enriched, capability_classification)

    await _run_step6(enriched, telemetry_dict)

    _section("METADATA")
    print(f"  CVE:                    {cve_id}")
    print(f"  AI steps used:          step2 AI + step4 AI + step6 AI (nếu enabled)")
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
        print(" TEST BATCH STEP 1 + 2 + 4 + 6 E2E TỪ OPENCTI")
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
