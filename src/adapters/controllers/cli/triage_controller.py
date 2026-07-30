from __future__ import annotations

import os
import time
from typing import Any

from src.usecases.step_1_triage.orchestrator import TriageOrchestrator
from config.settings import settings
from src.infrastructure.providers.opencti import OpenCTIProvider
from src.adapters.presenters.cli_presenter import (
    print_step1_triage,
    print_step2_analysis,
    print_step4_telemetry,
    print_step6_sigma,
    print_metadata_footer,
    _section_header,
    _subsection,
    _kv,
    _C,
    _truncate,
)


def _wait_for_user(step_description: str) -> None:
    """Bấm Enter để tiếp tục. Set CVE_TI_NONINTERACTIVE=1 để auto-skip."""
    print(f"\n👉 [BẤM ENTER] để thực hiện: {step_description}")
    if os.getenv("CVE_TI_NONINTERACTIVE", "0").lower() in ("1", "true", "yes"):
        return
    input()


def _print_nuclei_cache(cve_id: str, nuclei_raw: dict | None) -> None:
    """Print PoC Details fetched by Step 1's nuclei crawl stage.

    Length truncation honors CVE_TI_FULL_OUTPUT (opt-in via env / .env).
    """
    if not nuclei_raw:
        return

    _section_header(f"PoC Details — {cve_id}")
    status = nuclei_raw.get("status", "?")
    status_color = (
        _C.GREEN if status == "success"
        else _C.YELLOW if status == "disabled"
        else _C.RED
    )
    print(_kv("status", f"{status_color}{status}{_C.RESET}"))
    err = nuclei_raw.get("error")
    if err:
        print(_kv("error", f"{_C.RED}{_truncate(err, max_len=200)}{_C.RESET}"))

    evidence = nuclei_raw.get("evidence") or []
    print(_kv("evidence", f"{len(evidence)} record(s)"))
    if evidence:
        _subsection("Records", _C.MAGENTA)
        for rec in evidence:
            rtype = rec.get("type", "?")
            if rtype == "documentation":
                txt = (rec.get("request") or "").strip().replace("\n", " ")
                print(f"  {_C.DIM}·{_C.RESET} {_C.BOLD}documentation{_C.RESET}: {_truncate(txt, max_len=200)}")
            else:
                ri = rec.get("request_info") or {}
                method = ri.get("method", "?")
                path = ri.get("path", "?")
                print(f"  {_C.DIM}·{_C.RESET} {_C.BOLD}network{_C.RESET}: {method} {_truncate(path, max_len=200)}")
                if ri.get("body"):
                    print(f"      body: {_truncate(ri['body'], max_len=300)}")

    refs = nuclei_raw.get("references") or []
    if refs:
        _subsection("References", _C.BLUE)
        for r in refs:
            url = r.get("url") if isinstance(r, dict) else r
            print(f"  {_C.DIM}·{_C.RESET} {_C.CYAN}{url}{_C.RESET}")


class CLITriageController:
    """Controller phụ trách tiếp nhận các luồng lệnh CLI liên quan đến full pipeline.

    Flow:
      Step 1 (Triage + Enrichment) → Step 2 (Behavior + ATT&CK)
        → Step 4 (Telemetry Selector) → Step 6 (Sigma generation)

    Mỗi step sẽ skip nếu step trước fail (vd NO-GO decision ở Step 1).
    User bấm Enter giữa các step (override `CVE_TI_NONINTERACTIVE=1` để chạy thẳng).
    """

    def __init__(self) -> None:
        self.orchestrator = TriageOrchestrator()

    async def run_single_cve(self, cve_id: str) -> None:
        pipeline_start = time.perf_counter()

        print()
        print(f"{'═' * 78}")
        print(f" CVE THREAT-INTEL PIPELINE · {cve_id}")
        print(f"{'═' * 78}")

        _wait_for_user(f"Step 1: Triage & Enrichment cho {cve_id}")

        # --- STEP 1 + 2 ---
        enriched: Any | None = None
        try:
            enriched = await self.orchestrator.orchestrate(cve_id)
        except Exception as exc:
            print(f"\n[!] Step 1 failed: {exc}")
            return

        print_step1_triage(enriched)

        # --- Nuclei evidence cache (fired concurrently in Step 1's asyncio.gather) ---
        _print_nuclei_cache(cve_id, getattr(enriched, "nuclei_evidence", None))

        # NO-GO → skip downstream steps
        if (enriched.triage.decision or "").upper() in ("NO-GO", "STOP"):
            print(f"\n⚠ Pipeline halted at Step 1 (decision={enriched.triage.decision}).")
            print(f"  Skipping Step 2 / 4 / 6.")
            return

        # --- STEP 2 (analysis populated by orchestrate) ---
        _wait_for_user(f"Step 2: AI phân tích behavior + ATT&CK cho {cve_id}")
        print_step2_analysis(enriched)

        # Step 2 fail → skip Step 4/6
        if enriched.analysis is None:
            print(f"\n⚠ Step 2 produced no analysis. Skipping Step 4 / 6.")
            return

        # --- STEP 4 (Telemetry Selector) ---
        _wait_for_user(f"Step 4: AI Telemetry Selector cho {cve_id}")
        telemetry_dict: dict | None = None
        try:
            from src.usecases.step_1_triage.stages.telemetry_stage import run_telemetry_stage

            # CapabilityClassification object (not the str in triage.capability_assessment)
            capability_classification = self.orchestrator.capability_checker.classify(enriched.core)

            telemetry_assessment = await run_telemetry_stage(enriched, capability_classification)
            enriched.telemetry = telemetry_assessment
            telemetry_dict = telemetry_assessment.model_dump() if hasattr(
                telemetry_assessment, "model_dump"
            ) else dict(telemetry_assessment)
        except Exception as exc:
            print(f"\n[!] Step 4 failed: {exc}")
            import traceback
            traceback.print_exc()

        print_step4_telemetry(enriched)

        # --- STEP 6 (Sigma Generation) ---
        _wait_for_user(f"Step 6: AI Detection Logic Planner + Sigma Builder cho {cve_id}")
        result: Any = None
        if telemetry_dict is None or enriched.telemetry is None:
            print(f"\n⚠ Step 4 produced no telemetry. Skipping Step 6.")
        else:
            try:
                from src.infrastructure.ai.core import BaseAIClient
                from src.usecases.step_6_generate_sigma.orchestrator import Step6Orchestrator

                ai_client: BaseAIClient | None = None
                step6_ai_enabled = bool(getattr(settings, "step6_ai_enabled", True))
                if step6_ai_enabled and settings.get_step6_api_keys():
                    try:
                        ai_client = BaseAIClient()
                    except Exception as exc:
                        print(f"[Step 6] ⚠ Cannot create AI client: {exc}")
                        ai_client = None

                step6 = Step6Orchestrator(ai_client=ai_client)
                references = list(getattr(enriched.core, "references", []) or [])
                result = await step6.run(
                    core=enriched.core,
                    analysis=enriched.analysis,
                    attack=enriched.attack,
                    telemetry=telemetry_dict,
                    references=references,
                )
            except Exception as exc:
                print(f"\n[!] Step 6 failed: {exc}")

        print_step6_sigma(result, enriched)

        # --- Footer ---
        total_ms = int((time.perf_counter() - pipeline_start) * 1000)
        print_metadata_footer(enriched, total_ms)

    async def run_opencti_batch(self, limit: int) -> None:
        print("==========================================================")
        print(" BATCH CVE PROCESSING FROM OPENCTI")
        print("==========================================================\n")
        print(f"Connecting to OpenCTI: {settings.opencti_url}")

        if not settings.opencti_taxii_collection_id:
            print("[!] ERROR: opencti_taxii_collection_id is not set in settings/environment.")
            return

        provider = OpenCTIProvider()
        try:
            raw_bundle = await provider.client.fetch_raw_collection(limit=limit)
            cves = provider.parser.parse_bundle(raw_bundle)[:limit]
            print(f"[*] Successfully fetched {len(cves)} CVEs from OpenCTI:")
            for idx, cve in enumerate(cves, 1):
                print(f"    {idx}. {cve.cve_id}")
            print()
        except Exception as exc:
            print(f"[!] Error fetching OpenCTI TAXII collection: {exc}")
            return

        for idx, cve in enumerate(cves, 1):
            print(f"\n[{idx}/{len(cves)}] Processing {cve.cve_id}...")
            await self.run_single_cve(cve.cve_id)