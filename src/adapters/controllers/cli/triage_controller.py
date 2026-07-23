from __future__ import annotations

from src.usecases.step_1_triage.orchestrator import TriageOrchestrator
from config.settings import settings
from src.infrastructure.providers.opencti import OpenCTIProvider
from src.adapters.presenters.triage_presenter import print_triage_summary, print_description


def wait_for_user(step_description: str) -> None:
    print(f"\n👉 [BẤM ENTER] để thực hiện: {step_description}")
    input()


class CLITriageController:
    """Controller phụ trách tiếp nhận các luồng lệnh CLI liên quan đến Triage & Enrichment."""

    def __init__(self) -> None:
        self.orchestrator = TriageOrchestrator()

    async def run_single_cve(self, cve_id: str) -> None:
        wait_for_user(f"Làm giàu dữ liệu (Step 1 Triage) cho {cve_id}")
        
        print(f"==========================================================")
        print(f" TRIAGE & ENRICHMENT FOR: {cve_id}")
        print(f"==========================================================\n")

        original_ai_enabled = settings.ai_enabled
        settings.ai_enabled = False
        try:
            enriched = await self.orchestrator.orchestrate(cve_id)
        except Exception as exc:
            print(f"[!] Error during Step 1 Enrichment: {exc}")
            return
        finally:
            settings.ai_enabled = original_ai_enabled

        print_triage_summary(enriched)
        print_description(enriched)

    async def run_opencti_batch(self, limit: int) -> None:
        print("==========================================================")
        print(" BATCH CVE TRIAGE FROM OPENCTI")
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
