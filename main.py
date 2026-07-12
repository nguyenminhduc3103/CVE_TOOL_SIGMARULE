import asyncio
import sys
import argparse
import io
from pathlib import Path

# Force UTF-8 for stdout and stderr on Windows
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Add project root to sys.path
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.adapters.controllers.cli.triage_controller import CLITriageController


def main() -> None:
    parser = argparse.ArgumentParser(description="CVE Threat Intel & Sigma Generator Platform CLI")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--cve", type=str, help="Analyze a single CVE (e.g. CVE-2021-44228)")
    group.add_argument("--opencti", action="store_true", help="Batch process CVEs from OpenCTI TAXII collection")
    
    parser.add_argument("--limit", type=int, default=5, help="Batch limit for OpenCTI (default: 5)")
    
    args = parser.parse_args()

    # Ensure Selector loop policy on Windows for async HTTP clients
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    controller = CLITriageController()

    if args.cve:
        asyncio.run(controller.run_single_cve(args.cve))
    elif args.opencti:
        asyncio.run(controller.run_opencti_batch(limit=args.limit))


if __name__ == "__main__":
    main()
