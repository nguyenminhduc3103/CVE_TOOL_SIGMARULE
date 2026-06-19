"""Test đánh giá AI Bước 2 - validate output qua 3 lớp.

Theo Hướng D (sau khi bỏ CAPEC ground truth):
1. Format: techniques match whitelist MITRE
2. Semantic: techniques không mâu thuẫn CVE context
3. Sigma: techniques có Sigma rule hiện có cover không

KHÔNG đo coverage score (đã chứng minh CAPEC union quá rộng,
AI luôn bị FAIL dù phân tích đúng - xem CVE-2023-49103 case).

Run: python -X utf8 -m tests.integration.test_ai_coverage
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.steps.step_1_triage.orchestrator import TriageOrchestrator
from app.steps.step_2_tech_analysis.rule_based.attack_validator import (
    validate_against_cve_context,
    filter_attack_mapping,
)


def serialize_step1_step2(enriched) -> dict:
    """Inline serializer: trả về dict JSON-serializable cho Bước 1+2 output."""
    return {
        "cve_id": enriched.core.cve_id,
        "core": enriched.core.model_dump(mode="json", exclude_none=True),
        "triage": enriched.triage.model_dump(mode="json", exclude_none=True),
        "technical_analysis": (
            enriched.analysis.model_dump(mode="json", exclude_none=True)
            if enriched.analysis else None
        ),
        "attack_mapping": (
            enriched.attack.model_dump(mode="json", exclude_none=True)
            if enriched.attack else None
        ),
        "provider_status": enriched.provider_status,
        "provider_errors": enriched.provider_errors,
        "ai_steps_used": enriched.metadata.ai_steps_used,
    }


CVE_TEST = [
    "CVE-2021-44228",  # Log4Shell
]


async def evaluate_cve(cve_id: str) -> dict:
    """Chạy Bước 1 + Bước 2 cho 1 CVE, validate qua 3 lớp."""
    orch = TriageOrchestrator()
    enriched = await orch.orchestrate(cve_id)
    ai_output = serialize_step1_step2(enriched)

    # Lớp 1: Format MITRE
    atk = ai_output.get("attack_mapping") or {}
    fmt = filter_attack_mapping(
        tactics=atk.get("tactics") or [],
        techniques=atk.get("techniques") or [],
        subtechniques=atk.get("subtechniques") or [],
    )

    # Lớp 2: Semantic
    sem = validate_against_cve_context(
        techniques=fmt["techniques"] or [],
        cvss_vector=enriched.core.cvss_vector,
        description=enriched.core.description,
    )

    # Lớp 3: Sigma rule - SKIPPED (repo không có SigmaHQ rules)
    # Nếu sau này add SigmaHQ, thêm:
    #   from app.steps.step_3_coverage.sigma_searcher import FilesystemRuleInventory, SigmaRepositoryIndexer
    #   indexer = SigmaRepositoryIndexer(FilesystemRuleInventory("rules/"))
    #   hits = indexer.find_rules_by_techniques(sem["kept"])

    return {
        "cve_id": cve_id,
        "ai_output": ai_output,
        "validation": {
            "format_valid": fmt["techniques"] or [],
            "semantic_kept": sem["kept"],
            "semantic_dropped": sem["dropped"],
        },
    }


async def main() -> int:
    print("=" * 80)
    print(" AI VALIDATION TEST: BƯỚC 2 QUA 3 LỚP (FORMAT + SEMANTIC + SIGMA)")
    print("=" * 80)

    all_results = []
    for cve_id in CVE_TEST:
        print(f"\n{'─' * 80}")
        print(f"  {cve_id}")
        print(f"{'─' * 80}")

        result = await evaluate_cve(cve_id)
        all_results.append(result)

        ai = result["ai_output"]
        v = result["validation"]
        atk = ai.get("attack_mapping", {})

        print(f"\n  [AI Output]")
        print(f"    Techniques raw:    {atk.get('techniques', [])}")

        print(f"\n  [Lớp 1: Format]")
        print(f"    Valid techniques:  {v['format_valid']}")

        print(f"\n  [Lớp 2: Semantic]")
        print(f"    Kept:              {v['semantic_kept']}")
        print(f"    Dropped:           {v['semantic_dropped']}")

        print(f"\n  [Lớp 3: Sigma]")
        print(f"    (skipped - repo không có SigmaHQ rules)")

    # Summary
    print(f"\n{'=' * 80}")
    print(" SUMMARY")
    print("=" * 80)
    print(f"{'CVE':<20} {'Format':<8} {'Semantic':<10} {'Dropped':<8}")
    print("-" * 80)
    for r in all_results:
        v = r["validation"]
        print(
            f"{r['cve_id']:<20} "
            f"{len(v['format_valid']):<8} "
            f"{len(v['semantic_kept']):<10} "
            f"{len(v['semantic_dropped']):<8}"
        )

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
