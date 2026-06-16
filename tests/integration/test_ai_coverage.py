"""Test đánh giá AI Bước 2 phân tích đủ & chuẩn so với Ground Truth.

3 tiêu chí:
1. CWE coverage: AI có phân tích ra TẤT CẢ CWE từ NVD không
2. Behavior coverage: AI có extract đủ mandatory_behaviors không
3. TTP coverage: AI có map đủ MITRE techniques không

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
from app.steps.step_2_tech_analysis.gap_analysis import (
    compute_ground_truth,
    compute_coverage as compute_ai_coverage,
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
    """Chạy Bước 1 + Bước 2 cho 1 CVE, tính coverage score."""
    orch = TriageOrchestrator()
    enriched = await orch.orchestrate(cve_id)

    # Serialize theo format target
    ai_output = serialize_step1_step2(enriched)

    # Tính ground truth (rule-based, deterministic)
    ground_truth = compute_ground_truth(
        cve_id=enriched.core.cve_id,
        description=enriched.core.description,
        cwe_ids=enriched.core.cwe_ids,
        cvss_vector=enriched.core.cvss_vector,
    )

    # Tính coverage
    coverage = compute_ai_coverage(ai_output, ground_truth)

    return {
        "cve_id": cve_id,
        "ai_output": ai_output,
        "ground_truth": {k: sorted(v) for k, v in ground_truth.items()},
        "coverage": coverage,
    }


async def main() -> int:
    print("=" * 80)
    print(" AI COVERAGE TEST: BƯỚC 2 PHÂN TÍCH ĐỦ CHUẨN SO VỚI GROUND TRUTH?")
    print("=" * 80)

    all_results = []
    for cve_id in CVE_TEST:
        print(f"\n{'─' * 80}")
        print(f"  {cve_id}")
        print(f"{'─' * 80}")

        result = await evaluate_cve(cve_id)
        all_results.append(result)

        ai = result["ai_output"]
        cov = result["coverage"]
        gt = result["ground_truth"]

        print(f"\n  [NVD - Ground Truth]")
        print(f"    CWE IDs:     {gt['expected_cwes']}")
        print(f"    Behaviors:   {gt['expected_behaviors']}")
        print(f"    Techniques:  {gt['expected_techniques']}")
        print(f"    Tactics:     {gt['expected_tactics']}")

        print(f"\n  [AI Output]")
        tech = ai.get("technical_analysis", {})
        atk = ai.get("attack_mapping", {})
        print(f"    CWE IDs:     {tech.get('cwe_metadata', {}).get('cwe_ids', [])}")
        print(f"    Behaviors:   {tech.get('mandatory_behaviors', [])}")
        print(f"    Techniques:  {atk.get('techniques', [])}")
        print(f"    Tactics:     {atk.get('tactics', [])}")

        print(f"\n  [Coverage Score]")
        print(f"    CWE coverage:      {cov['cwe_coverage']:.0%}  (missing: {cov['missing_cwes']})")
        print(f"    Behavior coverage: {cov['behavior_coverage']:.0%}  (missing: {cov['missing_behaviors']})")
        print(f"    TTP coverage:      {cov['ttp_coverage']:.0%}  (missing: {cov['missing_techniques']})")
        print(f"    ─────────────────────────────────────")
        print(f"    Overall:           {cov['overall_coverage']:.0%}  → {cov['verdict']}")

        if cov["extra_techniques"]:
            print(f"    ⚠️  Extra techniques (AI bịa?): {cov['extra_techniques']}")

    # Summary
    print(f"\n{'=' * 80}")
    print(" SUMMARY")
    print("=" * 80)
    print(f"{'CVE':<20} {'CWE':<8} {'Behav':<8} {'TTP':<8} {'Overall':<10} Verdict")
    print("-" * 80)
    for r in all_results:
        c = r["coverage"]
        print(
            f"{r['cve_id']:<20} "
            f"{c['cwe_coverage']:.0%}{'':5} "
            f"{c['behavior_coverage']:.0%}{'':5} "
            f"{c['ttp_coverage']:.0%}{'':5} "
            f"{c['overall_coverage']:.0%}{'':5} "
            f"{c['verdict']}"
        )

    # Overall verdict
    n_pass = sum(1 for r in all_results if r["coverage"]["verdict"] == "PASS")
    n_partial = sum(1 for r in all_results if r["coverage"]["verdict"] == "PARTIAL")
    n_fail = sum(1 for r in all_results if r["coverage"]["verdict"] == "FAIL")
    print()
    print(f"  PASS:    {n_pass}/{len(all_results)}")
    print(f"  PARTIAL: {n_partial}/{len(all_results)}")
    print(f"  FAIL:    {n_fail}/{len(all_results)}")

    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
