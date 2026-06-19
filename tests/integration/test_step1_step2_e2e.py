"""Test end-to-end Bước 1 (Triage) + Bước 2 (Behavior + ATT&CK).

Khác với test_behavior.py (hardcode CoreCVEData, chỉ test Bước 2):
- File này gọi orchestrator thật -> Bước 1 gọi NVD/KEV/EPSS API thật
- Bước 2 nhận data từ Bước 1 -> gọi AI Groq (nếu enabled) hoặc fallback rule-based
- Tách output thành từng khối riêng (Step 1 / Step 2 / Coverage vs Ground Truth)
- Có thêm coverage % so với ground truth rule-based
- AI bịa techniques → coverage bị penalty → retry sẽ trigger

Run: python -X utf8 -m tests.integration.test_step1_step2_e2e CVE-2021-44228
     (default = CVE-2021-44228 nếu không truyền arg)
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.steps.step_1_triage.orchestrator import TriageOrchestrator
from app.steps.step_2_tech_analysis.rule_based.attack_validator import (
    filter_attack_mapping,
    validate_against_cve_context,
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


async def main(cve_id: str) -> None:
    orch = TriageOrchestrator()
    enriched = await orch.orchestrate(cve_id)

    # =========================================================================
    # STEP 1 — ENRICHMENT
    # =========================================================================
    _section(f"STEP 1 — ENRICHMENT (NVD + KEV + EPSS) for {cve_id}")
    core = enriched.core
    print(f"  Severity:       {core.severity}")
    print(f"  CVSS Score:     {core.cvss_score}")
    print(f"  CVSS Vector:    {core.cvss_vector}")
    print(f"  CWE IDs:        {core.cwe_ids or []}")
    print(f"  Published:      {core.published_at.isoformat() if core.published_at else None}")
    print(f"  Modified:       {core.modified_at.isoformat() if core.modified_at else None}")
    print(f"  Description:    {(core.description or '')[:200]}{'...' if len(core.description or '') > 200 else ''}")
    print(f"  References:     {len(core.references or [])} URLs")
    print(f"  CPEs:           {len(core.cpes or [])} entries")

    triage = enriched.triage
    print(f"  In KEV:         {triage.in_kev}")
    print(f"  KEV added:      {triage.kev_added_date.isoformat() if triage.kev_added_date else None}")
    print(f"  Ransomware:     {triage.ransomware_usage}")
    print(f"  EPSS score:     {triage.epss_score}")
    print(f"  EPSS %ile:      {triage.epss_percentile}")
    print(f"  Capability:     {triage.capability_assessment}")
    print(f"  Priority:       {triage.priority} (score={triage.priority_score})")
    print(f"  Decision:       {triage.decision}")
    print(f"  Reason:         {triage.decision_reason}")

    # =========================================================================
    # STEP 1 — PROVIDER STATUS
    # =========================================================================
    _section("STEP 1 — PROVIDER STATUS")
    for provider, status in enriched.provider_status.items():
        print(f"  {provider:6s}: {status}")
    if enriched.provider_errors:
        print("  Errors:")
        for provider, error in enriched.provider_errors.items():
            print(f"    - {provider}: {error}")

    # =========================================================================
    # STEP 2 — TECH ANALYSIS (Behavior + CWE)
    # =========================================================================
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

        # CWE metadata đầy đủ
        print(f"  CWE metadata:")
        if a.cwe_metadata:
            print(f"    cwe_ids:           {a.cwe_metadata.cwe_ids or []}")
            print(f"    cwe_names:         {a.cwe_metadata.cwe_names or []}")
            print(f"    mapping_confidence:{a.cwe_metadata.mapping_confidence}")
        else:
            print("    - none")

        # AttackFlow — 3 trường MANDATORY
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

        # Reasoning — lý do AI đưa ra kết luận
        print(f"  Reasoning ({len(a.reasoning or [])} items):")
        _print_list(a.reasoning or [])

    # =========================================================================
    # STEP 2 — ATT&CK MAPPING
    # =========================================================================
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
        # mapping_reasons — lý do AI chọn TTPs
        print(f"  Mapping reasons ({len(atk.mapping_reasons or [])}):")
        _print_list(atk.mapping_reasons or [])

    # =========================================================================
    # STEP 2 — AI USAGE
    # =========================================================================
    _section("STEP 2 — AI USAGE")
    ai_steps = enriched.metadata.ai_steps_used or []
    if ai_steps:
        print(f"  AI steps used: {ai_steps}")
        if enriched.analysis:
            print(f"  Retries:       {enriched.analysis.ai_retry_count}")
        # ai_models_used: list of every distinct model that actually fired
        # for this CVE (analyze + retry if invoked). Order-preserved.
        if enriched.analysis and enriched.analysis.ai_models_used:
            print(f"  AI models used: {enriched.analysis.ai_models_used}")
        elif enriched.attack and enriched.attack.ai_models_used:
            print(f"  AI models used: {enriched.attack.ai_models_used}")
    else:
        print("  AI not used in Bước 2 — fell back to rule-based")

    # =========================================================================
    # STEP 2 — VALIDATION (2 lớp: format + semantic)
    # =========================================================================
    # Lớp 3 (Sigma rule validation) SKIPPED - repo không có SigmaHQ rules.
    # Nếu sau này add SigmaHQ: thêm FilesystemRuleInventory("rules/") ở đây.
    _section("STEP 2 — VALIDATION (2 lớp: format + semantic)")
    atk = enriched.attack
    raw_techs = (atk.techniques if atk else None) or []
    raw_subtechs = (atk.subtechniques if atk else None) or []

    # Lớp 1: Format MITRE
    fmt = filter_attack_mapping(tactics=None, techniques=raw_techs, subtechniques=raw_subtechs)
    fmt_techs = fmt["techniques"] or []

    # Lớp 2: Semantic (MÂU THUẪN context CVE)
    sem = validate_against_cve_context(
        techniques=fmt_techs,
        cvss_vector=enriched.core.cvss_vector,
        description=enriched.core.description,
    )
    sem_kept = sem["kept"]
    sem_dropped = sem["dropped"]

    print(f"  Raw techniques (AI/rule): {raw_techs}")
    print(f"  Format valid:             {fmt_techs}")
    print(f"  Semantic kept:            {sem_kept}")
    if sem_dropped:
        print(f"  ⚠️  Semantic dropped (mâu thuẫn CVE): {sem_dropped}")
    print(f"  ─────────────────────────────────────")
    print(f"  ✓ Validation passed ({len(sem_kept)} techniques)")

    # =========================================================================
    # METADATA
    # =========================================================================
    _section("METADATA")
    print(f"  Partial enrichment:  {enriched.metadata.partial_enrichment}")
    print(f"  Pipeline duration:   {enriched.metadata.enrichment_duration_ms} ms")
    print(f"  AI steps used:       {enriched.metadata.ai_steps_used}")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    asyncio.run(main(target))
