from __future__ import annotations

import asyncio
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.triage.orchestrator import TriageOrchestrator


def _print_list(items: list[str] | None) -> None:
    if not items:
        print("- none")
        return
    for item in items:
        print(f"- {item}")


async def main(cve_id: str) -> None:
    orchestrator = TriageOrchestrator()
    enriched = await orchestrator.orchestrate(cve_id)

    summary = {
        "cve_id": enriched.core.cve_id,
        "severity": enriched.core.severity,
        "cvss_score": enriched.core.cvss_score,
        "epss_score": enriched.triage.epss_score,
        "priority": enriched.triage.priority,
        "provider_status": enriched.provider_status,
        "provider_errors": enriched.provider_errors,
        "metadata": enriched.metadata.model_dump(mode="json", exclude_none=True),
    }

    print(f"=============================")
    print(f" REPORT FOR: {summary['cve_id']}")
    print(f"=============================\n")

    # 1. KHỐI CORE (Dữ liệu gốc từ NVD)
    print("[CORE]")
    print(f"Severity: {summary['severity']}")
    print(f"CVSS Score: {summary['cvss_score']}")
    print(f"CVSS Vector: {getattr(enriched.core, 'cvss_vector', 'None')}")
    print(f"CWE IDs: {getattr(enriched.core, 'cwe_ids', 'None')}")
    print(f"CPEs (Sản phẩm bị ảnh hưởng): {getattr(enriched.core, 'cpes', 'None')}")
    print(f"EPSS Score: {summary['epss_score']}")
    print(f"Priority: {summary['priority']}")
    print()

    # 2. KHỐI DESCRIPTION
    print("[DESCRIPTION]")
    print(getattr(enriched.core, 'description', 'None (Cần team Enrichment pull về!)'))
    print()

    # 3. KHỐI THREAT INTEL (Bối cảnh Tình báo)
    print("[THREAT INTEL & EXPOSURE]")
    print(f"In CISA KEV (Đang bị khai thác): {getattr(enriched.triage, 'in_kev', 'None')}")
    print(f"Ransomware Usage: {getattr(enriched.triage, 'ransomware_usage', 'False')}")
    print(f"Internet Exposure (Shodan): {getattr(enriched.triage, 'internet_exposure', 'None')} instances")
    print("Observed Threat Actors:")
    _print_list(getattr(enriched.triage, 'threat_actors', None))
    print("Public PoC References:")
    _print_list(getattr(enriched.triage, 'poc_references', None))
    print()

    # 3.5. KHỐI BẢN GHI TRIAGE CHUẨN RUNBOOK (GO / NO-GO)
    print("[TRIAGE RECORD (Quyết định phân tích)]")
    print(f"Capability (in_scope/out_of_scope): {getattr(enriched.triage, 'capability_assessment', 'None')}")
    print(f"Quyết định (GO / NO-GO): {getattr(enriched.triage, 'decision', 'None')}")
    print(f"Lý do: {getattr(enriched.triage, 'rationale', 'None')}")
    print()

    # 4. KHỐI ANALYSIS (Sau này AI sẽ fill vào)
    print("[ANALYSIS]")
    if enriched.analysis:
        print(f"Type: {getattr(enriched.analysis, 'vulnerability_type', 'None')}")
        print(f"Exploit vector: {getattr(enriched.analysis, 'exploit_vector', 'None')}")
        print(f"Remote exploitable: {getattr(enriched.analysis, 'remote_exploitable', 'None')}")
        print(f"Pre-auth: {getattr(enriched.analysis, 'pre_auth', 'None')}")
        print(f"Exploit complexity: {getattr(enriched.analysis, 'exploit_complexity', 'None')}")
        print(f"Confidence: {getattr(enriched.analysis, 'confidence', 'None')}")
        print(f"Analysis confidence: {getattr(enriched.analysis, 'analysis_confidence', 'None')}")
        print(f"Likely outcome: {getattr(enriched.analysis, 'likely_outcome', 'None')}")
        
        print("Classification reason (Lý do phân loại):")
        _print_list(getattr(enriched.analysis, 'classification_reason', None))
        print()
        print("Behavior reason (Chuỗi hành vi):")
        _print_list(getattr(enriched.analysis, 'behavior_reason', None))
        print()
        print("Mandatory behaviors (Hành vi bắt buộc):")
        _print_list(getattr(enriched.analysis, 'mandatory_behaviors', None))
        print()
        print("Evasive indicators:")
        _print_list(getattr(enriched.analysis, 'evasive_indicators', None))
        print()
        print("Exploit requirements:")
        _print_list(getattr(enriched.analysis, 'exploit_requirements', None))
    else:
        print("No analysis context")
    print()

    # 5. KHỐI ATT&CK
    print("[ATT&CK]")
    if enriched.attack:
        print("Tactics:")
        _print_list(getattr(enriched.attack, 'tactics', None))
        print()
        print("Techniques:")
        _print_list(getattr(enriched.attack, 'techniques', None))
        print()
        print("Subtechniques:")
        _print_list(getattr(enriched.attack, 'subtechniques', None))
        print()
        print(f"Confidence: {getattr(enriched.attack, 'confidence', 'None')}")
        print(f"Attack mapping confidence: {getattr(enriched.attack, 'attack_mapping_confidence', 'None')}")
        print("Mapping reasons:")
        _print_list(getattr(enriched.attack, 'mapping_reasons', None))
    else:
        print("No ATT&CK mapping")
    print()

    # 6. KHỐI TELEMETRY
    print("[TELEMETRY]")
    if enriched.telemetry:
        print("Detection axis:")
        _print_list(getattr(enriched.telemetry, 'detection_axis', None))
        print()
        print("Candidate logsources:")
        _print_list(getattr(enriched.telemetry, 'candidate_logsources', None))
        print()
        print("Required events:")
        _print_list(getattr(enriched.telemetry, 'required_events', None))
        print()
        print("Required fields:")
        _print_list(getattr(enriched.telemetry, 'required_fields', None))
        print()
        print("Validated fields:")
        _print_list(getattr(enriched.telemetry, 'validated_fields', None))
        print()
        print("Invalid fields:")
        _print_list(getattr(enriched.telemetry, 'invalid_fields', None))
        print()
        print(f"Telemetry confidence: {getattr(enriched.telemetry, 'telemetry_confidence', 'None')}")
        print(f"Correlation required: {getattr(enriched.telemetry, 'correlation_required', 'None')}")
        print("Taxonomy warnings:")
        _print_list(getattr(enriched.telemetry, 'taxonomy_warnings', None))
        print()
        print("Field taxonomy notes:")
        _print_list(getattr(enriched.telemetry, 'field_taxonomy_notes', None))
    else:
        print("No telemetry mapping")
    print()

    # 7. KHỐI COVERAGE
    print("[COVERAGE]")
    if enriched.coverage:
        print(f"Decision: {getattr(enriched.coverage, 'decision', 'None')}")
        print(f"Overlap score: {getattr(enriched.coverage, 'overlap_score', 'None')}")
        print(f"Relationship type: {getattr(enriched.coverage, 'relationship_type', 'None')}")
        print("Overlap breakdown:")
        if getattr(enriched.coverage, 'overlap_breakdown', None):
            for key, value in enriched.coverage.overlap_breakdown.items():
                print(f"- {key}: {value}")
        else:
            print("- none")
        print("Matched rule ids:")
        _print_list(getattr(enriched.coverage, 'matched_rule_ids', None))
        print()
        print("Matched titles:")
        _print_list(getattr(enriched.coverage, 'matched_titles', None))
        print()
        print("Related rules:")
        _print_list(getattr(enriched.coverage, 'related_rules', None))
        print()
        print("Related ATT&CK rules:")
        _print_list(getattr(enriched.coverage, 'related_attack_rules', None))
        print()
        print("Similarity reasoning:")
        _print_list(getattr(enriched.coverage, 'similarity_reasoning', None))
        print()
        print(f"Decision reason: {getattr(enriched.coverage, 'decision_reason', 'None')}")
        print(f"Reasoning: {getattr(enriched.coverage, 'reasoning', 'None')}")
    else:
        print("No coverage assessment")
    print()

    # 8. KHỐI PROVIDERS & METADATA
    print("[PROVIDERS]")
    for provider, status in summary["provider_status"].items():
        print(f"{provider}: {status}")
    if summary["provider_errors"]:
        print("Provider errors:")
        for provider, error in summary["provider_errors"].items():
            print(f"- {provider}: {error}")
    print()

    print("[METADATA]")
    print(f"Partial enrichment: {summary['metadata'].get('partial_enrichment')}")
    print(f"Pipeline duration: {summary['metadata'].get('enrichment_duration_ms')} ms")


if __name__ == "__main__":
    target_cve = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    asyncio.run(main(target_cve))