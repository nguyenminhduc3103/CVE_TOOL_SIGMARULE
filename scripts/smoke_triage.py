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

    print(summary["cve_id"])
    print("[CORE]")
    print(f"Severity: {summary['severity']}")
    print(f"CVSS: {summary['cvss_score']}")
    print(f"EPSS: {summary['epss_score']}")
    print(f"Priority: {summary['priority']}")
    print()

    print("[ANALYSIS]")
    if enriched.analysis:
        print(f"Capability: {enriched.triage.capability_assessment}")
        print(f"Type: {enriched.analysis.vulnerability_type}")
        print(f"Exploit vector: {enriched.analysis.exploit_vector}")
        print(f"Remote exploitable: {enriched.analysis.remote_exploitable}")
        print(f"Pre-auth: {enriched.analysis.pre_auth}")
        print(f"Exploit complexity: {enriched.analysis.exploit_complexity}")
        print(f"Confidence: {enriched.analysis.confidence}")
        print(f"Analysis confidence: {enriched.analysis.analysis_confidence}")
        print(f"Likely outcome: {enriched.analysis.likely_outcome}")
        print("Classification reason:")
        _print_list(enriched.analysis.classification_reason)
        print()
        print("Behavior reason:")
        _print_list(enriched.analysis.behavior_reason)
        print()
        print("Mandatory behaviors:")
        _print_list(enriched.analysis.mandatory_behaviors)
        print()
        print("Evasive indicators:")
        _print_list(enriched.analysis.evasive_indicators)
        print()
        print("Exploit requirements:")
        _print_list(enriched.analysis.exploit_requirements)
    else:
        print("No analysis context")
    print()

    print("[ATT&CK]")
    if enriched.attack:
        print("Tactics:")
        _print_list(enriched.attack.tactics)
        print()
        print("Techniques:")
        _print_list(enriched.attack.techniques)
        print()
        print("Subtechniques:")
        _print_list(enriched.attack.subtechniques)
        print()
        print(f"Confidence: {enriched.attack.confidence}")
        print(f"Attack mapping confidence: {enriched.attack.attack_mapping_confidence}")
        print("Mapping reasons:")
        _print_list(enriched.attack.mapping_reasons)
    else:
        print("No ATT&CK mapping")
    print()

    print("[TELEMETRY]")
    if enriched.telemetry:
        print("Detection axis:")
        _print_list(enriched.telemetry.detection_axis)
        print()
        print("Candidate logsources:")
        _print_list(enriched.telemetry.candidate_logsources)
        print()
        print("Required events:")
        _print_list(enriched.telemetry.required_events)
        print()
        print("Required fields:")
        _print_list(enriched.telemetry.required_fields)
        print()
        print("Validated fields:")
        _print_list(enriched.telemetry.validated_fields)
        print()
        print("Invalid fields:")
        _print_list(enriched.telemetry.invalid_fields)
        print()
        print(f"Telemetry confidence: {enriched.telemetry.telemetry_confidence}")
        print(f"Correlation required: {enriched.telemetry.correlation_required}")
        print("Taxonomy warnings:")
        _print_list(enriched.telemetry.taxonomy_warnings)
        print()
        print("Field taxonomy notes:")
        _print_list(enriched.telemetry.field_taxonomy_notes)
    else:
        print("No telemetry mapping")
    print()

    print("[COVERAGE]")
    if enriched.coverage:
        print(f"Decision: {enriched.coverage.decision}")
        print(f"Overlap score: {enriched.coverage.overlap_score}")
        print(f"Relationship type: {enriched.coverage.relationship_type}")
        print("Overlap breakdown:")
        if enriched.coverage.overlap_breakdown:
            for key, value in enriched.coverage.overlap_breakdown.items():
                print(f"- {key}: {value}")
        else:
            print("- none")
        print("Matched rule ids:")
        _print_list(enriched.coverage.matched_rule_ids)
        print()
        print("Matched titles:")
        _print_list(enriched.coverage.matched_titles)
        print()
        print("Related rules:")
        _print_list(enriched.coverage.related_rules)
        print()
        print("Related ATT&CK rules:")
        _print_list(enriched.coverage.related_attack_rules)
        print()
        print("Similarity reasoning:")
        _print_list(enriched.coverage.similarity_reasoning)
        print()
        print(f"Decision reason: {enriched.coverage.decision_reason}")
        print(f"Reasoning: {enriched.coverage.reasoning}")
    else:
        print("No coverage assessment")
    print()

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
