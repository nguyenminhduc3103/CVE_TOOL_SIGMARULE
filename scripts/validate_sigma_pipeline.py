#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# ensure repo root on path
ROOT = Path(__file__).resolve().parent.parent
import sys as _sys
if str(ROOT) not in _sys.path:
    _sys.path.insert(0, str(ROOT))

from app.triage.orchestrator import TriageOrchestrator
from app.sigma_generator.services.sigma_rule_generator import SigmaRuleGenerator


async def validate(cve_id: str) -> None:
    orchestrator = TriageOrchestrator()
    enriched = await orchestrator.orchestrate(cve_id)

    print("[ENRICHED] key fields:")
    fam = getattr(enriched.analysis, "family", None)
    sig = getattr(enriched.analysis, "signature", None)
    analysis_confidence = getattr(enriched.analysis, "analysis_confidence", None)
    techniques = getattr(enriched.attack, "techniques", None)
    candidate_logsources = getattr(enriched.telemetry, "candidate_logsources", None)
    correlation_required = getattr(enriched.telemetry, "correlation_required", None)

    print(f"family: {fam}")
    print(f"signature: {sig}")
    print(f"analysis_confidence: {analysis_confidence}")
    print(f"techniques: {techniques}")
    print(f"candidate_logsources: {candidate_logsources}")
    print(f"correlation_required: {correlation_required}")
    print()

    # generate sigma
    gen = SigmaRuleGenerator()
    rule = gen.generate(enriched.core, enriched.analysis, enriched.attack, enriched.telemetry, enriched.coverage)
    yaml = rule.to_yaml()

    print("[GENERATED YAML]")
    print(yaml)

    print("[EXTRACTED METADATA]")
    print(f"x_family: {rule.x_family}")
    print(f"x_signature: {rule.x_signature}")
    print(f"x_detection_confidence: {rule.x_detection_confidence}")
    print(f"tags: {rule.metadata.tags}")
    print(f"x_correlation_required: {rule.x_correlation_required}")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    asyncio.run(validate(target))
