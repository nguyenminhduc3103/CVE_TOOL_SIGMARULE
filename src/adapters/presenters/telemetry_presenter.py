from __future__ import annotations

def _print_list(items: list[str] | None, indent: str = "  ") -> None:
    if not items:
        print(f"{indent}- none")
        return
    for item in items:
        print(f"{indent}- {item}")

def print_telemetry_summary(enriched) -> None:
    if not enriched.telemetry:
        return

    t = enriched.telemetry
    print("=" * 80)
    print(" TELEMETRY & TAXONOMY ASSESSMENT REPORT (STEP 4)")
    print("=" * 80)
    
    print(f"{'Detection Axis:':<24}{t.detection_axis or 'None'}")
    print(f"{'Feasibility Score:':<24}{t.telemetry_feasibility_score or 0.0}")
    print(f"{'Confidence:':<24}{t.telemetry_confidence or 0.0}")
    print(f"{'Correlation Required:':<24}{str(t.correlation_required)}")
    
    print("\n[LOGSOURCES]")
    _print_list(t.candidate_logsources)
    
    print("\n[DETECTION STRATEGY]")
    _print_list(t.detection_strategy)

    print("\n[REQUIRED EVENTS]")
    _print_list(t.required_events)
    
    print("\n[VALIDATED FIELDS]")
    _print_list(t.validated_fields)
    
    if t.invalid_fields:
        print("\n[INVALID FIELDS (DROPPED)]")
        _print_list(t.invalid_fields)
        
    if t.taxonomy_warnings:
        print("\n[TAXONOMY WARNINGS]")
        for w in set(t.taxonomy_warnings):
            print(f"  - {w}")

    print("=" * 80)
    print()
