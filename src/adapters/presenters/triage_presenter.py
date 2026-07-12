from __future__ import annotations

import sys
from src.shared.parsers.cvss_parser import parse_cvss

def _print_list(items: list[str] | None, indent: str = "  ") -> None:
    if not items:
        print(f"{indent}- none")
        return
    for item in items:
        print(f"{indent}- {item}")


def print_triage_summary(enriched) -> None:
    print("=" * 80)
    print(" TRIAGE SUMMARY REPORT")
    print("=" * 80)
    
    # Chuẩn bị dữ liệu
    cve_id = enriched.core.cve_id
    severity = enriched.core.severity or "none"
    cvss_score = enriched.core.cvss_score or "none"
    cvss_vector = enriched.core.cvss_vector or "none"
    cwe_ids = ", ".join(enriched.core.cwe_ids) if enriched.core.cwe_ids else "none"
    
    in_kev = str(enriched.triage.in_kev)
    ransomware_usage = str(enriched.triage.ransomware_usage)
    
    epss_val = enriched.triage.epss_score
    if epss_val is not None:
        epss_pct = epss_val * 100
        epss_score = f"{epss_val:.5f} ({epss_pct:.3f}%)"
    else:
        epss_score = "None"
        
    public_poc = str(enriched.triage.public_poc)
    observed_in_the_wild = str(enriched.triage.observed_in_the_wild)
    
    actors = enriched.triage.threat_actors or ["none"]
    actors_str = ", ".join(actors)
    
    capability = enriched.triage.capability_assessment or "None"
    priority = enriched.triage.priority or "None"
    priority_score = str(enriched.triage.priority_score) if enriched.triage.priority_score is not None else "None"
    decision = enriched.triage.decision or "None"

    # In các thuộc tính theo đúng thứ tự yêu cầu
    print(f"{'cve_id:':<24}{cve_id}")
    print(f"{'severity:':<24}{severity}")
    print(f"{'cvss_score:':<24}{cvss_score}")
    print(f"{'cvss_vector:':<24}{cvss_vector}")
    print(f"{'cwe_ids:':<24}{cwe_ids}")
    print(f"{'in_kev:':<24}{in_kev}")
    print(f"{'ransomware_usage:':<24}{ransomware_usage}")
    print(f"{'epss_score:':<24}{epss_score}")
    print(f"{'public_poc:':<24}{public_poc}")
    print(f"{'observed_in_the_wild:':<24}{observed_in_the_wild}")
    print(f"{'threat_actors:':<24}{actors_str}")
    print(f"{'capability_assessment:':<24}{capability}")
    print(f"{'priority:':<24}{priority}")
    print(f"{'priority_score:':<24}{priority_score}")
    print(f"{'decision:':<24}{decision}")
    
    # decision_reason
    reason = (enriched.triage.decision_reason or "").strip()
    reason_lines = reason.splitlines() if reason else ["None"]
    print(f"{'decision_reason:':<24}{reason_lines[0]}")
    for r_line in reason_lines[1:]:
        print(f"{'':<24}{r_line}")
        
    print()  # Dòng trống phân tách
    
    # cpes
    products = enriched.core.affected_products or enriched.core.cpes or ["none"]
    cpes_label = f"cpes ({len(products)}):"
    print(f"{cpes_label:<24}{products[0]}")
    for prod in products[1:]:
        print(f"{'':<24}{prod}")
        
    print()  # Dòng trống phân tách
    
    # poc_references
    pocs = enriched.triage.poc_references or ["none"]
    print(f"{'poc_references:':<24}{pocs[0]}")
    for poc in pocs[1:]:
        print(f"{'':<24}{poc}")

    print("=" * 80)
    print()


def print_description(enriched) -> None:
    print("[DESCRIPTION]")
    desc = (enriched.core.description or "").strip()
    if desc:
        for line in desc.splitlines():
            print(f"  {line}")
    else:
        print("  (empty)")
    print()
