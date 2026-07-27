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


def _format_artifact_type(artifact) -> str:
    """Format artifact type for display."""
    artifact_type = artifact.artifact_type
    if hasattr(artifact_type, 'value'):
        artifact_type = artifact_type.value

    # Convert snake_case to Title Case
    title = artifact_type.replace("_", " ").title()
    return title


def _format_evidence_type(evidence_type) -> str:
    """Format evidence type for display."""
    ev_type = evidence_type
    if hasattr(ev_type, 'value'):
        ev_type = ev_type.value

    labels = {
        "raw_log": "Raw Log",
        "xml": "XML Event",
        "evtx": "EVTX File",
        "pcap": "PCAP File",
        "markdown": "Markdown Table",
        "documentation": "Documentation",
        "not_found": "Not Found",
    }
    return labels.get(ev_type, ev_type.replace("_", " ").title())


def _format_verification_label(method) -> str:
    """Format verification method for display."""
    method_str = method
    if hasattr(method, 'value'):
        method_str = method.value

    labels = {
        "raw_event": "Raw Event Found",
        "vendor_log": "Sample Log Found",
        "documentation": "Telemetry Description Found",
        "not_found": "Not Found",
    }
    return labels.get(method_str, method_str)


def _print_wrapped(text: str, indent: str = "    ", width: int = 76) -> None:
    """Print text with word wrapping."""
    words = text.split()
    line = indent
    for word in words:
        if len(line) + len(word) + 1 > width:
            print(line)
            line = indent + word
        else:
            line += " " + word
    if line.strip():
        print(line)


def _print_separator() -> None:
    """Print separator line."""
    print("  " + "-" * 76)


def print_telemetry_discovery(enriched) -> None:
    """Print Step 1.3/1.4 Two-Phase Telemetry Discovery results.

    NEW format per user requirements:
    - Phase A: "Telemetry providers" (not "Found")
    - Phase B: Evidence Extraction with source + evidence_type + evidence_content
    - Gate: Professional reasoning format

    Evidence Extraction (NO AI):
    - Parser/regex extracts log blocks from content
    - Evidence is VERBATIM, not generated
    """
    print("=" * 80)
    print(" TELEMETRY DISCOVERY (Step 1.3)")
    print("=" * 80)

    # Check if telemetry discovery exists
    if enriched.telemetry_discovery is None:
        print("  [NOT RUN] Telemetry discovery was not executed.")
        print()
        return

    discovery = enriched.telemetry_discovery
    assessment = enriched.telemetry_assessment

    # =============================================
    # PHASE A - TELEMETRY PROVIDERS (Not "Found"!)
    # =============================================
    print("\nTelemetry providers: {}".format(len(discovery.candidate_sources)))
    print("\n[PHASE A - KNOWN SEARCHABLE SOURCES]")

    if discovery.candidate_sources:
        for i, candidate in enumerate(discovery.candidate_sources, 1):
            source_type = candidate.source_type
            if hasattr(source_type, 'value'):
                source_type = source_type.value

            print(f"\n  [{i}] {candidate.source_name}")
            print(f"      Type:     {source_type}")
            print(f"      Status:   ⏳ Not yet verified")
            if candidate.reason:
                print(f"      Reason:   {candidate.reason}")
    else:
        print("  No telemetry providers configured.")

    # =============================================
    # DEBUG OUTPUT - Fetch/Extract Statistics
    # =============================================
    print("\n" + "=" * 80)
    print("[DEBUG - FETCH/EXTRACT STATISTICS]")
    print()

    # Get debug stats from sources if available
    debug_info = _get_discovery_debug_info(enriched)

    if debug_info:
        for source_name, stats in debug_info.items():
            _print_source_debug_stats(source_name, stats)
    else:
        print("  (No debug information available - run with DEBUG logging)")
        print("  Run with: python main.py --cve CVE-2021-44228 --log-level DEBUG")

    # =============================================
    # PHASE B - EVIDENCE EXTRACTION + VERIFIED ARTIFACTS
    # =============================================
    print("\n" + "=" * 80)
    print("[PHASE B - VERIFIED TELEMETRY ARTIFACTS]")
    print()

    if discovery.verified_artifacts:
        print("  Found {} verified artifact(s):".format(len(discovery.verified_artifacts)))
        print()

        for i, artifact in enumerate(discovery.verified_artifacts, 1):
            # Source name as header
            print("  [{}] {}".format(i, artifact.source_name))

            # Source type
            source_type = artifact.source_type
            if hasattr(source_type, 'value'):
                source_type = source_type.value
            source_type_label = source_type.replace("_", " ").title()
            print("  Source:           {}".format(source_type_label))

            # Artifact type
            artifact_type_label = _format_artifact_type(artifact)
            if artifact.event_id:
                artifact_type_label += f" (Event ID {artifact.event_id})"
            print("  Artifact Type:    {}".format(artifact_type_label))

            # Evidence Type
            ev_type = artifact.evidence_type
            if hasattr(ev_type, 'value'):
                ev_type = ev_type.value
            evidence_type_label = _format_evidence_type(ev_type)
            print("  Evidence Type:    {}".format(evidence_type_label))

            # Verification
            verification = artifact.verification_method
            verification_label = _format_verification_label(verification)
            print("  Verification:     ✓ {}".format(verification_label))

            # Download URL if available
            if artifact.download_url:
                print("  Download URL:     {}".format(artifact.download_url))

            print()

            # Evidence Content - VERBATIM extracted
            if artifact.evidence_content:
                print("  Content:")
                print("  " + "-" * 74)
                # Truncate if too long (max 30 lines)
                lines = artifact.evidence_content.split('\n')
                if len(lines) > 30:
                    lines = lines[:30] + ["    ... (truncated)"]
                for line in lines:
                    # Truncate individual lines too
                    if len(line) > 72:
                        line = line[:72] + "..."
                    print("  {}".format(line))
                print("  " + "-" * 74)
                print()

            _print_separator()
            print()

    else:
        print("\n  No verified telemetry artifacts found.")
        print("  Candidates were checked but no actual telemetry was found.")

    # =============================================
    # GATE ASSESSMENT - PROFESSIONAL FORMAT
    # =============================================
    print("=" * 80)
    print(" TELEMETRY ASSESSMENT (Step 1.4 - GATE)")
    print("=" * 80)

    if assessment:
        # Gate status with clear indicators
        gate_status = "✓ PASS" if not assessment.blocking else "✗ FAIL"
        gate_decision = "GO" if not assessment.blocking else "NO-GO"

        print("\n  Gate Status:      {}".format(gate_status))
        print("  Decision:         {}".format(gate_decision))
        print("  Confidence:       {}".format(
            assessment.confidence.value if hasattr(assessment.confidence, 'value') else assessment.confidence
        ))
        print("  Verified Count:   {}".format(assessment.verified_count))
        print("  Providers Searched: {}".format(assessment.candidate_count))
        print()

        # Verified evidence summary
        if assessment.verified_evidence:
            print("  Verified telemetry evidence:")
            for ev in assessment.verified_evidence:
                ev_type = ev.get("evidence_type", "")
                print("  ✓ {} documented by {}".format(
                    ev_type.replace("_", " ").title(),
                    ev["source"]
                ))
                if ev.get("event_id"):
                    print("    - Event ID {}: {}".format(
                        ev["event_id"],
                        ev.get("evidence_summary", "")
                    ))
            print()

        # Decision override message
        if assessment.blocking:
            print("  ⚠ Pipeline will STOP - No verified telemetry artifacts")
            print()
            print("  Reasoning:")
            _print_wrapped(
                "No publicly verifiable telemetry evidence found. Searched {} telemetry "
                "providers but none contained actual log samples, EVTX files, or other "
                "telemetry artifacts. Cannot generate reliable Sigma rules without "
                "observed telemetry.".format(assessment.candidate_count)
            )
            if assessment.recommendation:
                print()
                print("  Recommendation:")
                _print_wrapped(assessment.recommendation)
        else:
            print("  ✓ {} verified telemetry artifact(s) found".format(assessment.verified_count))
            print("  ✓ Pipeline can proceed with detection engineering")
            print()
            print("  Reasoning:")
            _print_wrapped(
                "Detection engineering can rely on observed telemetry instead of inferred behavior."
            )

    print("\n" + "=" * 80)
    print()


def _get_discovery_debug_info(enriched) -> dict:
    """Extract debug information from discovery sources.

    Note: This reads from structured logging context that sources populate.
    In a full implementation, this would read from a shared debug store.
    For now, we return empty dict and rely on DEBUG logs.
    """
    # TODO: Wire up a shared debug store between sources and presenter
    # The sources currently log to structlog, but we need to collect
    # this info for display in the console output.
    return {}


def _print_source_debug_stats(source_name: str, stats: dict) -> None:
    """Print debug statistics for a source in the format user requested.

    Format:
    Source: Rapid7
    Fetch: ✓
    HTML: 185421 bytes
    Code Blocks: Log=2, XML=1, Text=3, JSON=0
    XML Events: 1
    Apache Logs: 0
    EVTX Refs: 0
    PCAP Refs: 2
    Evidence: ✓ selected (Apache Log)
    """
    print(f"  Source: {source_name}")
    print("  " + "-" * 70)

    # Fetch status
    if "fetch_status" in stats:
        status = "✓" if stats["fetch_status"] == 200 else "✗"
        print(f"  Fetch: {status} (HTTP {stats['fetch_status']})")
    elif "fetch_success" in stats:
        status = "✓" if stats["fetch_success"] else "✗"
        print(f"  Fetch: {status}")

    # Content lengths
    if "fetch_length" in stats:
        print(f"  HTML: {stats['fetch_length']:,} bytes")
    if "html_length" in stats:
        print(f"  Markdown: {stats['html_length']:,} bytes")

    # Code block counts
    log_count = stats.get("code_blocks_log", 0)
    xml_count = stats.get("code_blocks_xml", 0)
    text_count = stats.get("code_blocks_text", 0)
    json_count = stats.get("code_blocks_json", 0)
    other_count = stats.get("code_blocks_other", 0)

    if any([log_count, xml_count, text_count, json_count, other_count]):
        parts = []
        if log_count:
            parts.append(f"Log={log_count}")
        if xml_count:
            parts.append(f"XML={xml_count}")
        if text_count:
            parts.append(f"Text={text_count}")
        if json_count:
            parts.append(f"JSON={json_count}")
        if other_count:
            parts.append(f"Other={other_count}")
        print(f"  Code Blocks: {', '.join(parts)}")

    # Pattern counts
    patterns = []
    if stats.get("windows_xml_events", 0):
        patterns.append(f"XML Events={stats['windows_xml_events']}")
    if stats.get("apache_logs", 0):
        patterns.append(f"Apache={stats['apache_logs']}")
    if stats.get("zeek_logs", 0):
        patterns.append(f"Zeek={stats['zeek_logs']}")
    if stats.get("suricata_events", 0):
        patterns.append(f"Suricata={stats['suricata_events']}")
    if stats.get("syslog_lines", 0):
        patterns.append(f"Syslog={stats['syslog_lines']}")
    if stats.get("event_ids", 0):
        patterns.append(f"EventIDs={stats['event_ids']}")

    if patterns:
        print(f"  Patterns: {', '.join(patterns)}")

    # File references
    refs = []
    if stats.get("evtx_refs", 0):
        refs.append(f"EVTX={stats['evtx_refs']}")
    if stats.get("pcap_refs", 0):
        refs.append(f"PCAP={stats['pcap_refs']}")
    if stats.get("log_refs", 0):
        refs.append(f"Log={stats['log_refs']}")
    if stats.get("json_refs", 0):
        refs.append(f"JSON={stats['json_refs']}")

    if refs:
        print(f"  File Refs: {', '.join(refs)}")

    # Extraction result
    if "extracted_count" in stats:
        count = stats["extracted_count"]
        if count > 0:
            print(f"  Evidence: ✓ {count} extracted")
        else:
            print(f"  Evidence: ✗ none extracted")

    # GitHub specific
    if "total_count" in stats:
        print(f"  GitHub Search: {stats['total_count']} files found")
    if "content_length" in stats and "content_fetched" in stats:
        if stats["content_fetched"]:
            print(f"  Downloaded: ✓ ({stats['content_length']:,} bytes)")
        else:
            print(f"  Downloaded: ✗ failed")

    print()
