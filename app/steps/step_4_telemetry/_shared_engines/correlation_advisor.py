from __future__ import annotations


def advise_correlation(logsources: list[str]) -> tuple[bool, list[str]]:
    notes: list[str] = []
    correlation_required = len(logsources) > 1

    if "webserver" in logsources and "process_creation" in logsources:
        correlation_required = True
        notes.append("Correlate HTTP request telemetry with downstream process creation by host and time.")

    if "network_connection" in logsources:
        notes.append("Correlate outbound network events with initiating process to reduce false positives.")

    if not notes:
        notes.append("Single-surface telemetry is sufficient for initial detection draft.")

    return correlation_required, notes
