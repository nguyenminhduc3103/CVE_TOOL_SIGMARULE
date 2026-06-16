from __future__ import annotations

from app.shared.models.telemetry import SigmaLogsource


BEHAVIOR_TO_LOGSOURCE: dict[str, tuple[SigmaLogsource, tuple[str, ...], tuple[str, ...], tuple[str, ...]]] = {
    "process_creation": (
        SigmaLogsource(category="process_creation", product="windows", service=None),
        ("process_start",),
        ("Sysmon EID 1",),
        ("CommandLine", "ParentImage", "Image"),
    ),
    "file_write": (
        SigmaLogsource(category="file_event", product="windows", service=None),
        ("file_create",),
        ("Sysmon EID 11",),
        ("TargetFilename", "FileName", "Hashes"),
    ),
    "registry_modification": (
        SigmaLogsource(category="registry_event", product="windows", service=None),
        ("registry_set",),
        ("Sysmon EID 13",),
        ("TargetObject", "Details"),
    ),
    "image_load": (
        SigmaLogsource(category="image_load", product="windows", service=None),
        ("image_load",),
        ("Sysmon EID 7",),
        ("ImageLoaded", "Image", "Signed", "Hashes"),
    ),
    "network_callback": (
        SigmaLogsource(category="network_connection", product="windows", service=None),
        ("network_connect",),
        ("Sysmon EID 3",),
        ("DestinationIp", "DestinationHostname", "DestinationPort"),
    ),
    "web_request": (
        SigmaLogsource(category="webserver", product="linux", service="apache"),
        ("http_request",),
        ("HTTP access log",),
        ("cs-uri-query", "cs-uri-stem", "c-ip"),
    ),
    "privilege_escalation": (
        SigmaLogsource(category="process_creation", product="windows", service=None),
        ("process_start",),
        ("Sysmon EID 1",),
        ("CommandLine", "ParentImage", "User"),
    ),
    "webshell_drop": (
        SigmaLogsource(category="file_event", product="windows", service=None),
        ("file_create",),
        ("Sysmon EID 11",),
        ("TargetFilename", "Hash", "CommandLine"),
    ),
}


TECHNIQUE_TO_LOGSOURCE: dict[str, tuple[SigmaLogsource, tuple[str, ...], tuple[str, ...], tuple[str, ...]]] = {
    "T1059": (
        SigmaLogsource(category="process_creation", product="windows", service=None),
        ("process_start",),
        ("Sysmon EID 1",),
        ("CommandLine", "ParentImage"),
    ),
    "T1068": (
        SigmaLogsource(category="process_creation", product="windows", service=None),
        ("process_start",),
        ("Sysmon EID 1",),
        ("CommandLine", "ParentImage", "User"),
    ),
    "T1190": (
        SigmaLogsource(category="webserver", product="linux", service="apache"),
        ("http_request",),
        ("HTTP access log",),
        ("cs-uri-query", "cs-uri-stem", "c-ip"),
    ),
    "T1505.003": (
        SigmaLogsource(category="webserver", product="linux", service="apache"),
        ("http_request", "http_response"),
        ("HTTP access log",),
        ("cs-uri-query", "cs-uri-stem", "c-ip"),
    ),
    "T1046": (
        SigmaLogsource(category="network_connection", product="windows", service=None),
        ("network_connect",),
        ("Sysmon EID 3",),
        ("DestinationIp", "DestinationHostname", "DestinationPort"),
    ),
    "T1071": (
        SigmaLogsource(category="network_connection", product="windows", service=None),
        ("network_connect",),
        ("Sysmon EID 3",),
        ("DestinationIp", "DestinationHostname", "DestinationPort"),
    ),
    "T1105": (
        SigmaLogsource(category="network_connection", product="windows", service=None),
        ("network_connect",),
        ("Sysmon EID 3",),
        ("DestinationIp", "DestinationHostname", "DestinationPort"),
    ),
}


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def map_logsources(
    mandatory_behaviors: list[str] | None,
    techniques: list[str] | None,
) -> tuple[list[SigmaLogsource], list[str], list[str], list[str]]:
    logsources: list[SigmaLogsource] = []
    events: list[str] = []
    event_ids: list[str] = []
    fields: list[str] = []

    for behavior in mandatory_behaviors or []:
        mapped = BEHAVIOR_TO_LOGSOURCE.get(behavior)
        if not mapped:
            continue
        logsource, required_events, required_event_ids, required_fields = mapped
        logsources.append(logsource)
        events.extend(required_events)
        event_ids.extend(required_event_ids)
        fields.extend(required_fields)

    for technique in techniques or []:
        mapped = TECHNIQUE_TO_LOGSOURCE.get(technique)
        if not mapped:
            continue
        logsource, required_events, required_event_ids, required_fields = mapped
        logsources.append(logsource)
        events.extend(required_events)
        event_ids.extend(required_event_ids)
        fields.extend(required_fields)

    unique_logsources: list[SigmaLogsource] = []
    seen = set()
    for logsource in logsources:
        key = (logsource.category, logsource.product, logsource.service)
        if key in seen:
            continue
        seen.add(key)
        unique_logsources.append(logsource)

    return unique_logsources, _unique(events), _unique(event_ids), _unique(fields)
