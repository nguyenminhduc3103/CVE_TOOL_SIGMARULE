from __future__ import annotations

from src.domain.models.telemetry import SigmaLogsource


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


# Free-form term → SigmaLogsource resolver (for AI candidate_logsources).
# AI emit terms như "apache", "java", "ldap" — code layer normalize về SigmaLogsource.
_SERVICE_TO_LOGSOURCE: dict[str, SigmaLogsource] = {
    "apache": SigmaLogsource(category="webserver", product="linux", service="apache"),
    "nginx": SigmaLogsource(category="webserver", product="linux", service="nginx"),
    "iis": SigmaLogsource(category="webserver", product="windows", service="iis"),
    "tomcat": SigmaLogsource(category="webserver", product="linux", service="tomcat"),
    "sysmon": SigmaLogsource(category="process_creation", product="windows"),
    "edr": SigmaLogsource(category="process_creation", product="windows"),
    "zeek": SigmaLogsource(category="network_connection", product="zeek"),
    "suricata": SigmaLogsource(category="network_connection", product="suricata"),
    "ldap": SigmaLogsource(category="network_connection", product="windows"),
    "dns": SigmaLogsource(category="dns_query", product="windows"),
    "dns_query": SigmaLogsource(category="dns_query", product="windows"),
    "powershell": SigmaLogsource(category="ps_script", product="windows"),
    "firewall": SigmaLogsource(category="firewall", product="windows"),
    "antivirus": SigmaLogsource(category="antivirus", product="windows"),
    "java": SigmaLogsource(category="process_creation", product="windows"),
    "process": SigmaLogsource(category="process_creation", product="windows"),
    "process_creation": SigmaLogsource(category="process_creation", product="windows"),
    "network": SigmaLogsource(category="network_connection", product="windows"),
    "network_connection": SigmaLogsource(category="network_connection", product="windows"),
    "webserver": SigmaLogsource(category="webserver", product="linux", service="apache"),
    "web": SigmaLogsource(category="webserver", product="linux", service="apache"),
    "file": SigmaLogsource(category="file_event", product="windows"),
    "file_event": SigmaLogsource(category="file_event", product="windows"),
    "registry": SigmaLogsource(category="registry_event", product="windows"),
    "registry_event": SigmaLogsource(category="registry_event", product="windows"),
    "image_load": SigmaLogsource(category="image_load", product="windows"),
}


def map_logsources_from_candidates(
    candidate_logsources: list[str] | None,
    mandatory_behaviors: list[str] | None = None,
    techniques: list[str] | None = None,
) -> list[SigmaLogsource]:
    """Map free-form AI terms → schema-enforced SigmaLogsource.

    Flow: (1) resolve free-form qua _SERVICE_TO_LOGSOURCE; (2) bổ sung từ
    mandatory_behaviors → BEHAVIOR_TO_LOGSOURCE; (3) bổ sung từ techniques →
    TECHNIQUE_TO_LOGSOURCE; (4) dedup theo (category, product, service).
    """
    logsources: list[SigmaLogsource] = []
    seen: set[tuple[str, str, str | None]] = set()

    def _add(logsource: SigmaLogsource | None) -> None:
        if logsource is None:
            return
        key = (logsource.category, logsource.product, logsource.service)
        if key in seen:
            return
        seen.add(key)
        logsources.append(logsource)

    # Free-form candidate terms
    for term in candidate_logsources or []:
        normalized = term.strip().lower()
        if not normalized:
            continue
        mapped = _SERVICE_TO_LOGSOURCE.get(normalized)
        if mapped is not None:
            _add(mapped)
            continue
        # Term không match whitelist → skip silently. taxonomy_validator sẽ warn field sai.

    # Bổ sung từ mandatory_behaviors
    for behavior in mandatory_behaviors or []:
        mapped = BEHAVIOR_TO_LOGSOURCE.get(behavior)
        if mapped is not None:
            _add(mapped[0])

    # Bổ sung từ techniques
    for technique in techniques or []:
        mapped = TECHNIQUE_TO_LOGSOURCE.get(technique)
        if mapped is not None:
            _add(mapped[0])

    return logsources


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
