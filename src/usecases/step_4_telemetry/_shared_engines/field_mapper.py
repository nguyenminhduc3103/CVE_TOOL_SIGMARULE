# Sigma category → field whitelist used by taxonomy_validator.
from __future__ import annotations


LOGSOURCE_FIELDS: dict[str, tuple[str, ...]] = {
    "process_creation": (
        "CommandLine",
        "ParentImage",
        "Image",
        "User",
        "ProcessId",
    ),
    "webserver": (
        "cs-method",
        "cs-uri-stem",
        "cs-uri-query",
        "cs-user-agent",
        "c-ip",
        "sc-status",
    ),
    "network_connection": (
        "DestinationIp",
        "DestinationHostname",
        "DestinationPort",
        "InitiatingProcessFileName",
    ),
    "file_event": (
        "TargetFilename",
        "FileName",
        "Hashes",
        "User",
    ),
    "registry_event": (
        "TargetObject",
        "Details",
        "User",
    ),
    "image_load": (
        "ImageLoaded",
        "Image",
        "Signed",
        "Hashes",
    ),
}


def map_required_fields(logsources: list[str], behaviors: list[str] | None = None) -> list[str]:
    fields: list[str] = []
    for logsource in logsources:
        fields.extend(LOGSOURCE_FIELDS.get(logsource, ()))

    behavior_fields = {
        "process_creation": ("CommandLine", "ParentImage"),
        "file_write": ("TargetFilename", "FileName"),
        "registry_modification": ("TargetObject", "Details"),
        "image_load": ("ImageLoaded", "Image"),
        "network_callback": ("DestinationIp", "DestinationHostname"),
        "web_request": ("cs-uri-query", "cs-uri-stem"),
        "privilege_escalation": ("CommandLine", "User"),
    }
    for behavior in behaviors or []:
        fields.extend(behavior_fields.get(behavior, ()))

    return list(dict.fromkeys(fields))
