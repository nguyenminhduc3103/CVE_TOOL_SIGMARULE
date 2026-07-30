# Map Canonical Telemetry ID → Sigma category (Sigma taxonomy is narrow; service distinguishes).
from __future__ import annotations

from src.domain.models.telemetry import SigmaLogsource
from src.usecases.step_4_telemetry._resolver.canonical_model import (
    CanonicalField,
    CanonicalTelemetry,
)


# Map Canonical Telemetry ID → Sigma category.
# Sigma taxonomy is narrow (11 categories) — many canonical telemetry route to same category.
SIGMA_CATEGORY_MAP: dict[str, str] = {
    "windows_security_audit": "process_creation",
    "sysmon_process": "process_creation",
    "sysmon_dns": "dns_query",
    "windows_registry": "registry_event",
    "windows_filesystem": "file_event",
    "windows_image_load": "image_load",
    "windows_powershell": "ps_script",
    "auditd_linux": "process_creation",
    "sysmon_linux": "process_creation",
    "apache_access": "webserver",
    "nginx_access": "webserver",
    "iis_access": "webserver",
    "cloudtrail_aws": "process_creation",
    "azure_signin_logs": "process_creation",
    "azure_activity_logs": "process_creation",
    "kube_audit": "process_creation",
    "docker_events": "process_creation",
    "office365_audit": "process_creation",
    "zeek_conn": "network_connection",
    "suricata_eve": "network_connection",
    "windows_firewall": "firewall",
}


def map_to_sigma(
    canonical_telemetry: list[CanonicalTelemetry],
    canonical_fields: list[CanonicalField],
) -> tuple[list[SigmaLogsource], list[str], dict[str, str]]:
    """Map canonical → Sigma output.

    Args:
        canonical_telemetry: Resolved canonical sources.
        canonical_fields: Canonical field definitions.

    Returns:
        (sigma_logsources, sigma_events, field_name_map)
        - sigma_logsources: list of SigmaLogsource(category, product, service).
        - sigma_events: aggregated event IDs/names.
        - field_name_map: {canonical_name: sigma_field_name}.
    """
    logsources: list[SigmaLogsource] = []
    events: list[str] = []
    seen: set[tuple[str, str, str | None]] = set()

    for ct in canonical_telemetry:
        category = SIGMA_CATEGORY_MAP.get(ct.id, "process_creation")
        product = ct.vendor
        # Windows generic: service=None (để product 'windows' đủ)
        # Non-Windows: dùng canonical ID làm service (vd 'cloudtrail_aws' → aws/cloudtrail)
        service: str | None = None
        if ct.vendor != "windows" or category not in {"process_creation", "ps_script"}:
            service = ct.id

        ls = SigmaLogsource(category=category, product=product, service=service)
        key = (ls.category, ls.product, ls.service)
        if key in seen:
            continue
        seen.add(key)
        logsources.append(ls)
        events.extend(ct.events)

    # Field name mapping — both canonical AND aliases → sigma backend name.
    # This lets Step 6 translate AI selection_hint keys (which may be free-text
    # vendor names like 'Uri', 'TargetUserName', or canonical names like
    # 'uri_query', 'target_user') to the Sigma backend field name.
    field_map: dict[str, str] = {}
    for cf in canonical_fields:
        sigma_name = cf.backends.get("sigma")
        if not sigma_name:
            continue
        field_map[cf.canonical] = sigma_name
        # Lower-canonical lookup
        field_map.setdefault(cf.canonical.lower(), sigma_name)
        # Sigma-name itself is idempotent
        field_map.setdefault(sigma_name, sigma_name)
        field_map.setdefault(sigma_name.lower(), sigma_name)
        # Aliases (vendor / free-text names)
        for alias in cf.aliases or []:
            field_map.setdefault(alias, sigma_name)
            field_map.setdefault(alias.lower(), sigma_name)

    return logsources, events, field_map