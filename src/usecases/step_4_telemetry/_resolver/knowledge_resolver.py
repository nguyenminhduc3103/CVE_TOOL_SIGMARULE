"""Resolve (domain × execution_surface × vendor) → Canonical Telemetry.

L3 — đọc canonical_telemetry.yaml, filter theo context (platform, surface),
trả về CanonicalTelemetryBundle.

Khi có telemetry mới (vd GCP audit, ETW, AWS GuardDuty) chỉ cần thêm
entry YAML — KHÔNG sửa code.
"""
from __future__ import annotations

from src.usecases.step_4_telemetry._knowledge import loader
from src.usecases.step_4_telemetry._resolver.canonical_model import (
    CanonicalField,
    CanonicalTelemetry,
    CanonicalTelemetryBundle,
)


def resolve(
    domains: list[str],
    execution_surfaces: list[str] | None = None,
    attacker_platforms: list[str] | None = None,
) -> CanonicalTelemetryBundle:
    """Resolve validated domains → Canonical Telemetry.

    Args:
        domains: Validated canonical domain IDs (output của domain_validator).
        execution_surfaces: ['server_side', 'client_side', 'local'] — từ Step 2
            `execution_surface` field. Defaults to all 3 nếu không xác định.
        attacker_platforms: ['windows', 'linux', 'aws', 'azure', 'kubernetes', ...]
            — inferred từ Step 2 (vulnerability_class, attack_flow, attacker_platforms).
            Defaults to ['windows'] cho CVE phổ biến nhất.

    Returns:
        CanonicalTelemetryBundle — matched telemetry, fields, skipped domains.
    """
    kb_telemetry = loader.load_canonical_telemetry()
    kb_fields = loader.load_canonical_fields()

    surfaces = execution_surfaces or ["server_side", "client_side", "local"]
    platforms = attacker_platforms or ["windows"]

    if not domains:
        return CanonicalTelemetryBundle(
            canonical_telemetry=[],
            canonical_fields=[],
            skipped_domains=[],
            resolution_warnings=["no_domains_to_resolve"],
        )

    all_telemetry = kb_telemetry.get("canonical_telemetry", [])
    canonical_list: list[CanonicalTelemetry] = []
    seen_ids: set[str] = set()
    warnings: list[str] = []

    for ct in all_telemetry:
        if ct["domain"] not in domains:
            continue
        if ct["vendor"] not in platforms:
            continue
        # Surface check: telemetry surface phải overlap với execution surfaces
        ct_surfaces = ct.get("execution_surfaces", [])
        if not any(s in surfaces for s in ct_surfaces):
            continue
        if ct["id"] in seen_ids:
            continue
        seen_ids.add(ct["id"])
        # Cast events int → str (Sysmon EIDs YAML có thể là 4624 hoặc "4624")
        ct_normalized = dict(ct)
        ct_normalized["events"] = [str(e) for e in ct.get("events", [])]
        canonical_list.append(CanonicalTelemetry(**ct_normalized))

    # Field resolution — collect all fields từ matched canonical telemetry
    matched_field_set: set[str] = set()
    for ct in canonical_list:
        matched_field_set.update(ct.fields)

    canonical_fields: list[CanonicalField] = []
    fields_kb = kb_fields.get("canonical_fields", [])
    for field_def in fields_kb:
        # Match nếu bất kỳ alias nào nằm trong matched_field_set
        if any(alias in matched_field_set for alias in field_def.get("aliases", [])):
            canonical_fields.append(CanonicalField(**field_def))

    # Domain skipped nếu không có canonical telemetry match
    matched_domains = {ct.domain for ct in canonical_list}
    skipped = [d for d in domains if d not in matched_domains]
    for d in skipped:
        warnings.append(f"domain_skipped:{d} (no canonical telemetry for platforms={platforms}, surfaces={surfaces})")

    if not canonical_list:
        warnings.append(f"no_canonical_resolved (domains={domains}, platforms={platforms})")

    return CanonicalTelemetryBundle(
        canonical_telemetry=canonical_list,
        canonical_fields=canonical_fields,
        skipped_domains=skipped,
        resolution_warnings=warnings,
    )