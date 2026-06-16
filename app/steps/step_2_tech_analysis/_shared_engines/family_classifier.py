from __future__ import annotations

from typing import Tuple

from app.steps.step_2_tech_analysis._shared_engines.vulnerability_signature_engine import match_signature
from app.shared.types.vulnerability_family import VulnerabilityFamily
from app.steps.step_2_tech_analysis._shared_engines.cwe_mapper import CWEProfile, map_cwe_profiles


def classify_family(
    cve_id: str | None,
    description: str | None,
    cwe_ids: list[str] | None,
    cpes: list[str] | None,
) -> Tuple[VulnerabilityFamily, float, list[str]]:
    reasons: list[str] = []

    sig = match_signature(cve_id=cve_id, description=description, cwe_ids=cwe_ids, cpes=cpes)
    if sig is not None:
        reasons.append(f"signature:{sig.signature.name}")
        return sig.signature.family, sig.confidence, reasons

    # Product/vendor heuristics via CPEs
    vendors = set()
    products = set()
    for cpe in cpes or []:
        parts = cpe.lower().split(":")
        if len(parts) >= 5:
            vendors.add(parts[3])
            products.add(parts[4])

    if products and any(p for p in products if "spring" in p or "springframework" in p):
        reasons.append("product:spring")
        return VulnerabilityFamily.CODE_INJECTION, 0.9, reasons

    # CWE mapping
    profiles = map_cwe_profiles(cwe_ids)
    if profiles:
        # choose family based on first profile
        first = profiles[0]
        mapping = {
            "CWE-502": VulnerabilityFamily.DESERIALIZATION,
            "CWE-22": VulnerabilityFamily.PATH_TRAVERSAL,
            "CWE-434": VulnerabilityFamily.FILE_UPLOAD,
            "CWE-269": VulnerabilityFamily.PRIVILEGE_ESCALATION,
            "CWE-78": VulnerabilityFamily.CODE_INJECTION,
        }
        key = first.cwe_id
        if key in mapping:
            reasons.append(f"cwe:{key}")
            return mapping[key], 0.85, reasons

    # Description keyword fallback
    text = (description or "").lower()
    if any(k in text for k in ("jndi", "ldap", "rmi")):
        reasons.append("kw:jndi")
        return VulnerabilityFamily.JNDI_INJECTION, 0.88, reasons
    if any(k in text for k in ("path traversal", "directory traversal", "../")):
        reasons.append("kw:traversal")
        return VulnerabilityFamily.PATH_TRAVERSAL, 0.8, reasons
    if any(k in text for k in ("spring", "spring4shell", "classloader", "data binder")):
        reasons.append("kw:spring")
        return VulnerabilityFamily.CODE_INJECTION, 0.9, reasons

    # generic fallback
    return VulnerabilityFamily.UNKNOWN, 0.6, reasons
