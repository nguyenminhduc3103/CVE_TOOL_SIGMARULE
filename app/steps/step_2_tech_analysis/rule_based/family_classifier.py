from __future__ import annotations

from typing import Tuple

from app.steps.step_2_tech_analysis.rule_based.vulnerability_signature_engine import match_signature
from app.shared.types.vulnerability_family import VulnerabilityFamily
from app.steps.step_2_tech_analysis.rule_based.cwe_mapper import CWEProfile, map_cwe_profiles


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

    # CWE mapping — use the family declared on the CWEProfile itself.
    profiles = map_cwe_profiles(cwe_ids)
    if profiles:
        first = profiles[0]
        if first.family is not None:
            reasons.append(f"cwe:{first.cwe_id}")
            return first.family, 0.85, reasons

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
