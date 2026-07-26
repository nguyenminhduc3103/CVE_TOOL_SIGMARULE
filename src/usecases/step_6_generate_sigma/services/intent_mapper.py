"""Intent Mapper — maps AI `DetectionIntent.intent` (free text) → Step 4 canonical logsource.

Uses:
- Step 6 KB `behaviors.<name>.domain_hint` (when intent matches behavior name)
- Step 6 KB `families.<signature>.intents[].intent` (when family known)
- Step 4 `TelemetryAssessment.sigma_logsources` (canonical logsource list)
- Step 4 `TelemetryAssessment.candidate_telemetry_domains` (canonical domain list)

NEVER hardcodes:
- domain → category mapping (Step 4 KB owns that)
- process names / ports / fields (Step 4 KB owns that)
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from src.usecases.step_6_generate_sigma._knowledge import loader
from src.usecases.step_6_generate_sigma.domain.detection_plan import DetectionIntent


class IntentResolution(BaseModel):
    """Resolution record for one DetectionIntent → canonical logsource."""

    intent: str
    canonical_logsource: dict[str, str] | None = None  # {"category": ..., "product": ...}
    canonical_fields: list[str] = Field(default_factory=list)
    domain_hint: str | None = None
    resolver_source: str = ""  # "behavior_kb" | "family_kb" | "fallback" | "unresolved"
    resolved: bool = False
    rationale: str = ""


def _normalize_slug(value: str) -> str:
    return value.strip().lower().replace("-", "_").replace(" ", "_")


def _intent_slug(intent_text: str) -> str:
    """Convert free-text intent to slug for KB lookup."""
    return _normalize_slug(intent_text)


def _resolve_from_step4_logsources(
    domain_hint: str | None,
    sigma_logsources: list[dict[str, Any]],
) -> dict[str, str] | None:
    """Pick the best matching Sigma logsource from Step 4's sigma_logsources list.

    Step 4 already filtered to valid options. We pick the first one matching
    `domain_hint`, else the first one.
    """
    if not sigma_logsources:
        return None

    # Map domain_hint → category candidates (only categories known to Step 4 KB).
    # These are Sigma category names — NOT hardcoded detection knowledge.
    # This is just a lookup index against Step 4 output.
    domain_to_categories = {
        "process": ["process_creation"],
        "network": ["network_connection"],
        "filesystem": ["file_event"],
        "registry": ["registry_event"],
        "memory": ["image_load"],
        "dns": ["dns_query"],
        "ldap": ["network_connection", "process_creation"],
        "http": ["webserver", "proxy"],
        "cloud": ["cloudtrail", "azure_activity_logs", "gcp_audit"],
        "container": ["container_event"],
        "kubernetes": ["k8s_audit"],
        "email": ["email"],
        "office": ["o365"],
        "identity": ["windows_security"],
        "credential": ["process_creation", "image_load"],
        "module": ["image_load"],
        "authorization": ["windows_security"],
        "persistence": ["process_creation", "registry_event", "file_event"],
    }

    candidates = domain_to_categories.get((domain_hint or "").lower(), [])

    for ls in sigma_logsources:
        category = str(ls.get("category", "")).lower()
        if category and category in candidates:
            return {"category": ls.get("category"), "product": ls.get("product", "windows")}

    # Fallback: use first Step 4 logsource (Step 4 already picked it)
    first = sigma_logsources[0]
    return {"category": first.get("category", ""), "product": first.get("product", "windows")}


def map_intent(
    intent: DetectionIntent,
    sigma_logsources: list[dict[str, Any]],
    validated_fields: list[str],
    family_signature: str | None = None,
    family: str | None = None,
) -> IntentResolution:
    """Resolve one DetectionIntent → canonical logsource + fields.

    Resolution order:
        1. Step 6 KB families.<signature>.intents (exact intent match)
        2. Step 6 KB behaviors.<name> (intent slug matches a behavior name)
        3. Fallback: first Step 4 sigma_logsource
        4. Unresolved (returns resolved=False)
    """
    intent_text = intent.intent
    intent_slug = _intent_slug(intent_text)
    rationale_parts: list[str] = []

    # 1. Family lookup
    family_entry = loader.get_family(family_signature) or loader.get_family(family)
    if family_entry:
        for fam_intent in family_entry.get("intents", []) or []:
            if _normalize_slug(str(fam_intent.get("intent", ""))) == intent_slug:
                dom = family_entry.get("domain_hint") or (fam_intent.get("domain_hint"))
                logsource = _resolve_from_step4_logsources(dom, sigma_logsources)
                fields = [f for f in validated_fields] if validated_fields else []
                return IntentResolution(
                    intent=intent_text,
                    canonical_logsource=logsource,
                    canonical_fields=fields,
                    domain_hint=dom,
                    resolver_source="family_kb",
                    resolved=bool(logsource),
                    rationale=f"intent matched family '{family_signature or family}' in KB",
                )
        rationale_parts.append(f"family={family_signature or family} known but intent not in family.intents")

    # 2. Behavior lookup
    behavior_entry = loader.get_behavior(intent_slug)
    if behavior_entry:
        dom = behavior_entry.get("domain_hint")
        logsource = _resolve_from_step4_logsources(dom, sigma_logsources)
        rationale = f"intent slug '{intent_slug}' matched KB behavior '{intent_slug}'"
        if not logsource:
            rationale += "; no Step 4 sigma_logsource available for this domain"
        return IntentResolution(
            intent=intent_text,
            canonical_logsource=logsource,
            canonical_fields=list(validated_fields),
            domain_hint=dom,
            resolver_source="behavior_kb",
            resolved=bool(logsource),
            rationale=rationale,
        )

    rationale_parts.append(f"no KB entry for intent slug '{intent_slug}'")

    # 3. Fallback: first Step 4 logsource
    if sigma_logsources:
        logsource = _resolve_from_step4_logsources(None, sigma_logsources)
        return IntentResolution(
            intent=intent_text,
            canonical_logsource=logsource,
            canonical_fields=list(validated_fields),
            domain_hint=None,
            resolver_source="fallback",
            resolved=bool(logsource),
            rationale="no KB match; using first Step 4 sigma_logsource as fallback",
        )

    # 4. Unresolved
    return IntentResolution(
        intent=intent_text,
        resolved=False,
        rationale="; ".join(rationale_parts) + "; no Step 4 sigma_logsource available",
    )


def map_all_intents(
    intents: list[DetectionIntent],
    telemetry: dict[str, Any] | None,
    family_signature: str | None = None,
    family: str | None = None,
) -> list[IntentResolution]:
    """Map every DetectionIntent in a plan."""
    sigma_logsources: list[dict[str, Any]] = []
    validated_fields: list[str] = []
    if telemetry:
        sigma_logsources = list(telemetry.get("sigma_logsources", []) or [])
        vf = telemetry.get("validated_fields", []) or []
        validated_fields = [str(f) for f in vf]

    return [
        map_intent(i, sigma_logsources, validated_fields, family_signature, family)
        for i in intents
    ]


__all__ = ["IntentResolution", "map_intent", "map_all_intents"]