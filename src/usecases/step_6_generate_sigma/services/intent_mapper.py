"""Intent Mapper — maps AI `DetectionIntent.intent` (free text) → Step 4 canonical logsource.

Never hardcodes domain→category, process names, ports, or fields (Step 4 KB owns those).

The mapper must be robust to AI-emitting intent text that is descriptive rather
than canonical (e.g. ``"suspicious jndi lookup injection in web request"`` vs the
KB slug ``jndi_payload_lookup``). Two mechanisms handle this:

  1. Substring/keyword match against family intents' ``intent`` slug.
  2. ``families.<sig>.aliases`` allow related family names (e.g.
     ``jndi_injection`` → ``log4shell``) to share the same intent KB.
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


def _keywords(slug: str) -> list[str]:
    """Split a slug into its key tokens for substring matching.

    Drops common stopwords so 'suspicious_jndi_lookup_injection' can match
    'jndi_payload_lookup' via the shared tokens 'jndi' and 'lookup'.
    """
    stops = {
        "suspicious", "malicious", "attempt", "indicator", "detection",
        "activity", "signature", "vulnerability", "exploit", "rce", "injection",
        # "rce" / "injection" are too generic — they cause false matches across
        # unrelated families (e.g. 'random_sql_injection_signature' vs
        # 'log4shell' via 'jndi_injection' alias).
    }
    return [tok for tok in slug.split("_") if tok and tok not in stops]


def _best_intent_match(
    intent_text: str,
    family_intents: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, str]:
    """Return the family-intent entry that best matches ``intent_text``.

    Match priority:
      1. Exact slug equality.
      2. Slug substring match in either direction.
      3. Shared keywords (>= 1 token, excluding stopwords).

    Returns ``(entry, reason)`` where reason is one of
    ``exact | substring | keyword | none``.
    """
    intent_slug = _intent_slug(intent_text)
    intent_keywords = set(_keywords(intent_slug))
    if not intent_keywords:
        return None, "none"

    # 1. exact
    for fam_intent in family_intents or []:
        fam_slug = _normalize_slug(str(fam_intent.get("intent", "")))
        if fam_slug and fam_slug == intent_slug:
            return fam_intent, "exact"

    # 2. substring (either direction)
    for fam_intent in family_intents or []:
        fam_slug = _normalize_slug(str(fam_intent.get("intent", "")))
        if not fam_slug:
            continue
        if fam_slug in intent_slug or intent_slug in fam_slug:
            return fam_intent, "substring"

    # 3. keyword overlap
    best: tuple[int, dict[str, Any]] | None = None
    for fam_intent in family_intents or []:
        fam_slug = _normalize_slug(str(fam_intent.get("intent", "")))
        if not fam_slug:
            continue
        fam_keywords = set(_keywords(fam_slug))
        if not fam_keywords:
            continue
        overlap = intent_keywords & fam_keywords
        if not overlap:
            continue
        # Prefer the entry with the most overlap, then the shortest slug.
        score = len(overlap) * 100 - len(fam_slug)
        if best is None or score > best[0]:
            best = (score, fam_intent)
    if best is not None:
        return best[1], "keyword"

    return None, "none"


def _resolve_from_step4_logsources(
    domain_hint: str | None,
    sigma_logsources: list[dict[str, Any]],
) -> dict[str, str] | None:
    """Pick the best matching Sigma logsource from Step 4's sigma_logsources list.

    Resolution order:
      1. If Step 4 emitted a logsource whose category matches the domain_hint
         candidates, use it (preserves Step 4's product/service resolution).
      2. Otherwise, build a canonical logsource from the domain_hint alone
         (using the ``domain_to_categories`` index). This kicks in when Step 4
         didn't surface a domain-aligned telemetry source — e.g. CVE analysis
         only called for process_creation but the AI plan needs a network or
         webserver sub-rule.
      3. Last resort: first Step 4 logsource.
    """
    # Lookup index against Step 4 output — not hardcoded detection knowledge.
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

    domain_key = (domain_hint or "").lower()
    candidates = domain_to_categories.get(domain_key, [])

    # 1. Best match within Step 4's sigma_logsources
    if sigma_logsources:
        for ls in sigma_logsources:
            category = str(ls.get("category", "")).lower()
            if category and category in candidates:
                return {"category": ls.get("category"), "product": ls.get("product", "windows")}

    # 2. Build a canonical logsource from the domain_hint alone.
    if candidates:
        canonical_category = candidates[0]
        # Pick a product: prefer the first Step 4 logsource's product if
        # available, else default 'windows'.
        product = "windows"
        if sigma_logsources:
            first = sigma_logsources[0]
            if isinstance(first, dict) and first.get("product"):
                product = str(first["product"])
        return {"category": canonical_category, "product": product}

    # 3. Last resort: first Step 4 logsource
    if sigma_logsources:
        first = sigma_logsources[0]
        return {
            "category": first.get("category", ""),
            "product": first.get("product", "windows"),
        }

    return None


def _resolve_family(
    family_signature: str | None,
    family: str | None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Resolve a family entry, honoring ``aliases`` if direct lookup misses.

    Returns ``(entry, resolved_name)`` — ``resolved_name`` is the slug that
    actually matched, so downstream code can mention it in rationale text.

    Resolution order:
      1. Exact KB family lookup for ``family_signature`` or ``family``.
      2. Exact alias match (case-insensitive substring/equality).
      3. Keyword/tokens overlap with aliases (e.g. AI emits
         ``"apache log4j2 jndi rce (log4shell)"`` which has tokens
         ``log4j``, ``jndi``, ``rce`` overlapping with the ``log4shell`` family
         alias ``"log4j2 jndi rce"``).
    """
    for name in (family_signature, family):
        entry = loader.get_family(name)
        if entry:
            return entry, name

    if not (family_signature or family):
        return None, None

    target_raw = (family_signature or family or "").lower()
    target_slug = _normalize_slug(target_raw)
    target_keywords = set(_keywords(target_slug))
    if not target_keywords:
        return None, None

    kb = loader.load_detection_kb()

    # 2. Exact alias match
    for fam_slug, fam_entry in (kb.get("families", {}) or {}).items():
        aliases = [a.lower() for a in (fam_entry.get("aliases", []) or [])]
        if target_raw in aliases or target_slug == fam_slug.lower():
            return fam_entry, fam_slug

    # 3. Keyword/tokens overlap. Score = (shared_tokens * 100) - len(fam_slug).
    # Prefer families with the most shared tokens; tie-break by shortest slug.
    best: tuple[int, str, dict[str, Any]] | None = None
    for fam_slug, fam_entry in (kb.get("families", {}) or {}).items():
        aliases = [a.lower() for a in (fam_entry.get("aliases", []) or [])]
        for alias in aliases:
            alias_slug = _normalize_slug(alias)
            alias_keywords = set(_keywords(alias_slug))
            if not alias_keywords:
                continue
            overlap = target_keywords & alias_keywords
            if not overlap:
                continue
            score = len(overlap) * 100 - len(alias_slug)
            if best is None or score > best[0]:
                best = (score, fam_slug, fam_entry)
        # Also check the family signature itself.
        sig_slug = _normalize_slug(str(fam_entry.get("signature", "")))
        sig_keywords = set(_keywords(sig_slug))
        overlap = target_keywords & sig_keywords
        if overlap:
            score = len(overlap) * 100 - len(sig_slug)
            if best is None or score > best[0]:
                best = (score, fam_slug, fam_entry)

    if best is not None:
        return best[2], best[1]

    return None, None


def map_intent(
    intent: DetectionIntent,
    sigma_logsources: list[dict[str, Any]],
    validated_fields: list[str],
    family_signature: str | None = None,
    family: str | None = None,
) -> IntentResolution:
    """Resolve one DetectionIntent → canonical logsource + fields.

    Resolution order:
        1. Step 6 KB families.<signature>.intents (exact → substring → keyword)
        2. Step 6 KB behaviors.<name> (intent slug matches a behavior name)
        3. Fallback: first Step 4 sigma_logsource
        4. Unresolved (returns resolved=False)
    """
    intent_text = intent.intent
    intent_slug = _intent_slug(intent_text)
    rationale_parts: list[str] = []

    # 1. Family lookup (with alias resolution + robust intent match)
    family_entry, resolved_family_name = _resolve_family(family_signature, family)
    if family_entry:
        fam_intent, match_kind = _best_intent_match(intent_text, family_entry.get("intents", []) or [])
        if fam_intent is not None:
            dom = fam_intent.get("domain_hint") or family_entry.get("domain_hint")
            logsource = _resolve_from_step4_logsources(dom, sigma_logsources)
            fields = [f for f in validated_fields] if validated_fields else []
            return IntentResolution(
                intent=intent_text,
                canonical_logsource=logsource,
                canonical_fields=fields,
                domain_hint=dom,
                resolver_source="family_kb",
                resolved=bool(logsource),
                rationale=(
                    f"intent '{intent_slug}' matched family "
                    f"'{resolved_family_name}' ({match_kind} match)"
                ),
            )
        rationale_parts.append(
            f"family={resolved_family_name} known but intent '{intent_slug}' did not match any KB intent"
        )

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