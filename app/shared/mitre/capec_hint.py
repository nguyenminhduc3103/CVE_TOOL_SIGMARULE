"""CAPEC hint query — return CAPEC attack patterns as INSPIRATION for AI.

Different from old `OntologyManager` Layer 2 (CAPEC ground truth):
- OLD: CAPEC union was used to BUILD expected TTP → AI bị so sánh/coverage penalty
  với union quá rộng → AI luôn FAIL dù phân tích đúng (xem test_ai_coverage
  Hướng D comment).
- NEW: CAPEC hints chỉ la INSPIRATION đưa vào user prompt, giúp AI narrow down
  ATT&CK mapping khi CVE description mơ hồ. KHONG dung de score/coverage.

Usage:
    from app.shared.mitre.capec_hint import query_capec_for_cwe
    hints = query_capec_for_cwe("CWE-502", max_results=3)
    # -> [{"capec_id": "CAPEC-502", "name": "...",
    #      "description": "...", "likelihood": "High", "related_techniques": ["T1059"]}, ...]

Caching:
- Lazy load CAPEC STIX bundle 1 lần vao memory (4.3MB) → dict CWE → CAPEC list.
- Subsequent calls O(1) lookup. Memory ~30-50MB peak.
- Disable: env CVE_TI_DISABLE_CAPEC_HINTS=1 (returns []).
"""
from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

from app.core.config import settings

logger = logging.getLogger(__name__)


# CAPEC STIX bundle path (same cache dir as ATT&CK).
_CAPEC_FILE = Path(settings.mitre_cache_dir) / "capec_stix.json"

# Disable flag (env-driven). Set CVE_TI_DISABLE_CAPEC_HINTS=1 to bypass.
_DISABLE_HINTS = os.environ.get("CVE_TI_DISABLE_CAPEC_HINTS") == "1"

# Regex matchers
_CWE_RE = __import__("re").compile(r"^CWE-\d+$", __import__("re").IGNORECASE)


# ----------------------------------------------------------------------
# Lazy loader (singleton)
# ----------------------------------------------------------------------


_cwe_to_capec_index: dict[str, list[dict[str, Any]]] | None = None
_capec_load_lock = threading.Lock()


def _load_capec_index() -> dict[str, list[dict[str, Any]]]:
    """Parse CAPEC STIX bundle → dict CWE-id → list of CAPEC hints.

    Each CAPEC hint dict:
        capec_id: str            e.g. "CAPEC-502"
        name: str                e.g. "Intent Spoof"
        description: str         <500 chars (truncated)
        likelihood: str | None   e.g. "High" | "Medium" | "Low" | None
        related_techniques: list[str]  e.g. ["T1059", "T1190"]

    Returns empty dict if bundle missing or parse fails.
    """
    global _cwe_to_capec_index
    if _cwe_to_capec_index is not None:
        return _cwe_to_capec_index

    with _capec_load_lock:
        if _cwe_to_capec_index is not None:  # double-checked
            return _cwe_to_capec_index

        if not _CAPEC_FILE.exists():
            logger.debug(
                "[capec_hint] %s not found → returning empty hints. "
                "Run `python -m app.shared.mitre.fetch_stix --capec-only` to download.",
                _CAPEC_FILE,
            )
            _cwe_to_capec_index = {}
            return _cwe_to_capec_index

        try:
            with open(_CAPEC_FILE, encoding="utf-8") as f:
                bundle = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("[capec_hint] failed to parse %s: %s", _CAPEC_FILE, exc)
            _cwe_to_capec_index = {}
            return _cwe_to_capec_index

        objects = bundle.get("objects") if isinstance(bundle, dict) else None
        if not isinstance(objects, list):
            logger.warning("[capec_hint] invalid CAPEC bundle: no 'objects' list")
            _cwe_to_capec_index = {}
            return _cwe_to_capec_index

        index: dict[str, list[dict[str, Any]]] = {}
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue

            # CAPEC ID
            capec_id: str | None = None
            cwes: set[str] = set()
            related_attack: set[str] = set()
            for ref in obj.get("external_references", []) or []:
                src = ref.get("source_name", "")
                eid = ref.get("external_id", "")
                if src == "capec" and eid.startswith("CAPEC-"):
                    capec_id = eid
                elif src == "cwe" and eid.startswith("CWE-"):
                    cwes.add(eid.upper())
                elif src == "ATTACK" and eid.startswith("T"):
                    related_attack.add(eid)

            if not capec_id or not cwes:
                continue

            # Likelihood (CAPEC custom property)
            likelihood: str | None = None
            for prop in obj.get("x_capec_custom_tags", []) or []:
                # some CAPEC versions use object_marking_refs; skip
                pass
            # Try alternative location: properties dict
            # (older CAPEC STIX may store as `x_capec_likelihood` directly)
            likelihood = obj.get("x_capec_likelihood") or obj.get("x_capec_likelihood_of_attack")

            # Description (truncate to 500 chars for prompt size)
            desc = (obj.get("description") or "").strip()
            if len(desc) > 500:
                desc = desc[:497] + "..."

            hint = {
                "capec_id": capec_id,
                "name": obj.get("name", capec_id),
                "description": desc,
                "likelihood": likelihood,
                "related_techniques": sorted(related_attack),
            }

            for cwe in cwes:
                index.setdefault(cwe, []).append(hint)

        logger.info(
            "[capec_hint] loaded %d CWEs → %d CAPEC attack patterns from %s",
            len(index), sum(len(v) for v in index.values()), _CAPEC_FILE,
        )
        _cwe_to_capec_index = index
        return _cwe_to_capec_index


def reset() -> None:
    """Drop the cached index (test helper). Next query will re-parse."""
    global _cwe_to_capec_index
    with _capec_load_lock:
        _cwe_to_capec_index = None


# ----------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------


def query_capec_for_cwe(
    cwe_id: str,
    max_results: int = 5,
) -> list[dict[str, Any]]:
    """Return up to `max_results` CAPEC attack patterns for the given CWE.

    Args:
        cwe_id: CWE ID string (case-insensitive). e.g. "CWE-502" or "502".
        max_results: Maximum number of hints to return. Default 5.

    Returns:
        List of hint dicts (each with capec_id, name, description, likelihood,
        related_techniques). Empty list if CWE has no mapping, hints disabled,
        or CAPEC bundle unavailable.

    Note: This is INSPIRATION, not ground truth. AI may or may not follow
    these hints. Empty list is a valid result — caller should gracefully
    skip the hint section in the user prompt.
    """
    if _DISABLE_HINTS:
        return []

    if not cwe_id or not _CWE_RE.match(cwe_id.strip()):
        return []

    normalized = cwe_id.strip().upper()
    index = _load_capec_index()

    hints = index.get(normalized, [])
    if not hints:
        return []

    # Sort: prefer higher likelihood first if available, then alphabetical.
    likelihood_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    def _sort_key(h: dict[str, Any]) -> tuple[int, str]:
        rank = likelihood_rank.get((h.get("likelihood") or "").upper(), 0)
        return (-rank, h.get("capec_id", ""))

    sorted_hints = sorted(hints, key=_sort_key)
    return sorted_hints[:max_results]


def format_hints_for_prompt(hints: list[dict[str, Any]]) -> str:
    """Format CAPEC hints as a compact text block for user prompt.

    Returns:
        Multi-line string, or empty string if no hints.

    Example output:
        CAPEC-94 (Man in the Middle): likelihood=High, related=T1059
        CAPEC-502 (Intent Spoof): likelihood=Medium
    """
    if not hints:
        return ""

    lines: list[str] = []
    for h in hints:
        capec_id = h.get("capec_id", "?")
        name = h.get("name", "")
        likelihood = h.get("likelihood") or "?"
        related = h.get("related_techniques") or []
        related_str = ", ".join(related) if related else "no direct ATT&CK mapping"
        lines.append(f"  - {capec_id} ({name}): likelihood={likelihood}, ATT&CK hints=[{related_str}]")
    return "\n".join(lines)
