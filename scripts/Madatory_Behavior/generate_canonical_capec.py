"""Generate a canonical CAPEC.json from the CAPEC STIX bundle.

Input  : .cache/mitre_attack/capec_stix.json  (STIX 2.1 bundle)
Output : .cache/mitre_attack/capec_canonical.json

Each output entry has the schema:

    {
      "capec_id":      "CAPEC-1",
      "name":          "...",
      "description":   "...",
      "execution_flow": [{"title": ..., "description": ..., "techniques": [...]}],
      "prerequisites": ["...", ...],
      "consequences":  ["Gain Privileges", "Read Data", ...],
      "related_cwe":   ["CWE-285", ...]
    }

``execution_flow`` is flattened: the ``Explore/Experiment/Exploit`` phase
wrapper is dropped, only the action steps are kept (in their original
order). ``consequences`` is flattened: the scope (``Confidentiality``,
``Integrity``, ...) is dropped, only the unique impacts are kept.

Run:
    python scripts/generate_canonical_capec.py
    python scripts/generate_canonical_capec.py --in path/to/stix.json \
                                               --out path/to/out.json
"""

from __future__ import annotations

import argparse
import json
import re
from html import unescape
from pathlib import Path
from typing import Any, Iterable

DEFAULT_IN = Path(".cache/mitre_attack/capec_stix.json")
DEFAULT_OUT = Path(".cache/mitre_attack/capec_canonical.json")

# Strip all HTML tags and collapse whitespace runs into a single space.
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def _html_to_text(html: str) -> str:
    """Convert an HTML snippet to clean text."""
    if not html:
        return ""
    # Preserve <br> as a newline separator before stripping tags.
    text = re.sub(r"<br\s*/?>", "\n", html, flags=re.IGNORECASE)
    text = _TAG_RE.sub(" ", text)
    text = unescape(text)
    return _WS_RE.sub(" ", text).strip()


# Capture the phase blocks. Each block is wrapped in <div>...<h3>PHASE</h3>...</div>.
_PHASE_RE = re.compile(
    r"<h3>\s*([^<]+?)\s*</h3>(.*?)(?=<h3>|</div>\s*</div>|$)",
    flags=re.DOTALL | re.IGNORECASE,
)

# Match each <li>...</li> block. Some STIX blobs put the <table> (which holds
# the techniques) OUTSIDE the </li>, so we greedily attach any <table>...</
# table> block that immediately follows the closing </li>.
_LI_RE = re.compile(
    r"<li>(?:(?!<li>).)*?</li>(?:\s*<table[^>]*>.*?</table>)?",
    flags=re.DOTALL | re.IGNORECASE,
)
_TABLE_RE = re.compile(r"<table[^>]*>(.*?)</table>", flags=re.DOTALL | re.IGNORECASE)
_STEP_BODY_RE = re.compile(
    r"<p>\s*<b>\s*([^<:]+?)\s*:\s*</b>\s*(.*?)</p>",
    flags=re.DOTALL | re.IGNORECASE,
)
_TECHNIQUE_TD_RE = re.compile(r"<td>(.*?)</td>", flags=re.DOTALL | re.IGNORECASE)


def parse_execution_flow(html: str) -> list[dict[str, Any]]:
    """Parse the CAPEC ``x_capec_execution_flow`` HTML blob.

    Returns a list of ``{"phase": str, "steps": [{"title", "description",
    "techniques"}]}``. Returns an empty list when the blob is empty or
    cannot be parsed.
    """
    if not html:
        return []

    # Drop the leading <h2>Execution Flow</h2> wrapper so _PHASE_RE starts clean.
    body = re.sub(r"<h2>.*?</h2>", "", html, count=1, flags=re.DOTALL | re.IGNORECASE)

    flow: list[dict[str, Any]] = []
    for phase_match in _PHASE_RE.finditer(body):
        phase_name = _html_to_text(phase_match.group(1))
        phase_body = phase_match.group(2)
        steps: list[dict[str, Any]] = []
        for li_match in _LI_RE.finditer(phase_body):
            li_html = li_match.group(0)
            # Pull any <p><b>Title:</b> description</p> inside the <li>.
            body_match = _STEP_BODY_RE.search(li_html)
            if body_match:
                title = _html_to_text(body_match.group(1))
                description = _html_to_text(body_match.group(2))
            else:
                # Some <li> only carry a description (rare).
                title = ""
                description = _html_to_text(li_html)
            # Techniques (if any) sit in <table>...</table> blocks adjacent to
            # the <li> — both inside and trailing in the source.
            table_html = " ".join(_TABLE_RE.findall(li_html))
            techniques = [
                _html_to_text(td)
                for td in _TECHNIQUE_TD_RE.findall(table_html)
                if _html_to_text(td)
            ]
            if not title and not description and not techniques:
                continue
            step: dict[str, Any] = {"title": title, "description": description}
            if techniques:
                step["techniques"] = techniques
            steps.append(step)
        if steps:
            flow.append({"phase": phase_name, "steps": steps})
    return flow


def _flatten_execution_flow(
    flow: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Drop the phase wrapper, keep only the action steps in order."""
    steps: list[dict[str, Any]] = []
    for phase in flow:
        for step in phase.get("steps", []):
            steps.append(step)
    return steps


def _clean_text(value: Any) -> Any:
    """Strip HTML/whitespace from a string value, pass others through."""
    if isinstance(value, str):
        return _html_to_text(value)
    return value


def _clean_list(values: Iterable[Any] | None) -> list[str]:
    """Clean an iterable of strings; drop empty entries."""
    if not values:
        return []
    cleaned: list[str] = []
    for v in values:
        text = _clean_text(v)
        if text:
            cleaned.append(text)
    return cleaned


def extract_canonical(stix_obj: dict[str, Any]) -> dict[str, Any] | None:
    """Convert one STIX attack-pattern object to the canonical CAPEC entry."""
    # 1. CAPEC id comes from the external_reference with source_name == "capec".
    capec_id: str | None = None
    related_cwe: list[str] = []
    for ref in stix_obj.get("external_references", []):
        source = ref.get("source_name")
        if source == "capec" and capec_id is None:
            capec_id = ref.get("external_id")
        elif source == "cwe":
            cwe_id = ref.get("external_id")
            if cwe_id:
                related_cwe.append(cwe_id)
    if not capec_id:
        return None

    # 2. Consequences: collect impacts from every scope, preserving first-seen
    #    order and dropping empty entries. Scope is intentionally discarded.
    raw_consequences = stix_obj.get("x_capec_consequences") or {}
    impacts: list[str] = []
    if isinstance(raw_consequences, dict):
        for scope_impacts in raw_consequences.values():
            for impact in _clean_list(scope_impacts):
                if impact not in impacts:
                    impacts.append(impact)

    return {
        "capec_id": capec_id,
        "name": _clean_text(stix_obj.get("name", "")),
        "description": _clean_text(stix_obj.get("description", "")),
        # Flatten execution_flow: drop the phase wrapper, keep only the steps.
        "execution_flow": _flatten_execution_flow(
            parse_execution_flow(stix_obj.get("x_capec_execution_flow", ""))
        ),
        "prerequisites": _clean_list(stix_obj.get("x_capec_prerequisites")),
        # Flatten consequences: drop the scope, keep only impacts.
        "consequences": impacts,
        "related_cwe": sorted(set(related_cwe)),
    }


def iter_attack_patterns(bundle: dict[str, Any]) -> Iterable[dict[str, Any]]:
    """Yield attack-pattern SDOs from a STIX bundle."""
    for obj in bundle.get("objects", []):
        if obj.get("type") == "attack-pattern":
            yield obj


def generate(in_path: Path, out_path: Path) -> dict[str, Any]:
    """Read STIX bundle at ``in_path`` and write canonical CAPEC JSON."""
    bundle = json.loads(in_path.read_text(encoding="utf-8"))

    seen_ids: set[str] = set()
    canonical: list[dict[str, Any]] = []
    skipped = 0
    for stix_obj in iter_attack_patterns(bundle):
        entry = extract_canonical(stix_obj)
        if entry is None or entry["capec_id"] in seen_ids:
            skipped += 1
            continue
        seen_ids.add(entry["capec_id"])
        canonical.append(entry)

    def _capec_num(entry: dict[str, Any]) -> int:
        capec_id = entry["capec_id"]
        try:
            return int(capec_id.split("-", 1)[1])
        except (IndexError, ValueError):
            return 0

    canonical.sort(key=_capec_num)

    payload = {
        "source": str(in_path),
        "count": len(canonical),
        "skipped": skipped,
        "capecs": canonical,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return payload


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--in",
        dest="in_path",
        type=Path,
        default=DEFAULT_IN,
        help=f"Path to CAPEC STIX bundle (default: {DEFAULT_IN})",
    )
    parser.add_argument(
        "--out",
        dest="out_path",
        type=Path,
        default=DEFAULT_OUT,
        help=f"Path to canonical output JSON (default: {DEFAULT_OUT})",
    )
    return parser


def main() -> None:
    args = _build_parser().parse_args()
    result = generate(args.in_path, args.out_path)
    print(
        f"wrote {result['count']} CAPEC entries to {args.out_path} "
        f"(skipped {result['skipped']})"
    )


if __name__ == "__main__":
    main()