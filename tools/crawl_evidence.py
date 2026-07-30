"""Evidence Crawler — tools/crawl_evidence.py.

Crawl nuclei-templates PoC YAML for a single CVE.
Source: projectdiscovery/nuclei-templates (raw GitHub).
No AI — pure YAML parse.

Output JSON v3.2 — two record kinds only:

  * ``documentation``: ``request`` is the joined ``info.description +
    info.impact`` text (the "what & why").
  * ``network``: ``request_info`` is ``{method, path, headers, body,
    raw_block_count}`` parsed from the http[] step (the "how").

No provenance/observable/auxiliary fields — keeps the output focused on
the two sub-systems threat intel cares about: explanation + exploit code.

Top-level wrapper: {cve_id, evidence[], references[]}.

STANDALONE CLI — NOT wired into Step 1.4 / Step 4 / Step 6.

Usage:
    python tools/crawl_evidence.py --cve CVE-2026-0926
    python tools/crawl_evidence.py --cve CVE-2021-44228 --output out.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
import sys
from pathlib import Path
from typing import Any, Literal

# Allow import từ repo root.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

import httpx  # noqa: E402
import yaml  # noqa: E402
from pydantic import BaseModel, model_validator  # noqa: E402


logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# nuclei-templates source
# ─────────────────────────────────────────────────────────────────────────────

NUCLEI_RAW = (
    "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main"
)

# Threshold above which identical headers are collapsed with a note.
# Set conservatively: real templates rarely need >5 identical lines,
# so anything beyond a couple is almost certainly a payload spam pattern.
_DEDUP_HEADER_THRESHOLD = 2


# ─────────────────────────────────────────────────────────────────────────────
# Record schema (v3.2 — minimal: two sub-systems, documentation | network)
# ─────────────────────────────────────────────────────────────────────────────

EvidenceType = Literal["documentation", "network"]


class CrawlEvidenceRecord(BaseModel):
    """Single normalized evidence record — schema v3.2. STANDALONE CLI.

    Two shapes only:

    * ``documentation``: ``request`` holds the joined ``info.description +
      info.impact`` text.
    * ``network``: ``request_info`` holds ``{method, path, headers, body,
      raw_block_count}`` parsed from the http[] step.
    """

    id: str = ""
    type: EvidenceType
    request: str | None = None
    request_info: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _at_least_one_content(self) -> "CrawlEvidenceRecord":
        if not any([self.request, self.request_info]):
            raise ValueError(
                "record must have request (documentation) or "
                "request_info (network)"
            )
        return self


# ─────────────────────────────────────────────────────────────────────────────
# YAML fetcher
# ─────────────────────────────────────────────────────────────────────────────

def _cve_year(cve_id: str) -> str | None:
    """``CVE-2021-44228`` → ``2021``."""
    m = re.match(r"^CVE-(\d{4})-(\d+)$", cve_id.strip(), re.I)
    return m.group(1) if m else None


async def fetch_template_yaml(
    client: httpx.AsyncClient, cve_id: str
) -> dict | None:
    """Fetch + parse the nuclei-templates YAML for one CVE.

    Returns the parsed mapping on success, ``None`` on 404 / network / parse error.
    """
    year = _cve_year(cve_id)
    if not year:
        return None
    url = f"{NUCLEI_RAW}/http/cves/{year}/{cve_id}.yaml"
    try:
        r = await client.get(url, timeout=10.0)
    except httpx.HTTPError as exc:
        logger.debug("[crawl_evidence] fetch failed for %s: %s", cve_id, exc)
        return None
    if r.status_code != 200 or not r.text:
        return None
    try:
        # PyYAML silently drops the trailing `# digest:` comment — fine.
        data = yaml.safe_load(r.text)
    except yaml.YAMLError as exc:
        logger.debug("[crawl_evidence] YAML parse failed for %s: %s", cve_id, exc)
        return None
    return data if isinstance(data, dict) else None


# ─────────────────────────────────────────────────────────────────────────────
# Raw HTTP block parser (for the request_info structure)
# ─────────────────────────────────────────────────────────────────────────────

def _parse_raw_block(block: str) -> dict[str, Any] | None:
    """Parse a single literal HTTP/1.x request block into structured form.

    Accepts block scalar output (e.g. ``"GET /path HTTP/1.1\\nHost: ...\\n\\nbody"``).
    Returns ``None`` if the block isn't a recognizable request line.

    Returned shape::

        {"method": str, "path": str, "headers": dict[str, str], "body": str | None}
    """
    text = block.replace("\r\n", "\n").strip("\n")
    if not text:
        return None

    lines = text.split("\n")
    # Request line: "METHOD <path> HTTP/1.x"
    request_line = lines[0].strip()
    m = re.match(r"^([A-Z]+)\s+(\S+)\s+HTTP/\d", request_line)
    if not m:
        return None
    method = m.group(1)
    path = m.group(2)

    headers: dict[str, str] = {}
    body: str | None = None
    # Headers continue until a blank line, then body.
    for line in lines[1:]:
        if line.strip() == "":
            # Everything after this is body.
            body = "\n".join(lines[lines.index(line) + 1 :])
            break
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        headers[k.strip()] = v.strip()

    return {
        "method": method,
        "path": path,
        "headers": headers,
        "body": body if body else None,
    }


def _dedup_headers(headers: dict[str, str]) -> dict[str, Any]:
    """Collapse identical (case-insensitive key + same value) headers.

    Real templates (Log4Shell etc.) spam the same JNDI payload across many
    headers with the same value; collapse them with a ``_collapsed_count``
    sibling key so the user still sees the count without the noise.

    Headers with distinct values are preserved verbatim.
    """
    if not headers:
        return {}

    # Group by lowercased key first.
    by_key: dict[str, list[tuple[str, str]]] = {}
    for k, v in headers.items():
        by_key.setdefault(k.lower(), []).append((k, v))

    out: dict[str, Any] = {}
    for lk, entries in by_key.items():
        if len(entries) == 1:
            out[entries[0][0]] = entries[0][1]
            continue

        # Multiple entries with same lowercased key — check value identity.
        distinct_values = {v for _, v in entries}
        if len(distinct_values) == 1:
            # Identical values: collapse.
            out[entries[0][0]] = entries[0][1]
            if len(entries) > _DEDUP_HEADER_THRESHOLD:
                # Use the original casing from the first occurrence + count note.
                note_key = f"_{entries[0][0].lower().replace('-', '_')}_collapsed_count"
                out[note_key] = len(entries)
        else:
            # Same key, different values: preserve all (keep order).
            for k, v in entries:
                out.setdefault(k, v)
            if len(entries) > _DEDUP_HEADER_THRESHOLD:
                note_key = f"_{lk.replace('-', '_')}_variants_count"
                out[note_key] = len(entries)
    return out


def _build_request_info(step: dict) -> dict[str, Any] | None:
    """Build ``request_info`` dict for one http[] step.

    Behavior:
      * ``method`` and ``path`` come from the first parseable raw block (or
        from the structured fields when no raw blocks exist).
      * ``headers`` is the **union across all raw blocks**, with identical
        (key+value) pairs collapsed via :func:`_dedup_headers` so Log4Shell-
        style payload spam across many headers is visible but not noisy.
      * ``body`` comes from the first block that has one.
      * ``raw_block_count`` records how many raw blocks were present.
      * Fallback when no raw blocks exist: reconstruct from ``method`` +
        ``path`` + ``headers`` + ``body`` (structured fields).
    """
    raw_blocks = step.get("raw") or []

    if raw_blocks:
        # First parseable block drives method/path/body.
        primary: dict[str, Any] | None = None
        merged_headers: dict[str, str] = {}
        primary_body: str | None = None
        primary_method: str | None = None
        primary_path: str | None = None

        for block in raw_blocks:
            parsed = _parse_raw_block(str(block))
            if parsed is None:
                continue
            merged_headers.update(parsed["headers"] or {})
            if primary is None:
                primary = parsed
                primary_method = parsed["method"]
                primary_path = parsed["path"]
                primary_body = parsed["body"]
            elif primary_body is None and parsed["body"]:
                primary_body = parsed["body"]

        if primary is not None:
            info: dict[str, Any] = {
                "method": primary_method,
                "path": primary_path,
                "headers": _dedup_headers(merged_headers),
            }
            if primary_body:
                info["body"] = primary_body
            if len(raw_blocks) > 1:
                info["raw_block_count"] = len(raw_blocks)
            return info

    # Fallback: reconstruct from structured fields.
    method = step.get("method", "GET")
    paths = step.get("path") or ["/"]
    path = paths[0] if isinstance(paths, list) else str(paths)
    body = step.get("body")
    info: dict[str, Any] = {
        "method": method,
        "path": path,
        "headers": _dedup_headers(dict(step.get("headers") or {})),
    }
    if body:
        info["body"] = body
    return info


# ─────────────────────────────────────────────────────────────────────────────
# Record builders
# ─────────────────────────────────────────────────────────────────────────────

def _description_record(template: dict, cve_id: str) -> CrawlEvidenceRecord:
    """Emit one documentation record holding ``info.description + info.impact``.

    ``remediation`` is intentionally dropped (per user decision).
    """
    info = template.get("info") or {}
    parts: list[str] = []
    description = (info.get("description") or "").strip()
    if description:
        parts.append(description)
    impact = (info.get("impact") or "").strip()
    if impact:
        parts.append(impact)
    return CrawlEvidenceRecord(
        id=f"{cve_id.lower()}_description",
        type="documentation",
        request="\n\n".join(parts),
    )


def _http_step_record(
    step: dict, idx: int, cve_id: str
) -> CrawlEvidenceRecord:
    """Emit one network record per ``http[]`` step."""
    return CrawlEvidenceRecord(
        id=f"{cve_id.lower()}_http_{idx:02d}",
        type="network",
        request_info=_build_request_info(step),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

async def crawl(cve_id: str, max_evidence: int = 50, timeout: float = 10.0) -> dict:
    """Fetch nuclei YAML for ``cve_id`` and emit documentation + per-step records.

    Top-level shape (v3.2):
        {cve_id, evidence[], references[]}

    ``timeout`` is the httpx request deadline (seconds) — owns the deadline
    so the utility has a single, well-defined time budget callers can rely on.
    """
    year = _cve_year(cve_id)
    yaml_url = f"{NUCLEI_RAW}/http/cves/{year}/{cve_id}.yaml" if year else ""

    async with httpx.AsyncClient(timeout=timeout) as client:
        template = await fetch_template_yaml(client, cve_id)

    if template is None:
        return {
            "cve_id": cve_id,
            "evidence": [],
            "references": [],
        }

    records: list[CrawlEvidenceRecord] = [
        _description_record(template, cve_id)
    ]
    http_steps = template.get("http") or []
    for idx, step in enumerate(http_steps):
        records.append(_http_step_record(step, idx, cve_id))

    # Cap (description is preserved; http steps may be truncated).
    records = records[:max_evidence]

    return {
        "cve_id": cve_id,
        "evidence": [r.model_dump(exclude_none=True) for r in records],
        "references": [{"url": yaml_url}],
    }


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Crawl nuclei-templates PoC YAML for 1 CVE. Output JSON schema v3.2."
    )
    parser.add_argument("--cve", required=True, help="CVE ID (e.g. CVE-2021-44228)")
    parser.add_argument(
        "--output", "-o",
        help="Write JSON to file (default: stdout)",
    )
    parser.add_argument(
        "--max-evidence", type=int, default=50,
        help="Cap total evidence records per CVE (default 50)",
    )
    args = parser.parse_args()

    try:
        result = asyncio.run(crawl(args.cve, max_evidence=args.max_evidence))
    except KeyboardInterrupt:
        sys.exit(130)

    json_str = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(json_str, encoding="utf-8")
        n = len(result["evidence"])
        print(
            f"Written {args.output}: {n} evidence records",
            file=sys.stderr,
        )
    else:
        print(json_str)


if __name__ == "__main__":
    main()