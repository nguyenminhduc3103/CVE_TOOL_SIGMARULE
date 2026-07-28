"""Evidence Crawler — tools/crawl_evidence.py.

Crawl evidence cho 1 CVE từ nomi-sec/PoC-in-GitHub (curated list).
Output JSON v2.0: list evidence_records (multi-record normalized) + references
(URL only) + metadata (schema_version + extraction_stats).

Pipeline extract:
  1. AI classify README → list CrawlEvidenceRecord (multi-type: network /
     poc_script / payload / scan_result / log_snippet / file_reference /
     config / documentation).
  2. Regex supplement (extract_steps_section_records) → 1 documentation record
     + log_snippet / file_reference từ code fences.
  3. Cả hai cùng tồn tại (không dedup) — mỗi record tự gắn extraction_method.

STANDALONE CLI — KHÔNG wired vào Step 1.4 / Step 4 / Step 6.

Usage:
    python tools/crawl_evidence.py --cve CVE-2021-44228
    python tools/crawl_evidence.py --cve CVE-2021-44228 --output out.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

# Allow import từ repo root.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

import httpx  # noqa: E402
from pydantic import BaseModel, Field, field_validator, model_validator  # noqa: E402

from config.settings import settings  # noqa: E402


logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# nomi-sec source
# ─────────────────────────────────────────────────────────────────────────────

NOMISEC_RAW = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"


# ─────────────────────────────────────────────────────────────────────────────
# AI extraction config
# ─────────────────────────────────────────────────────────────────────────────

_PROMPTS_DIR = Path(__file__).parent / "prompts"
_MAX_README_CHARS = 12_000   # ~3k input tokens, đủ cho output 3k
_MAX_RETRIES = 2
_MAX_REGEX_RECORDS_PER_REPO = 12  # cap regex supplement per repo

EvidenceType = Literal[
    "network",          # HTTP/LDAP/SMB request/response, curl examples
    "poc_script",       # Python/Bash exploit scripts
    "payload",          # Raw payload string (no wrapping request)
    "scan_result",      # Tool output: "Found CVE-...", "9 vulnerable files"
    "log_snippet",      # Verbatim log lines from code fence
    "file_reference",   # .log / .pcap / .evtx filename refs
    "config",           # YAML/TOML/env misconfiguration snippet
    "documentation",    # Catch-all heading-level prose (regex returns)
]


class CrawlEvidenceRecord(BaseModel):
    """Single normalized evidence record — schema v2.0. STANDALONE CLI.

    Fields `id`, `extraction_method`, `source`, `reference_url` are set in code
    (NOT by LLM). The LLM only fills content fields (type, request, payload,
    observable, tool, etc.) — keeps the AI contract simple and avoids the LLM
    refusing to fill provenance fields we don't care about.
    """

    id: str = ""                                # patched post-loop
    type: EvidenceType
    title: str | None = None
    request: str | None = None
    payload: str | None = None
    observable: list[str] = Field(default_factory=list)
    tool: str | None = None
    log_type: str | None = None
    source_section: str | None = None
    confidence: float = 0.7                     # patched: 0.7 ai / 0.5 regex
    extraction_method: Literal["ai", "regex"] = "regex"   # patched
    source: str = ""                            # patched
    reference_url: str = ""                     # patched

    @field_validator("confidence")
    @classmethod
    def _bounded_confidence(cls, value: float) -> float:
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"confidence must be in [0,1], got {value}")
        return value

    @model_validator(mode="after")
    def _at_least_one_content(self) -> "CrawlEvidenceRecord":
        if not any([self.request, self.payload, self.observable]):
            raise ValueError(
                "record must have at least one of request/payload/observable"
            )
        return self


class _EvidenceExtractionLLMResponse(BaseModel):
    """Internal: parsed AI response. LLM only fills content fields."""

    cve_id: str
    evidence_records: list[CrawlEvidenceRecord] = Field(default_factory=list)
    skipped_sections: list[str] = Field(default_factory=list)
    reason: str | None = None


class _AIDisabledError(Exception):
    """Internal: AI disabled or no key. Caller still runs regex supplement."""


def _clean_json(text: str) -> str:
    """Mirror ai_telemetry_service._clean_json (balanced-brace, string-escape aware).

    Source: src/usecases/step_4_telemetry/services/ai_telemetry_service.py:480-525
    """
    text = text.strip()

    # Step 1: fenced markdown
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        return fenced.group(1).strip()

    # Step 2: balanced-brace scanner (string-aware)
    first = text.find("{")
    if first == -1:
        return text.strip()

    depth = 0
    in_string = False
    escape = False
    last = -1
    for i in range(first, len(text)):
        c = text[i]
        if escape:
            escape = False
            continue
        if c == "\\":
            escape = True
            continue
        if c == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                last = i
                break

    if last == -1:
        # Balanced-brace không khép — JSON bị truncate. Trả về best-effort text.
        return text[first:].strip()

    return text[first: last + 1].strip()


async def extract_evidence_with_ai(
    readme_text: str,
    cve_id: str,
    full_name: str,
    html_url: str,
) -> list[CrawlEvidenceRecord]:
    """AI-based multi-record extraction. Returns list (possibly empty).

    Raises:
        _AIDisabledError: AI disabled — caller still runs regex.
        AIServiceError / json.JSONDecodeError / ValidationError: caller catches.
    """
    from src.infrastructure.ai.core import BaseAIClient

    base = BaseAIClient()
    if not base.ai_enabled:
        raise _AIDisabledError("ai_enabled=False")

    # Reuse Phase 1 cascade (classification task fits Phase 1's purpose).
    model = settings.get_phase1_model() or "llama-3.3-70b-versatile"
    phase1_keys = settings.get_phase1_api_keys()
    phase1_base_url = settings.get_phase1_base_url()
    has_separate = (phase1_keys != settings.get_api_keys()) or (
        phase1_base_url != getattr(settings, "ai_base_url", None)
    )

    truncated = readme_text[:_MAX_README_CHARS]
    if len(readme_text) > _MAX_README_CHARS:
        truncated += "\n\n[README truncated for length]"

    sys_prompt = (_PROMPTS_DIR / "extract_evidence.system.txt").read_text(encoding="utf-8")
    user_prompt = (_PROMPTS_DIR / "extract_evidence.user.txt").read_text(encoding="utf-8").format(
        cve_id=cve_id,
        max_chars=_MAX_README_CHARS,
        readme_text=truncated,
    )

    kwargs: dict = dict(
        system_prompt=sys_prompt,
        user_prompt=user_prompt,
        model=model,
        max_tokens=3000,                # bumped: multi-record output
        response_format_json=True,
        max_retries=_MAX_RETRIES,
    )
    if has_separate:
        kwargs.update(
            override_api_key=phase1_keys[0],
            override_base_url=phase1_base_url,
        )

    raw = await base.call_llm(**kwargs)
    parsed = _EvidenceExtractionLLMResponse.model_validate(json.loads(_clean_json(raw)))

    # Patch provenance + extraction_method + confidence in code (NOT from LLM).
    patched: list[CrawlEvidenceRecord] = []
    for rec in parsed.evidence_records:
        patched.append(
            rec.model_copy(update={
                "extraction_method": "ai",
                "confidence": 0.7,
                "source": f"NomiSec - {full_name}",
                "reference_url": html_url,
            })
        )
    return patched


async def extract_evidence_hybrid(
    readme_text: str,
    cve_id: str,
    full_name: str,
    html_url: str,
) -> tuple[list[CrawlEvidenceRecord], dict[str, int]]:
    """AI try → always supplement with regex (no dedup).

    Returns:
        (records, stats) where stats = {ai_calls, ai_failures, regex_calls}.
    NEVER raises — caller's job is just to push results into evidence[].
    """
    records: list[CrawlEvidenceRecord] = []
    stats = {"ai_calls": 0, "ai_failures": 0, "regex_calls": 0}

    # Path A — AI
    try:
        stats["ai_calls"] += 1
        ai_records = await extract_evidence_with_ai(
            readme_text, cve_id, full_name, html_url
        )
        records.extend(ai_records)
    except _AIDisabledError:
        pass  # silent — pure-regex mode
    except Exception as exc:  # AIServiceError, JSON, Validation, anything
        stats["ai_failures"] += 1
        logger.debug(
            "[crawl_evidence] AI failed for %s/%s: %s",
            cve_id, full_name, exc,
        )

    # Path B — regex supplement (always, no dedup vs AI per user decision)
    try:
        stats["regex_calls"] += 1
        regex_records = extract_steps_section_records(
            readme_text, cve_id, full_name, html_url
        )
        records.extend(regex_records)
    except Exception as exc:
        logger.debug(
            "[crawl_evidence] regex failed for %s/%s: %s",
            cve_id, full_name, exc,
        )

    return records, stats


# ─────────────────────────────────────────────────────────────────────────────
# Regex fallback
# ─────────────────────────────────────────────────────────────────────────────

_HEADING_PATTERN = re.compile(
    r"^#{1,3}\s*(?:"
    r"Steps?\s+to\s+Reproduce|"
    r"Steps?|"
    r"Reproduction|Reproduce|"
    r"Proof\s+of\s+Concept|"
    r"PoC|"
    r"How\s+to\s+(?:Use|Run|Exploit|Reproduce)|"
    r"Usage|"
    r"Run(?:\s+the\s+exploit)?|"
    r"(?:Attack|Exploit|Exploitation)\s+Steps?|"
    r"Quick\s*Start|Getting\s+Started|"
    r"重现步骤|复现步骤|重现|复现"
    r")\s*:?\s*$",
    re.I | re.M,
)
_NEXT_HEADING = re.compile(r"^#{1,3}\s+\S", re.M)
_FENCE_PATTERN = re.compile(r"```([a-zA-Z]*)\s*\n(.*?)\n```", re.S)

# Log content patterns (reuse from src/infrastructure/.../evidence_extractor.py).
_APACHE_LOG_PATTERN = re.compile(
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+-\s+\S+\s+\[[\d\w:/]+\s+[+-]\d{4}\]\s+\""
    r"[^"
    r"\"]+\"\s+\d+\s+\d+"
)
_ZEEK_CONN_PATTERN = re.compile(
    r"^\d+\.\d+\.\d+\.\d+\t\d+\t[\d.]+\t\d+\t(?:tcp|udp|icmp)",
    re.M,
)
_SURICATA_EVE_PATTERN = re.compile(
    r'"event_type"\s*:\s*"(?:alert|flow|dns|http|smtp|tls|ssh|ftp)"'
)
_WINDOWS_XML_PATTERN = re.compile(r"<Event xmlns=\"[^\"]+\">.*?</Event>", re.S)
_FILE_REF_PATTERN = re.compile(r"\b(\w+\.(?:evtx|pcap|log|json|tsv|csv))\b", re.I)


def _fence_log_type(content: str) -> str | None:
    """Detect log type from fenced code block content."""
    if _APACHE_LOG_PATTERN.search(content):
        return "apache_access_log"
    if _ZEEK_CONN_PATTERN.search(content):
        return "zeek_conn_log"
    if _SURICATA_EVE_PATTERN.search(content):
        return "suricata_eve"
    if _WINDOWS_XML_PATTERN.search(content):
        return "windows_event_xml"
    return None


def _extract_code_block_records(
    readme_text: str,
    full_name: str,
    html_url: str,
) -> list[CrawlEvidenceRecord]:
    """Find fenced ```lang ... ``` blocks; emit log_snippet/file_reference records."""
    records: list[CrawlEvidenceRecord] = []
    for match in _FENCE_PATTERN.finditer(readme_text):
        lang = (match.group(1) or "").lower()
        content = match.group(2).strip()
        if not content or len(content) < 10:
            continue

        # log_snippet: detect log type from content
        log_type = _fence_log_type(content)
        if log_type:
            records.append(CrawlEvidenceRecord(
                id="",  # patched by caller
                type="log_snippet",
                title=f"Fenced code block ({lang or 'plain'})",
                observable=[f"Detected {log_type} pattern", content[:200]],
                log_type=log_type,
                source_section=None,
                confidence=0.5,
                extraction_method="regex",
                source=f"NomiSec - {full_name}",
                reference_url=html_url,
            ))
            if len(records) >= _MAX_REGEX_RECORDS_PER_REPO:
                break
            continue

        # file_reference: detect .evtx / .pcap / .log etc in content
        refs = list({m.group(1) for m in _FILE_REF_PATTERN.finditer(content)})[:3]
        for ref in refs:
            records.append(CrawlEvidenceRecord(
                id="",
                type="file_reference",
                title=f"File reference: {ref}",
                observable=[f"File: {ref}", content[:200]],
                source_section=None,
                confidence=0.5,
                extraction_method="regex",
                source=f"NomiSec - {full_name}",
                reference_url=html_url,
            ))
            if len(records) >= _MAX_REGEX_RECORDS_PER_REPO:
                break

        if len(records) >= _MAX_REGEX_RECORDS_PER_REPO:
            break
    return records


def extract_steps_section_records(
    readme_text: str,
    cve_id: str,
    full_name: str,
    html_url: str,
) -> list[CrawlEvidenceRecord]:
    """Regex fallback. Emits 1 documentation record + log_snippet/file_reference sub-records.

    Always sets `extraction_method="regex"`, `confidence=0.5`.
    """
    records: list[CrawlEvidenceRecord] = []

    heading_match = _HEADING_PATTERN.search(readme_text)
    if heading_match:
        start = heading_match.end()
        nxt = _NEXT_HEADING.search(readme_text, start)
        end = nxt.start() if nxt else len(readme_text)
        section_body = readme_text[start:end].strip()
        section_body = re.sub(r"^\s*\n", "", section_body)

        heading_text = heading_match.group(0).strip().lstrip("#").strip()
        if len(section_body) >= 30:
            records.append(CrawlEvidenceRecord(
                id="",  # patched by caller
                type="documentation",
                title=heading_text or "Steps section",
                request=section_body[:1000],
                observable=[],
                source_section=heading_text,
                confidence=0.5,
                extraction_method="regex",
                source=f"NomiSec - {full_name}",
                reference_url=html_url,
            ))

    # Sub-extractor: code fences in full README (not just section body) — sometimes
    # scanner output lives in a standalone block outside the heading section.
    records.extend(_extract_code_block_records(readme_text, full_name, html_url))
    return records[:_MAX_REGEX_RECORDS_PER_REPO]


# ─────────────────────────────────────────────────────────────────────────────
# HTTP fetch helpers (unchanged from prior version)
# ─────────────────────────────────────────────────────────────────────────────

def _cve_year(cve_id: str) -> str | None:
    """``CVE-2021-44228`` → ``2021``."""
    m = re.match(r"^CVE-(\d{4})-(\d+)$", cve_id.strip(), re.I)
    return m.group(1) if m else None


async def fetch_repos_for_cve(client: httpx.AsyncClient, cve_id: str) -> list[dict]:
    """Fetch list repo PoC cho 1 CVE từ nomi-sec (1 HTTP call).

    Returns: list[dict] — mỗi dict là 1 repo entry từ GitHub search API format.
    """
    year = _cve_year(cve_id)
    if not year:
        return []
    url = f"{NOMISEC_RAW}/{year}/{cve_id}.json"
    r = await client.get(url, timeout=15.0)
    if r.status_code != 200:
        return []  # 404 = CVE không có trên nomi-sec
    data = r.json()
    if not isinstance(data, list):
        return []
    return [
        e for e in data
        if isinstance(e, dict) and e.get("full_name") and not e.get("fork", False)
    ]


async def fetch_default_branch(client: httpx.AsyncClient, full_name: str) -> str:
    """Fetch default_branch của repo (cached per instance). Fallback: ``main``."""
    r = await client.get(
        f"https://api.github.com/repos/{full_name}",
        timeout=5.0,
    )
    if r.status_code == 200:
        return (r.json().get("default_branch") or "main").strip()
    return "main"


async def fetch_readme(
    client: httpx.AsyncClient,
    full_name: str,
    branch: str,
) -> str | None:
    """Fetch raw README từ 1 repo. Try nhiều tên file."""
    for name in ("README.md", "README", "readme.md", "Readme.md"):
        url = f"https://raw.githubusercontent.com/{full_name}/{branch}/{name}"
        r = await client.get(url, timeout=5.0)
        if r.status_code == 200 and r.text:
            return r.text
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

def _make_evidence_id(cve_id: str, seq: int) -> str:
    return f"evidence_{cve_id.strip().lower().replace('-', '_')}_{seq:03d}"


async def crawl(
    cve_id: str,
    max_repos: int = 5,
    max_evidence: int = 50,
) -> dict:
    """Crawl nomi-sec cho 1 CVE. Output schema v2.0: evidence + references + metadata."""
    async with httpx.AsyncClient(timeout=15.0) as client:
        repos = await fetch_repos_for_cve(client, cve_id)
        top_repos = sorted(
            repos, key=lambda r: r.get("stargazers_count", 0), reverse=True
        )[:max_repos]

        evidence: list[CrawlEvidenceRecord] = []
        references: list[dict] = []
        repos_with_evidence = 0
        ai_calls = 0
        ai_failures = 0
        regex_calls = 0

        for repo in top_repos:
            full_name = repo.get("full_name", "")
            html_url = repo.get("html_url", "")
            stars = repo.get("stargazers_count", 0)
            if not full_name:
                continue

            references.append({
                "url": html_url,
                "stars": stars,
                "description": (repo.get("description") or "").strip(),
            })

            branch = await fetch_default_branch(client, full_name)
            readme = await fetch_readme(client, full_name, branch)
            if not readme:
                continue

            records, stats = await extract_evidence_hybrid(
                readme, cve_id, full_name, html_url,
            )
            ai_calls += stats["ai_calls"]
            ai_failures += stats["ai_failures"]
            regex_calls += stats["regex_calls"]

            if records:
                repos_with_evidence += 1
                evidence.extend(records)

        # Cap BEFORE renumbering (IDs stay contiguous).
        if len(evidence) > max_evidence:
            logger.info(
                "[crawl_evidence] capping %d evidence records to %d (--max-evidence)",
                len(evidence), max_evidence,
            )
            evidence = evidence[:max_evidence]

        # Per-CVE global renumbering (001..N).
        for i, rec in enumerate(evidence, 1):
            rec.id = _make_evidence_id(cve_id, i)

        if ai_calls == 0:
            backend_mode = "regex"
        elif ai_failures == ai_calls:
            backend_mode = "regex"
        elif ai_failures > 0:
            backend_mode = "hybrid"
        else:
            backend_mode = "ai"

        metadata = {
            "schema_version": "2.0",
            "extraction_stats": {
                "ai_records": sum(1 for r in evidence if r.extraction_method == "ai"),
                "regex_records": sum(1 for r in evidence if r.extraction_method == "regex"),
                "ai_calls": ai_calls,
                "ai_failures": ai_failures,
                "regex_calls": regex_calls,
                "backend_mode": backend_mode,
                "repos_with_evidence": repos_with_evidence,
                "repos_without_evidence": len(top_repos) - repos_with_evidence,
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    return {
        "cve_id": cve_id,
        "evidence": [r.model_dump() for r in evidence],
        "references": references,
        "metadata": metadata,
    }


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Crawl PoC evidence từ nomi-sec. Output JSON schema v2.0.",
    )
    parser.add_argument("--cve", required=True, help="CVE ID (e.g. CVE-2021-44228)")
    parser.add_argument(
        "--output", "-o",
        help="Write JSON to file (mặc định: stdout)",
    )
    parser.add_argument(
        "--max-repos", type=int, default=5,
        help="Cap số repo crawl theo stars (mặc định 5)",
    )
    parser.add_argument(
        "--max-evidence", type=int, default=50,
        help="Cap tổng evidence records per CVE (mặc định 50)",
    )
    args = parser.parse_args()

    try:
        result = asyncio.run(
            crawl(
                args.cve,
                max_repos=args.max_repos,
                max_evidence=args.max_evidence,
            )
        )
    except KeyboardInterrupt:
        sys.exit(130)

    json_str = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(json_str, encoding="utf-8")
        stats = result["metadata"]["extraction_stats"]
        print(
            f"Written {args.output}: "
            f"{len(result['evidence'])} evidence "
            f"({stats['ai_records']} ai, {stats['regex_records']} regex), "
            f"{len(result['references'])} references, "
            f"schema v{result['metadata']['schema_version']}",
            file=sys.stderr,
        )
    else:
        print(json_str)


if __name__ == "__main__":
    main()
