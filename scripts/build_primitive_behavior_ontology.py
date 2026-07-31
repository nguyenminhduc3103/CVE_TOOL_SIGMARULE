"""Tool 3 — Build the primitive-behavior ontology from CAPEC behaviors.

Pipeline:
    .cache/ontology/capec_primitive_behaviors.json  (Tool 2 output)
        |
        |  Step 1: collect all tokens into a unique candidate list
        |  Step 2: AI-assisted clustering (batched) -> {canonical: [aliases]}
        |  Step 3: AI-assisted descriptions (batched) -> {token: sentence}
        |  Step 4: deterministic fallback if AI disabled / fails
        v
    .cache/ontology/primitive_behavior_ontology.json

Output schema:
    {
      "source": ".../capec_primitive_behaviors.json",
      "count": <int>,
      "primitives": [
        {
          "primitive": "authorization_bypass",
          "aliases": ["acl_bypass", "permission_bypass"],
          "description": "Access a protected resource without proper authorization.",
          "capecs": ["CAPEC-1", "CAPEC-122", "CAPEC-233"]
        },
        ...
      ]
    }

Run:
    python scripts/build_primitive_behavior_ontology.py
    python scripts/build_primitive_behavior_ontology.py --batch-size 80
    python scripts/build_primitive_behavior_ontology.py --no-ai
"""

from __future__ import annotations

import argparse
import asyncio
import itertools
import json
import logging
import re
import sys
import threading
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config.settings import settings  # noqa: E402
from src.infrastructure.ai.core import AIServiceError, BaseAIClient  # noqa: E402

logger = logging.getLogger("build_primitive_ontology")

DEFAULT_IN = Path(".cache/ontology/capec_primitive_behaviors.json")
DEFAULT_OUT = Path(".cache/ontology/primitive_behavior_ontology.json")
PROMPTS_DIR = Path(__file__).parent / "prompts"
CLUSTER_SYSTEM = PROMPTS_DIR / "cluster_primitive_behaviors.system.txt"
CLUSTER_USER = PROMPTS_DIR / "cluster_primitive_behaviors.user.txt"
DESCRIBE_SYSTEM = PROMPTS_DIR / "describe_primitive_behaviors.system.txt"
DESCRIBE_USER = PROMPTS_DIR / "describe_primitive_behaviors.user.txt"

_TOKEN_RE = re.compile(r"^[a-z][a-z0-9_]*$")


def _build_credential_cycle(
    credentials: list[tuple[str, str]] | None,
) -> tuple[itertools.cycle | None, threading.Lock | None]:
    """Return (cycle, lock) for round-robin across multiple API keys."""
    if not credentials:
        return None, None
    return itertools.cycle(credentials), threading.Lock()


_VERB_PREFIXES = (
    "execute", "bypass", "enumerate", "inject", "read", "write",
    "discover", "spoof", "forge", "tamper", "intercept", "replay",
    "manipulate", "exfiltrate", "exhaust", "crash", "overflow",
    "sniff", "redirect", "masquerade", "evade", "persist", "escalate",
    "trigger", "exploit", "leak", "guess", "scan", "probe", "steal",
    "impersonate", "embed", "hide", "extract", "craft", "deliver",
    "send", "receive", "modify", "delete", "create", "drop", "load",
)


def _clean_json(text: str) -> str:
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        return fenced.group(1).strip()
    first = text.find("{")
    last = text.rfind("}")
    if first != -1 and last != -1 and last > first:
        return text[first : last + 1].strip()
    return text.strip()


def _normalize_key(token: str) -> str:
    """Aggressive normalizer used only for fallback clustering.

    Strips plural/gerund suffixes, drops common stop words, sorts multi-word
    tokens so word-order variants collapse to the same key.
    """
    t = token.strip().lower()
    # Drop trailing s/es/ing that often vary between spellings.
    for suffix in ("_ing", "ies", "ing", "ies", "ed", "es", "s"):
        if t.endswith(suffix) and len(t) > len(suffix) + 2:
            t = t[: -len(suffix)]
            break
    # Word-order invariant: sort words alphabetically.
    parts = sorted(p for p in re.split(r"[_]+", t) if p)
    return "_".join(parts)


def _deterministic_cluster(tokens: list[str]) -> dict[str, list[str]]:
    """Group tokens by ``_normalize_key``; pick the shortest token as canonical.

    This is a coarse fallback used when AI is unavailable — it merges
    word-order variants and plural variants but NOT true synonyms
    (e.g. authorization_bypass vs auth_bypass stay separate).
    """
    buckets: dict[str, list[str]] = defaultdict(list)
    for tok in tokens:
        buckets[_normalize_key(tok)].append(tok)
    out: dict[str, list[str]] = {}
    for group in buckets.values():
        # Canonical = shortest token (most concise form).
        canonical = min(group, key=lambda x: (len(x), x))
        out[canonical] = [t for t in group if t != canonical]
    return out


async def _call_cluster_batch(
    client: BaseAIClient,
    model: str,
    system_prompt: str,
    user_template: str,
    batch: list[str],
    max_retries: int,
    cred_cycle: itertools.cycle | None = None,
    cred_lock: threading.Lock | None = None,
    override_api_key: str | None = None,
    override_base_url: str | None = None,
) -> dict[str, list[str]] | None:
    """Ask AI to cluster one batch; return {canonical: [aliases]} or None."""
    user_prompt = user_template.format(
        input_json=json.dumps(sorted(batch), ensure_ascii=False, indent=2),
    )
    last_err: str | None = None
    for attempt in range(1, max_retries + 1):
        # Pick a credential (round-robin if cycle supplied, else static override).
        if cred_cycle is not None:
            with cred_lock:
                api_key, base_url = next(cred_cycle)
        else:
            api_key = override_api_key
            base_url = override_base_url
        try:
            response = await client.call_llm(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                model=model,
                response_format_json=True,
                override_api_key=api_key,
                override_base_url=base_url,
            )
            data = json.loads(_clean_json(response))
            clusters = data.get("clusters") or []
            out: dict[str, list[str]] = {}
            covered: set[str] = set()
            for cl in clusters:
                canonical = cl.get("canonical")
                aliases = cl.get("aliases") or []
                if not isinstance(canonical, str) or not _TOKEN_RE.match(canonical):
                    continue
                if canonical in covered:
                    continue
                covered.add(canonical)
                clean_aliases: list[str] = []
                for a in aliases:
                    if not isinstance(a, str):
                        continue
                    a = a.strip()
                    if not _TOKEN_RE.match(a):
                        continue
                    if a == canonical or a in covered:
                        continue
                    covered.add(a)
                    clean_aliases.append(a)
                out[canonical] = clean_aliases
            # Sanity: every input token must be covered.
            missing = [t for t in batch if t not in covered]
            if missing:
                # Surface as singletons so we don't lose tokens.
                for m in missing:
                    out.setdefault(m, [])
                    covered.add(m)
            return out
        except (json.JSONDecodeError, AIServiceError) as e:
            last_err = f"{type(e).__name__}: {e}"
            logger.warning(
                "[cluster] batch=%d attempt=%d/%d failed: %s",
                len(batch), attempt, max_retries, last_err,
            )
            await asyncio.sleep(1.0 * attempt)
        except Exception as e:  # pragma: no cover
            last_err = f"Unexpected: {type(e).__name__}: {e}"
            logger.error("[cluster] unexpected error: %s", e)
            await asyncio.sleep(1.0 * attempt)
    return None


async def _ai_cluster_all(
    client: BaseAIClient,
    model: str,
    system_prompt: str,
    user_template: str,
    tokens: list[str],
    batch_size: int,
    concurrency: int,
    max_retries: int,
    cred_cycle: itertools.cycle | None = None,
    cred_lock: threading.Lock | None = None,
    override_api_key: str | None = None,
    override_base_url: str | None = None,
) -> tuple[dict[str, list[str]], int]:
    """Cluster all tokens with bounded AI calls.

    Returns (canonical_to_aliases_map, num_failed_batches).
    """
    batches: list[list[str]] = [
        tokens[i : i + batch_size]
        for i in range(0, len(tokens), batch_size)
    ]
    sem = asyncio.Semaphore(concurrency)
    results: list[dict[str, list[str]] | None] = [None] * len(batches)

    async def _run(idx: int, batch: list[str]) -> None:
        async with sem:
            results[idx] = await _call_cluster_batch(
                client, model, system_prompt, user_template,
                batch, max_retries,
                cred_cycle=cred_cycle,
                cred_lock=cred_lock,
                override_api_key=override_api_key,
                override_base_url=override_base_url,
            )

    await asyncio.gather(*[_run(i, b) for i, b in enumerate(batches)])

    merged: dict[str, list[str]] = {}
    failed = 0
    for r in results:
        if r is None:
            failed += 1
            continue
        for canonical, aliases in r.items():
            if canonical in merged:
                # Merge aliases, dedup.
                seen = set(merged[canonical])
                for a in aliases:
                    if a not in seen:
                        merged[canonical].append(a)
                        seen.add(a)
            else:
                merged[canonical] = list(aliases)
    return merged, failed


async def _ai_describe_all(
    client: BaseAIClient,
    model: str,
    system_prompt: str,
    user_template: str,
    canonicals: list[str],
    batch_size: int,
    concurrency: int,
    max_retries: int,
    cred_cycle: itertools.cycle | None = None,
    cred_lock: threading.Lock | None = None,
    override_api_key: str | None = None,
    override_base_url: str | None = None,
) -> tuple[dict[str, str], int]:
    """Batch-describe all canonical primitives."""
    batches: list[list[str]] = [
        canonicals[i : i + batch_size]
        for i in range(0, len(canonicals), batch_size)
    ]
    sem = asyncio.Semaphore(concurrency)
    results: list[dict[str, str] | None] = [None] * len(batches)

    async def _run(idx: int, batch: list[str]) -> None:
        async with sem:
            user_prompt = user_template.format(
                input_json=json.dumps(sorted(batch), ensure_ascii=False, indent=2),
            )
            last_err: str | None = None
            for attempt in range(1, max_retries + 1):
                if cred_cycle is not None:
                    with cred_lock:
                        api_key, base_url = next(cred_cycle)
                else:
                    api_key = override_api_key
                    base_url = override_base_url
                try:
                    response = await client.call_llm(
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        model=model,
                        response_format_json=True,
                        override_api_key=api_key,
                        override_base_url=base_url,
                    )
                    data = json.loads(_clean_json(response))
                    desc_map = data.get("descriptions") or {}
                    if not isinstance(desc_map, dict):
                        raise ValueError("descriptions is not a dict")
                    # Keep only valid string entries for tokens in this batch.
                    clean: dict[str, str] = {}
                    for k, v in desc_map.items():
                        if isinstance(k, str) and isinstance(v, str):
                            v = v.strip()
                            if v and k in batch:
                                clean[k] = v
                    results[idx] = clean
                    return
                except (json.JSONDecodeError, AIServiceError, ValueError) as e:
                    last_err = f"{type(e).__name__}: {e}"
                    logger.warning(
                        "[describe] batch=%d attempt=%d/%d failed: %s",
                        len(batch), attempt, max_retries, last_err,
                    )
                    await asyncio.sleep(1.0 * attempt)
                except Exception as e:  # pragma: no cover
                    last_err = f"Unexpected: {type(e).__name__}: {e}"
                    logger.error("[describe] unexpected error: %s", e)
                    await asyncio.sleep(1.0 * attempt)
            results[idx] = None

    await asyncio.gather(*[_run(i, b) for i, b in enumerate(batches)])

    merged: dict[str, str] = {}
    failed = 0
    for r in results:
        if r is None:
            failed += 1
            continue
        merged.update(r)
    return merged, failed


def _fallback_description(token: str) -> str:
    """Deterministic placeholder used when AI is unavailable."""
    # Convert snake_case to a sentence that reads as an attacker action.
    words = token.replace("_", " ")
    head = words.split(" ", 1)[0]
    if head in _VERB_PREFIXES:
        return f"{words.capitalize()}."
    return f"Perform a {words} action."


def _load_capec_behaviors(path: Path) -> tuple[dict[str, list[str]], dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload.get("behaviors") or {}, payload


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--in", dest="in_path", type=Path, default=DEFAULT_IN)
    parser.add_argument("--out", dest="out_path", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--batch-size", type=int, default=60,
                        help="Tokens per AI batch (cluster + describe).")
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--max-retries", type=int, default=3)
    parser.add_argument("--model", default=None,
                        help="Override model (default: settings.get_phase1_model()).")
    parser.add_argument(
        "--no-ai", action="store_true",
        help="Skip AI calls entirely; use deterministic fallback for both "
             "clustering and descriptions.",
    )
    parser.add_argument("--provider", choices=["auto", "primary", "phase1", "tiered"],
                        default="auto",
                        help="Which AI provider to call. 'auto' uses phase1 keys "
                             "when they differ from primary; otherwise primary. "
                             "'tiered' rotates through all primary keys first, "
                             "then all phase1 keys (high→low quota fallback).")
    return parser


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    args = _build_parser().parse_args()

    capec_behaviors, src_payload = _load_capec_behaviors(args.in_path)
    if not capec_behaviors:
        logger.error("No behaviors found in %s — run Tool 2 first.", args.in_path)
        return
    logger.info("Loaded %d CAPEC behaviors from %s", len(capec_behaviors), args.in_path)

    # Step 1 — collect unique tokens.
    unique_tokens: set[str] = set()
    for behaviors in capec_behaviors.values():
        for tok in behaviors:
            if isinstance(tok, str) and _TOKEN_RE.match(tok):
                unique_tokens.add(tok)
    tokens_sorted = sorted(unique_tokens)
    logger.info("Unique candidate tokens: %d", len(tokens_sorted))

    # Build reverse index: token -> CAPECs that use it.
    token_to_capecs: dict[str, list[str]] = defaultdict(list)
    for capec_id, behaviors in capec_behaviors.items():
        seen_for_this_capec: set[str] = set()
        for tok in behaviors:
            if isinstance(tok, str) and tok in unique_tokens and tok not in seen_for_this_capec:
                token_to_capecs[tok].append(capec_id)
                seen_for_this_capec.add(tok)
    for tok in token_to_capecs:
        token_to_capecs[tok].sort(key=lambda s: int(s.split("-", 1)[1]))

    # Decide AI strategy.
    use_ai = (
        not args.no_ai
        and getattr(settings, "ai_enabled", False)
    )
    if args.no_ai:
        logger.info("AI disabled via --no-ai; using deterministic fallback.")
    elif not getattr(settings, "ai_enabled", False):
        logger.warning(
            "AI disabled in settings (ai_enabled=False); falling back to "
            "deterministic clustering."
        )
        use_ai = False

    cluster_failed = 0
    describe_failed = 0

    if use_ai:
        client = BaseAIClient()

        # Resolve provider override (Phase 1 vs Primary).
        phase1_keys = settings.get_phase1_api_keys()
        main_keys = settings.get_api_keys()
        main_base_url = getattr(settings, "ai_base_url", None)
        phase1_base_url = settings.get_phase1_base_url()

        has_separate_phase1 = (
            phase1_keys and (phase1_keys != main_keys or phase1_base_url != main_base_url)
        )

        if args.provider == "phase1" or (args.provider == "auto" and has_separate_phase1):
            if not phase1_keys:
                logger.error(
                    "Phase 1 provider requested but no PHASE1_AI_API_KEY configured."
                )
                return
            override_credentials = [(k, phase1_base_url) for k in phase1_keys]
            override_api_key = phase1_keys[0] if phase1_keys else None
            override_base_url = phase1_base_url
            model = args.model or settings.get_phase1_model() or "llama-3.3-70b-versatile"
            logger.info(
                "Using Phase 1 provider: model=%s base_url=%s keys=%d",
                model, phase1_base_url, len(override_credentials),
            )
        elif args.provider == "tiered":
            # Pool = primary keys FIRST (high quota), then phase1 (free tier).
            # Each attempt rotates through the entire pool, so when primary
            # burns out we fall through to Gemini without losing progress.
            override_credentials = (
                [(k, main_base_url) for k in main_keys]
                + [(k, phase1_base_url) for k in phase1_keys]
            )
            if not override_credentials:
                logger.error("Tiered provider requested but no API keys configured.")
                return
            override_api_key = override_credentials[0][0]
            override_base_url = override_credentials[0][1]
            model = args.model or settings.get_analyze_model() or "llama-3.3-70b-versatile"
            logger.info(
                "Using TIERED credentials (primary→phase1): model=%s total_keys=%d",
                model, len(override_credentials),
            )
        else:
            override_credentials = None
            override_api_key = None
            override_base_url = None
            model = args.model or settings.get_analyze_model() or "llama-3.3-70b-versatile"
            logger.info("Using primary provider: model=%s base_url=%s", model, main_base_url)

        cred_cycle, cred_lock = _build_credential_cycle(override_credentials)

        cluster_sys = CLUSTER_SYSTEM.read_text(encoding="utf-8")
        cluster_user = CLUSTER_USER.read_text(encoding="utf-8")
        describe_sys = DESCRIBE_SYSTEM.read_text(encoding="utf-8")
        describe_user = DESCRIBE_USER.read_text(encoding="utf-8")

        try:
            logger.info("[cluster] model=%s batch=%d concurrency=%d",
                        model, args.batch_size, args.concurrency)
            cluster_map, cluster_failed = await _ai_cluster_all(
                client, model, cluster_sys, cluster_user,
                tokens_sorted, args.batch_size, args.concurrency,
                args.max_retries,
                cred_cycle=cred_cycle,
                cred_lock=cred_lock,
                override_api_key=override_api_key,
                override_base_url=override_base_url,
            )
            logger.info("[cluster] %d canonicals (failed batches=%d)",
                        len(cluster_map), cluster_failed)

            canonicals = sorted(cluster_map.keys())
            logger.info("[describe] %d canonicals to describe", len(canonicals))
            descriptions, describe_failed = await _ai_describe_all(
                client, model, describe_sys, describe_user,
                canonicals, args.batch_size, args.concurrency,
                args.max_retries,
                cred_cycle=cred_cycle,
                cred_lock=cred_lock,
                override_api_key=override_api_key,
                override_base_url=override_base_url,
            )
            logger.info("[describe] %d descriptions (failed batches=%d)",
                        len(descriptions), describe_failed)
        finally:
            await client.close()

        # If AI cluster returned nothing usable, fall back entirely.
        if not cluster_map:
            logger.warning("AI clustering returned no clusters; using fallback.")
            cluster_map = _deterministic_cluster(tokens_sorted)
    else:
        cluster_map = _deterministic_cluster(tokens_sorted)
        logger.info("Used deterministic clustering: %d canonicals", len(cluster_map))
        descriptions = {}

    # Build the final primitive list.
    primitives: list[dict[str, Any]] = []
    for canonical in sorted(cluster_map.keys()):
        aliases = cluster_map.get(canonical, []) or []
        # Ensure every alias appears in the reverse index (defensive).
        capecs = sorted(set(token_to_capecs.get(canonical, [])))
        for alias in aliases:
            for c in token_to_capecs.get(alias, []):
                if c not in capecs:
                    capecs.append(c)
        description = (
            descriptions.get(canonical)
            or _fallback_description(canonical)
        )
        primitives.append({
            "primitive": canonical,
            "aliases": sorted(set(aliases)),
            "description": description,
            "capecs": capecs,
        })

    args.out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "source": str(args.in_path),
        "count": len(primitives),
        "ai_used": use_ai,
        "cluster_failed_batches": cluster_failed,
        "describe_failed_batches": describe_failed,
        "primitives": primitives,
    }
    args.out_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    logger.info(
        "Wrote %d primitives to %s (ai_used=%s)",
        len(primitives), args.out_path, use_ai,
    )


if __name__ == "__main__":
    asyncio.run(main())