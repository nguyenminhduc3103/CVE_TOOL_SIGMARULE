"""Tool 2 — Extract primitive behaviors for every CAPEC.

Pipeline:
    .cache/mitre_attack/capec_canonical.json  (Tool 1 output)
        |
        |  per CAPEC: send 4 fields to AI
        |  (name, description, execution_flow, prerequisites)
        v
    .cache/ontology/capec_primitive_behaviors.json

Output schema:
    {
      "source": ".../capec_canonical.json",
      "model": "llama-3.3-70b-versatile",
      "count": <int>,
      "skipped": <int>,
      "errors": [{"capec_id": "...", "error": "..."}],
      "behaviors": {
        "CAPEC-1": ["resource_discovery", "authorization_bypass", ...],
        "CAPEC-2": ["credential_guessing", "account_lockout", ...],
        ...
      }
    }

Run:
    python scripts/extract_capec_primitive_behaviors.py
    python scripts/extract_capec_primitive_behaviors.py --concurrency 8
    python scripts/extract_capec_primitive_behaviors.py --resume
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
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config.settings import settings  # noqa: E402
from src.infrastructure.ai.core import AIServiceError, BaseAIClient  # noqa: E402

logger = logging.getLogger("extract_primitive_behaviors")

DEFAULT_IN = Path(".cache/mitre_attack/capec_canonical.json")
DEFAULT_OUT = Path(".cache/ontology/capec_primitive_behaviors.json")
PROMPTS_DIR = Path(__file__).parent / "prompts"
SYSTEM_PROMPT_PATH = PROMPTS_DIR / "capec_primitive_behaviors.system.txt"
USER_PROMPT_PATH = PROMPTS_DIR / "capec_primitive_behaviors.user.txt"

# Tokenize a snake_case primitive: lowercase ASCII letters/digits/underscore.
_TOKEN_RE = re.compile(r"^[a-z][a-z0-9_]*$")

# Pull "retry in Xs" from rate-limit error messages (Gemini / OpenAI both
# surface a hint like "Please retry in 25.08547798s."). Returns seconds or None.
_RETRY_AFTER_RE = re.compile(r"retry in (\d+(?:\.\d+)?)s", re.IGNORECASE)


def _extract_retry_after(err_msg: str) -> float | None:
    m = _RETRY_AFTER_RE.search(err_msg or "")
    if not m:
        return None
    try:
        return float(m.group(1))
    except (TypeError, ValueError):
        return None


def _clean_json(text: str) -> str:
    """Strip markdown fences / leading prose so json.loads can parse."""
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        return fenced.group(1).strip()
    first = text.find("{")
    last = text.rfind("}")
    if first != -1 and last != -1 and last > first:
        return text[first : last + 1].strip()
    return text.strip()


def _normalize_behaviors(raw: Any) -> list[str]:
    """Lowercase, dedup, validate snake_case tokens. Drop invalid entries."""
    if not isinstance(raw, list):
        return []
    seen: set[str] = set()
    out: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            continue
        token = item.strip().lower().replace("-", "_").replace(" ", "_")
        # Collapse runs of underscores caused by replacements.
        token = re.sub(r"_+", "_", token).strip("_")
        if not token or not _TOKEN_RE.match(token):
            continue
        if token in seen:
            continue
        seen.add(token)
        out.append(token)
    return out


def _build_input_payload(capec: dict[str, Any]) -> dict[str, Any]:
    """Pick the four fields the AI needs and trim long text for the prompt."""
    description = (capec.get("description") or "").strip()
    # Cap description length: AI only needs intent, not the full prose.
    if len(description) > 1500:
        description = description[:1500] + " ..."

    execution_flow = capec.get("execution_flow") or []
    # Keep only title + description per step (drop long technique blobs the
    # model tends to regurgitate as primitive tokens).
    trimmed_flow: list[dict[str, Any]] = []
    for step in execution_flow:
        step_clean: dict[str, Any] = {}
        if step.get("title"):
            step_clean["title"] = str(step["title"])[:200]
        if step.get("description"):
            step_clean["description"] = str(step["description"])[:400]
        if step.get("techniques"):
            # Just keep the first 3 techniques truncated
            step_clean["techniques"] = [str(t)[:200] for t in step["techniques"][:3]]
        if step_clean:
            trimmed_flow.append(step_clean)

    return {
        "name": capec.get("name", ""),
        "description": description,
        "execution_flow": trimmed_flow,
        "prerequisites": capec.get("prerequisites") or [],
    }


class PrimitiveBehaviorExtractor:
    """Async runner that AI-extracts primitive behaviors per CAPEC."""

    def __init__(
        self,
        client: BaseAIClient,
        model: str,
        system_prompt: str,
        user_template: str,
        concurrency: int = 8,
        max_retries: int = 3,
        override_credentials: list[tuple[str, str]] | None = None,
        on_complete=None,
    ) -> None:
        self.client = client
        self.model = model
        self.system_prompt = system_prompt
        self.user_template = user_template
        self.sem = asyncio.Semaphore(concurrency)
        self.max_retries = max_retries
        # Each tuple is (api_key, base_url). When set, calls round-robin
        # across them so a per-key free-tier quota (e.g. 20 req/min) is
        # shared across all keys instead of bursting any single one.
        self.override_credentials = override_credentials
        if override_credentials:
            self._cred_cycle = itertools.cycle(override_credentials)
            self._cred_lock = threading.Lock()
        else:
            self._cred_cycle = None
            self._cred_lock = None
        # Optional sync callback invoked after every completed CAPEC.
        self.on_complete = on_complete

    def _next_credentials(self) -> tuple[str | None, str | None]:
        if self._cred_cycle is None:
            return None, None
        with self._cred_lock:
            return next(self._cred_cycle)

    async def extract_one(self, capec: dict[str, Any]) -> tuple[str, list[str] | None, str | None]:
        """Return (capec_id, primitives | None, error | None)."""
        capec_id = capec.get("capec_id", "")
        payload = _build_input_payload(capec)
        user_prompt = self.user_template.format(
            input_json=json.dumps(payload, ensure_ascii=False, indent=2),
        )

        async with self.sem:
            last_err: str | None = None
            # When override credentials are configured, run a per-credential
            # round: each failure rotates to the NEXT credential in the
            # list (not the same one twice). This dodges per-key quotas that
            # would otherwise bunch 3 retries on one exhausted key.
            if self.override_credentials:
                # Pick `total_attempts = max_retries * num_credentials` to
                # stay symmetric with the same-row quota allocation.
                cred_pool: list[tuple[str, str]] = list(self.override_credentials)
                n_keys = len(cred_pool)
                # Walk keys until we exhaust retries: each attempt uses the
                # next credential in cycle; on 429, skip to the next one.
                cred_iter = itertools.cycle(cred_pool)
                rotated_key, rotated_url = next(cred_iter)
                for attempt in range(1, self.max_retries * n_keys + 1):
                    try:
                        response = await self.client.call_llm(
                            system_prompt=self.system_prompt,
                            user_prompt=user_prompt,
                            model=self.model,
                            response_format_json=True,
                            override_api_key=rotated_key,
                            override_base_url=rotated_url,
                        )
                        data = json.loads(_clean_json(response))
                        behaviors = _normalize_behaviors(data.get("primitive_behaviors"))
                        if not behaviors:
                            # Empty result — treat as soft error and rotate.
                            last_err = "empty primitive_behaviors"
                            await asyncio.sleep(2.0 * attempt)
                            rotated_key, rotated_url = next(cred_iter)
                            continue
                        return capec_id, behaviors, None
                    except (json.JSONDecodeError, AIServiceError) as e:
                        last_err = f"{type(e).__name__}: {e}"
                        wait = _extract_retry_after(last_err) or (2.0 * attempt)
                        logger.warning(
                            "[%s] attempt %d (key %s) failed: %s; sleeping %.1fs",
                            capec_id, attempt, rotated_key[:8], last_err, wait,
                        )
                        await asyncio.sleep(wait)
                        rotated_key, rotated_url = next(cred_iter)
                    except Exception as e:  # pragma: no cover
                        last_err = f"Unexpected: {type(e).__name__}: {e}"
                        logger.error("[%s] unexpected error: %s", capec_id, e)
                        await asyncio.sleep(2.0 * attempt)
                        rotated_key, rotated_url = next(cred_iter)
                return capec_id, None, last_err

            # No override credentials: behave like before — single client,
            # its internal round-robin + retry does the work.
            for attempt in range(1, self.max_retries + 1):
                try:
                    response = await self.client.call_llm(
                        system_prompt=self.system_prompt,
                        user_prompt=user_prompt,
                        model=self.model,
                        response_format_json=True,
                    )
                    data = json.loads(_clean_json(response))
                    behaviors = _normalize_behaviors(data.get("primitive_behaviors"))
                    if not behaviors:
                        # AI returned empty list — treat as soft error and retry.
                        last_err = "empty primitive_behaviors"
                        await asyncio.sleep(2.0 * attempt)
                        continue
                    return capec_id, behaviors, None
                except (json.JSONDecodeError, AIServiceError) as e:
                    last_err = f"{type(e).__name__}: {e}"
                    logger.warning(
                        "[%s] attempt %d/%d failed: %s",
                        capec_id, attempt, self.max_retries, last_err,
                    )
                    # Parse "retry in Xs" hint from error (Gemini/OpenAI both
                    # surface it). When present, sleep exactly that long.
                    wait = _extract_retry_after(last_err) or (2.0 * attempt)
                    await asyncio.sleep(wait)
                except Exception as e:  # pragma: no cover
                    last_err = f"Unexpected: {type(e).__name__}: {e}"
                    logger.error("[%s] unexpected error: %s", capec_id, e)
                    await asyncio.sleep(2.0 * attempt)
            return capec_id, None, last_err

    async def extract_all(
        self,
        capecs: list[dict[str, Any]],
        on_progress: Any | None = None,
    ) -> tuple[dict[str, list[str]], list[dict[str, str]]]:
        """Run extraction concurrently; return (behaviors, errors)."""
        tasks = [self.extract_one(c) for c in capecs]
        behaviors: dict[str, list[str]] = {}
        errors: list[dict[str, str]] = []
        completed = 0
        total = len(tasks)
        for coro in asyncio.as_completed(tasks):
            capec_id, primitives, error = await coro
            completed += 1
            if primitives is not None:
                behaviors[capec_id] = primitives
            else:
                errors.append({"capec_id": capec_id, "error": error or "unknown"})
            if self.on_complete is not None:
                try:
                    self.on_complete(capec_id, primitives, error)
                except Exception as cb_err:  # pragma: no cover
                    logger.warning("[on_complete] callback error: %s", cb_err)
            if on_progress and completed % 10 == 0:
                on_progress(completed, total, len(behaviors), len(errors))
        return behaviors, errors


def _load_canonical(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    capecs = payload.get("capecs") or []
    # Stable numeric sort by CAPEC-N.
    capecs.sort(key=lambda c: int(c["capec_id"].split("-", 1)[1]))
    return capecs


def _load_resume(path: Path) -> tuple[dict[str, list[str]], list[dict[str, str]]]:
    """Return (existing_behaviors, existing_errors) from a partial output."""
    if not path.exists():
        return {}, []
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload.get("behaviors", {}) or {}, payload.get("errors", []) or []


def _save_output(
    path: Path,
    in_path: Path,
    model: str,
    behaviors: dict[str, list[str]],
    errors: list[dict[str, str]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "source": str(in_path),
        "model": model,
        "count": len(behaviors),
        "skipped": len(errors),
        "errors": errors,
        "behaviors": behaviors,
    }
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--in", dest="in_path", type=Path, default=DEFAULT_IN)
    parser.add_argument("--out", dest="out_path", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--concurrency", type=int, default=8,
                        help="Max concurrent AI calls (default 8).")
    parser.add_argument("--max-retries", type=int, default=3)
    parser.add_argument("--resume", action="store_true",
                        help="Skip CAPEC IDs already present in --out.")
    parser.add_argument("--limit", type=int, default=0,
                        help="Process only the first N CAPECs (useful for smoke).")
    parser.add_argument("--model", default=None,
                        help="Override model (default: settings.get_phase1_model()).")
    parser.add_argument("--provider", choices=["auto", "primary", "phase1", "tiered"],
                        default="auto",
                        help="Which AI provider to call. 'auto' uses phase1 keys "
                             "when they differ from primary; otherwise primary. "
                             "'tiered' rotates through all primary keys first, "
                             "then all phase1 keys (high→low quota fallback).")
    parser.add_argument("--dry-run", action="store_true",
                        help="Render the promp for the first CAPEC and exit.")
    parser.add_argument("--save-every", type=int, default=5,
                        help="Persist output every N completed CAPECs "
                             "(default 5; set 1 for crash-safe writes).")
    return parser


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    args = _build_parser().parse_args()

    capecs = _load_canonical(args.in_path)
    if args.limit > 0:
        capecs = capecs[: args.limit]
    logger.info("Loaded %d CAPECs from %s", len(capecs), args.in_path)

    # Dry-run: render first prompt and exit.
    if args.dry_run:
        system_prompt = SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
        user_template = USER_PROMPT_PATH.read_text(encoding="utf-8")
        sample = _build_input_payload(capecs[0])
        print("=== SYSTEM (first 400 chars) ===")
        print(system_prompt[:400])
        print("\n=== USER (rendered) ===")
        print(user_template.format(
            input_json=json.dumps(sample, ensure_ascii=False, indent=2),
        ))
        return

    # Resume support: skip already-processed CAPECs.
    existing_behaviors: dict[str, list[str]] = {}
    existing_errors: list[dict[str, str]] = []
    if args.resume:
        existing_behaviors, existing_errors = _load_resume(args.out_path)
        skip = set(existing_behaviors) | {e["capec_id"] for e in existing_errors}
        capecs = [c for c in capecs if c["capec_id"] not in skip]
        logger.info(
            "Resume: kept %d CAPECs to process (skipped %d already in output).",
            len(capecs), len(skip),
        )

    if not capecs:
        logger.info("Nothing to do.")
        return

    # Build client + prompts.
    client = BaseAIClient()
    if not getattr(settings, "ai_enabled", False):
        logger.error(
            "AI is disabled in settings (ai_enabled=False). "
            "Set AI_ENABLED=1 and AI_API_KEY/AI_BASE_URL in .env."
        )
        return

    # Resolve model + provider override (Phase 1 vs Primary).
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
                "Phase 1 provider requested but no PHASE1_AI_API_KEY "
                "(or PHASE1_AI_KEYS) configured."
            )
            return
        # Build round-robin credentials list. With multiple Gemini keys,
        # concurrency can be > 1 without bursting one key.
        override_credentials = [(k, phase1_base_url) for k in phase1_keys]
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
        model = args.model or settings.get_analyze_model() or "llama-3.3-70b-versatile"
        logger.info(
            "Using TIERED credentials (primary→phase1): model=%s total_keys=%d",
            model, len(override_credentials),
        )
    else:
        override_credentials = None
        model = args.model or settings.get_analyze_model() or "llama-3.3-70b-versatile"
        logger.info("Using primary provider: model=%s base_url=%s", model, main_base_url)

    system_prompt = SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
    user_template = USER_PROMPT_PATH.read_text(encoding="utf-8")

    # Incremental save state: start with whatever resume loaded, then merge
    # new results as they arrive.
    behaviors: dict[str, list[str]] = dict(existing_behaviors)
    errors: list[dict[str, str]] = list(existing_errors)
    save_lock = asyncio.Lock()
    save_counter = 0

    def _save_now() -> None:
        _save_output(args.out_path, args.in_path, model, behaviors, errors)

    def _on_capec_done(capec_id: str, primitives: list[str] | None,
                       error: str | None) -> None:
        # Mutating shared state — only the save_lock protects against races
        # with concurrent callbacks that fire while _save_now() is mid-write.
        nonlocal save_counter
        if primitives is not None:
            behaviors[capec_id] = primitives
        else:
            errors.append({"capec_id": capec_id, "error": error or "unknown"})
        save_counter += 1
        if save_counter % max(1, args.save_every) == 0:
            try:
                _save_now()
            except Exception as sv_err:  # pragma: no cover
                logger.warning("[save] incremental write failed: %s", sv_err)

    extractor = PrimitiveBehaviorExtractor(
        client=client,
        model=model,
        system_prompt=system_prompt,
        user_template=user_template,
        concurrency=args.concurrency,
        max_retries=args.max_retries,
        override_credentials=override_credentials,
        on_complete=_on_capec_done,
    )

    logger.info(
        "Calling AI (model=%s, concurrency=%d, save_every=%d)",
        model, args.concurrency, args.save_every,
    )

    def _progress(done: int, total: int, ok: int, err: int) -> None:
        logger.info("[progress] %d/%d done (ok=%d, err=%d)", done, total, ok, err)

    try:
        await extractor.extract_all(capecs, on_progress=_progress)
    finally:
        await client.close()

    # Final flush (covers the partial batch where save_counter % save_every != 0).
    _save_now()
    logger.info(
        "Wrote %d behaviors, %d errors to %s",
        len(behaviors), len(errors), args.out_path,
    )


if __name__ == "__main__":
    asyncio.run(main())