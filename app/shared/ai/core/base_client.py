"""Base AI client (OpenAI-compatible: Groq, Anthropic, Ollama)."""
from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

from openai import AsyncOpenAI

from app.core.config import settings

logger = logging.getLogger(__name__)


class AIServiceError(Exception):
    """Raised when AI call cannot be fulfilled."""
    pass


class BaseAIClient:
    """Thin async wrapper around OpenAI AsyncClient. Subclasses (behavior, telemetry, etc.)
    add domain-specific prompt assembly on top of call_llm.

    Supports round-robin API key rotation (Groq free tier): set AI_API_KEYS=k1,k2,k3
    in .env. Falls back to AI_API_KEY (single) for backward compatibility.
    On 429 / rate_limit_exceeded response, switches to next key automatically.
    """

    def __init__(self) -> None:
        self.api_keys: list[str] = settings.get_api_keys()
        self.api_key = self.api_keys[0] if self.api_keys else None  # back-compat
        self.base_url = getattr(settings, "ai_base_url", None)
        self.ai_enabled = getattr(settings, "ai_enabled", False)
        # Round-robin cursor + lock (multi-call safety across coroutines).
        self._key_index: int = 0
        self._key_lock = threading.Lock()
        # Track usage counts per key (key index -> count). Useful for logs/debugging.
        self._key_usage: dict[int, int] = {}

        if self.ai_enabled:
            if not self.api_keys:
                logger.warning(
                    "AI enabled but no API key configured (AI_API_KEY / AI_API_KEYS). "
                    "Calls will fail with AIServiceError."
                )
            # max_retries=0 disables the SDK's internal retry on 429/5xx so
            # OUR round-robin (and our own retry budget) is the sole
            # backoff/rotation mechanism. Without this, the SDK would re-try
            # the same key 2-3x before our 429 detection ever fires.
            self.client = AsyncOpenAI(
                api_key=self.api_key,
                base_url=self.base_url,
                max_retries=0,
            )
        else:
            self.client = None
            logger.info("AI disabled by configuration (ai_enabled=False).")

    # ------------------------------------------------------------------
    # Key rotation helpers
    # ------------------------------------------------------------------

    def _next_key_index(self, current: int) -> int:
        """Return the index of the next key in the list (wraps around)."""
        if not self.api_keys:
            return current
        return (current + 1) % len(self.api_keys)

    def _rotate_to_next_key(self) -> str | None:
        """Advance the round-robin cursor and rebuild the OpenAI client with
        the new key. Returns the new key (or None if no keys configured).
        """
        with self._key_lock:
            old_idx = self._key_index
            if not self.api_keys:
                return None
            new_idx = (old_idx + 1) % len(self.api_keys)
            self._key_index = new_idx
            new_key = self.api_keys[new_idx]
            # Rebuild the client bound to the new key (base_url unchanged).
            self.client = AsyncOpenAI(
                api_key=new_key,
                base_url=self.base_url,
                max_retries=0,
            )
            self.api_key = new_key
        logger.debug(
            "[AI] rotating to key %d/%d after rate limit.",
            new_idx + 1,
            len(self.api_keys),
        )
        return new_key

    def _current_key_index(self) -> int:
        with self._key_lock:
            return self._key_index

    @staticmethod
    def _is_rate_limit_error(exc: Exception) -> bool:
        """Detect 429 / rate_limit_exceeded from Groq (or any OpenAI-compat)."""
        # openai SDK exposes status_code on APIError; httpx.HTTPStatusError too.
        status = getattr(exc, "status_code", None) or getattr(exc, "status", None)
        if status == 429:
            return True
        # Fallback: string match on body (Groq returns {"error":{"code":"rate_limit_exceeded",...}})
        body = getattr(exc, "body", None)
        if body and "rate_limit_exceeded" in str(body):
            return True
        msg = str(exc)
        if "rate_limit_exceeded" in msg or "Rate limit reached" in msg:
            return True
        return False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def call_llm(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str = "llama3-70b-8192",
        max_retries: int = 3,
        override_api_key: str | None = None,
        override_base_url: str | None = None,
    ) -> str:
        """Call the LLM. If `override_api_key`/`override_base_url` are provided,
        build a one-shot AsyncOpenAI client bound to those (used by retry path
        to switch providers — e.g. Groq analyze → Gemini retry to dodge TPM).
        """
        if not self.ai_enabled:
            raise AIServiceError("AI is disabled.")

        # Per-call override client (separate from self.client so we don't
        # touch the round-robin state for the primary key pool).
        if override_api_key:
            if not override_base_url:
                raise AIServiceError(
                    "override_api_key provided but override_base_url is None."
                )
            call_client = AsyncOpenAI(
                api_key=override_api_key,
                base_url=override_base_url,
                max_retries=0,
            )
            logger.debug(
                "[AI] retry call using override endpoint (%s, model=%s)",
                override_base_url,
                model,
            )
        else:
            if not self.api_keys:
                raise AIServiceError(
                    "No API key configured (set AI_API_KEY or AI_API_KEYS in .env)."
                )
            call_client = self.client

        last_exc: Exception | None = None
        # Round-robin (only for primary path): try up to len(api_keys) * max_retries
        # attempts total, rotating to the next key on 429. We use a single attempt
        # loop and rotate manually on rate-limit instead of nested loops to keep
        # the flow simple and the key-usage log accurate.
        if override_api_key:
            total_attempts = max_retries
        else:
            total_attempts = max_retries * len(self.api_keys)
        for attempt in range(total_attempts):
            key_idx = self._current_key_index() if not override_api_key else 0
            if not override_api_key:
                logger.debug(
                    "[AI] using key %d/%d (attempt %d/%d)",
                    key_idx + 1,
                    len(self.api_keys),
                    attempt + 1,
                    total_attempts,
                )
                with self._key_lock:
                    self._key_usage[key_idx] = self._key_usage.get(key_idx, 0) + 1
            try:
                response = await call_client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    max_tokens=4096,
                    temperature=0.0,
                )
                return response.choices[0].message.content
            except Exception as e:
                last_exc = e
                logger.debug("[AI] raw exception type=%s msg=%r body=%r status=%s", type(e).__name__, str(e), getattr(e, 'body', None), getattr(e, 'status_code', None))
                if self._is_rate_limit_error(e):
                    if override_api_key:
                        # Override path has only one "key" — no rotation.
                        # Just backoff and retry.
                        logger.warning(
                            "[AI] override endpoint hit rate limit (attempt %d/%d): %s",
                            attempt + 1, total_attempts, e,
                        )
                        await asyncio.sleep(2)
                        continue
                    logger.warning(
                        "[AI] key %d/%d hit rate limit (attempt %d/%d): %s",
                        key_idx + 1,
                        len(self.api_keys),
                        attempt + 1,
                        total_attempts,
                        e,
                    )
                    # Rotate to next key. If only one key, still re-raise to
                    # let outer retry/backoff handle it on next attempt.
                    if len(self.api_keys) > 1:
                        self._rotate_to_next_key()
                        # No sleep — move to next key immediately.
                        continue
                    # Single key: fall through to backoff path.
                    await asyncio.sleep(2)
                    continue
                # Non-rate-limit error: simple backoff retry.
                logger.warning(
                    "[AI] call attempt %d/%d failed: %s. Retrying in 2s.",
                    attempt + 1,
                    total_attempts,
                    e,
                )
                await asyncio.sleep(2)

        # All attempts exhausted.
        raise AIServiceError(
            f"AI Call failed after {total_attempts} attempts: {last_exc}"
        )
