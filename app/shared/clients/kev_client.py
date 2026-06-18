"""KEV HTTP client with GitHub mirror fallback.

Tries CISA's primary endpoint first; on 403 (Akamai/WAF block) or network
error, falls back to the official `cisagov/kev-data` GitHub mirror so the
pipeline keeps working when the CDN is unreachable from this network.
"""
from __future__ import annotations

import asyncio
import os
from typing import Any

import httpx

from app.shared.clients.base import BaseHTTPClient
from app.core.logging import get_logger
from app.shared.cache.response_cache import ResponseCache


class KEVHTTPClient(BaseHTTPClient):
    BASE_URL = "https://www.cisa.gov"
    ENDPOINT = "/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    MIRROR_URL = (
        "https://raw.githubusercontent.com/"
        "cisagov/kev-data/main/known_exploited_vulnerabilities.json"
    )
    DEFAULT_USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
    )

    def __init__(self, timeout: float = 10.0, retries: int = 3, backoff_seconds: float = 0.5, cache: ResponseCache | None = None) -> None:
        kev_api_url = os.environ.get("KEV_API_URL")
        self.endpoint = kev_api_url or self.ENDPOINT
        self._using_default_endpoint = kev_api_url is None

        # `BaseHTTPClient.__init__` may create a default client. We replace it
        # with one that follows redirects (CISA may redirect), then patch in
        # our custom User-Agent.
        super().__init__(base_url=None if kev_api_url else self.BASE_URL, timeout=timeout)
        headers = {
            "User-Agent": os.environ.get("CUSTOM_USER_AGENT") or self.DEFAULT_USER_AGENT,
            "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://www.cisa.gov/",
        }
        self._client = httpx.AsyncClient(
            base_url=None if kev_api_url else self.BASE_URL,
            timeout=timeout,
            follow_redirects=True,
            headers=headers,
            trust_env=True,
        )

        self.retries = retries
        self.backoff_seconds = backoff_seconds
        self.logger = get_logger(__name__)
        self.last_error_message: str | None = None
        self.last_failure_kind: str | None = None
        self._cache = cache or ResponseCache()

    async def fetch_raw(self, cve_id: str) -> Any:
        # KEV is catalog-wide: every (cve_id, year) ask returns the same
        # JSON document, so we cache the whole payload keyed per-endpoint.
        cache_key = f"catalog::{self.endpoint}"
        cached = self._cache.get("kev", cache_key)
        if cached is not None:
            if isinstance(cached, dict) and "__error__" in cached:
                # Cached failure — surface it as None (KEV semantics) and
                # remember the failure kind so callers can branch on it.
                status = cached["__error__"]
                self.last_failure_kind = f"http_{status}"
                self.last_error_message = f"cached KEV failure (status={status})"
                return None
            return cached

        last_error: Exception | None = None
        self.last_error_message = None
        self.last_failure_kind = None

        for attempt in range(1, self.retries + 1):
            try:
                self.logger.info("[KEV] Fetching CVE", cve_id=cve_id, attempt=attempt)
                # `self._client` is created with `follow_redirects=True` so
                # we don't need to pass it per-call.
                response = await self._client.get(self.endpoint)
                response.raise_for_status()
                payload = response.json()
                self.logger.info(
                    "[KEV] Response received",
                    cve_id=cve_id,
                    status_code=response.status_code,
                )
                self._cache.set("kev", cache_key, payload)
                return payload
            except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError) as exc:
                if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 403:
                    self.logger.warning(
                        "[KEV] 403 Forbidden — likely Akamai/WAF block. "
                        f"cve_id={cve_id} attempt={attempt}"
                    )
                # Mirror fallback: only if we're on the default endpoint AND
                # the failure is retryable (timeout, network, 403).
                if self._using_default_endpoint and self._should_fallback_to_mirror(exc):
                    self.logger.warning(
                        "[WARN] Akamai/WAF chặn IP. Tự động chuyển hướng sang GitHub Mirror..."
                    )
                    mirror_payload = await self._fetch_from_mirror()
                    if mirror_payload is not None:
                        return mirror_payload

                last_error = exc
                retryable = self._is_retryable(exc)
                self.last_failure_kind = self._classify_failure(exc)
                self.last_error_message = self._short_message(exc)
                if not (isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 403):
                    self.logger.warning(
                        "[KEV] Request failed",
                        cve_id=cve_id,
                        attempt=attempt,
                        retryable=retryable,
                        error=self.last_error_message,
                    )
                if not retryable or attempt >= self.retries:
                    break
                await asyncio.sleep(self.backoff_seconds * (2 ** (attempt - 1)))

        # Cache transient upstream failures briefly so we don't hammer CISA
        # when it's down. Only cache retryable failures (429/5xx/timeout).
        if last_error is not None and self._is_retryable(last_error):
            status = (
                last_error.response.status_code
                if isinstance(last_error, httpx.HTTPStatusError)
                else 503
            )
            self._cache.set(
                "kev",
                cache_key,
                {"__error__": status},
                ttl_seconds=60,
            )

        if isinstance(last_error, httpx.HTTPStatusError) and last_error.response.status_code == 403:
            self.logger.error(f"[KEV] Failed cve_id={cve_id} error=403 Forbidden")
        return None

    async def _fetch_from_mirror(self) -> Any | None:
        try:
            response = await self._client.get(self.MIRROR_URL)
            response.raise_for_status()
            payload = response.json()
            self.logger.info(
                "[KEV] Mirror response received", status_code=response.status_code
            )
            return payload
        except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError) as exc:
            self.last_failure_kind = self._classify_failure(exc)
            self.last_error_message = self._short_message(exc)
            self.logger.warning(
                "[KEV] Mirror request failed", error=self.last_error_message
            )
            return None
        except Exception as exc:
            # Mirror returned non-JSON (HTML 404 page etc.)
            self.last_failure_kind = "bad_response"
            self.last_error_message = self._short_message(exc)
            self.logger.warning(
                "[KEV] Mirror returned non-JSON",
                error=self.last_error_message,
            )
            return None

    @staticmethod
    def _should_fallback_to_mirror(exc: Exception) -> bool:
        if isinstance(exc, (httpx.TimeoutException, httpx.NetworkError)):
            return True
        if isinstance(exc, httpx.HTTPStatusError):
            return exc.response.status_code == 403
        return False

    @staticmethod
    def _is_retryable(exc: Exception) -> bool:
        if isinstance(exc, (httpx.TimeoutException, httpx.NetworkError)):
            return True
        if isinstance(exc, httpx.HTTPStatusError):
            code = exc.response.status_code
            return code in {408, 425, 429} or code >= 500
        return False

    @staticmethod
    def _classify_failure(exc: Exception) -> str:
        if isinstance(exc, httpx.TimeoutException):
            return "timeout"
        if isinstance(exc, httpx.NetworkError):
            return "network_error"
        if isinstance(exc, httpx.HTTPStatusError):
            return f"http_{exc.response.status_code}"
        return "unknown"

    @staticmethod
    def _short_message(exc: Exception) -> str:
        return str(exc).splitlines()[0] if str(exc) else type(exc).__name__
