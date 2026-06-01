from __future__ import annotations

import asyncio
import os
from typing import Any

import httpx

from app.clients.base import BaseHTTPClient
from app.core.logging import get_logger


class KEVHTTPClient(BaseHTTPClient):
    BASE_URL = "https://www.cisa.gov"
    ENDPOINT = "/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    MIRROR_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
    DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

    def __init__(self, timeout: float = 10.0, retries: int = 3, backoff_seconds: float = 0.5) -> None:
        kev_api_url = os.environ.get("KEV_API_URL")
        self.endpoint = kev_api_url or self.ENDPOINT
        self._using_default_endpoint = kev_api_url is None
        base_url = None if kev_api_url else self.BASE_URL

        super().__init__(base_url=base_url, timeout=timeout)
        if self._client is None:
            self._client = httpx.AsyncClient(base_url=base_url, timeout=timeout, trust_env=True)
        self.retries = retries
        self.backoff_seconds = backoff_seconds
        self.logger = get_logger(__name__)
        self.last_error_message: str | None = None
        self.last_failure_kind: str | None = None
        self.user_agent = os.environ.get("CUSTOM_USER_AGENT") or self.DEFAULT_USER_AGENT

    def _headers(self) -> dict[str, str]:
        return {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://www.cisa.gov/",
        }

    async def fetch_raw(self, cve_id: str) -> Any:
        # TODO: add feed freshness checks if the upstream feed changes shape.
        last_error: Exception | None = None
        self.last_error_message = None
        self.last_failure_kind = None

        for attempt in range(1, self.retries + 1):
            try:
                self.logger.info("[KEV] Fetching CVE", cve_id=cve_id, attempt=attempt)
                response = await self.get(self.endpoint, headers=self._headers(), follow_redirects=True)
                response.raise_for_status()
                payload = response.json()
                self.logger.info("[KEV] Response received", cve_id=cve_id, status_code=response.status_code)
                return payload
            except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError) as exc:
                if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 403:
                    self.logger.warning(
                        f"[KEV] Request failed attempt={attempt} cve_id={cve_id} error=403 Forbidden retryable=False"
                    )
                if self._using_default_endpoint and self._should_fallback_to_mirror(exc):
                    self.logger.warning("[WARN] Akamai/WAF chặn IP. Tự động chuyển hướng sang GitHub Mirror...")
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

        if isinstance(last_error, httpx.HTTPStatusError) and last_error.response.status_code == 403:
            self.logger.error(f"[KEV] Failed cve_id={cve_id} error=403 Forbidden")
        return None

    async def _fetch_from_mirror(self) -> Any | None:
        try:
            response = await self.get(self.MIRROR_URL, headers=self._headers(), follow_redirects=True)
            response.raise_for_status()
            payload = response.json()
            self.logger.info("[KEV] Mirror response received", status_code=response.status_code)
            return payload
        except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError) as exc:
            if isinstance(exc, httpx.HTTPStatusError):
                self._log_http_error(exc)
            self.last_failure_kind = self._classify_failure(exc)
            self.last_error_message = self._short_message(exc)
            self.logger.warning("[KEV] Mirror request failed", error=self.last_error_message)
            return None

    def _should_fallback_to_mirror(self, exc: Exception) -> bool:
        if isinstance(exc, (httpx.TimeoutException, httpx.NetworkError)):
            return True
        if isinstance(exc, httpx.HTTPStatusError):
            return exc.response.status_code == 403
        return False

    def _is_retryable(self, exc: Exception) -> bool:
        if isinstance(exc, (httpx.TimeoutException, httpx.NetworkError)):
            return True
        if isinstance(exc, httpx.HTTPStatusError):
            return exc.response.status_code in {408, 425, 429} or exc.response.status_code >= 500
        return False

    def _classify_failure(self, exc: Exception) -> str:
        if isinstance(exc, httpx.TimeoutException):
            return "timeout"
        if isinstance(exc, httpx.NetworkError):
            return "network_error"
        if isinstance(exc, httpx.HTTPStatusError):
            if exc.response.status_code == 403:
                return "forbidden"
            if exc.response.status_code == 429:
                return "rate_limited"
            if exc.response.status_code >= 500:
                return "server_error"
            return "http_error"
        return "error"

    def _short_message(self, exc: Exception) -> str:
        if isinstance(exc, httpx.HTTPStatusError):
            return f"{exc.response.status_code} {exc.response.reason_phrase}"
        return str(exc).splitlines()[0]
