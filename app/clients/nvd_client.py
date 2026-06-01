from __future__ import annotations

import asyncio
from typing import Any

import httpx

from app.clients.base import BaseHTTPClient
from app.core.logging import get_logger


class NVDHTTPClient(BaseHTTPClient):
    BASE_URL = "https://services.nvd.nist.gov"
    ENDPOINT = "/rest/json/cves/2.0"

    def __init__(self, timeout: float = 10.0, retries: int = 3, backoff_seconds: float = 0.5) -> None:
        super().__init__(base_url=self.BASE_URL, timeout=timeout)
        self.retries = retries
        self.backoff_seconds = backoff_seconds
        self.logger = get_logger(__name__)

    async def fetch_cve(self, cve_id: str) -> dict[str, Any]:
        # TODO: add API key support and rate-limit aware retry strategy.
        params = {"cveId": cve_id}
        last_error: Exception | None = None

        for attempt in range(1, self.retries + 1):
            try:
                self.logger.info("[NVD] Fetching CVE", cve_id=cve_id, attempt=attempt)
                response = await self.get(self.ENDPOINT, params=params)
                response.raise_for_status()
                payload = response.json()
                self.logger.info("[NVD] Response received", cve_id=cve_id, status_code=response.status_code)
                return payload
            except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError) as exc:
                last_error = exc
                retryable = isinstance(exc, (httpx.TimeoutException, httpx.NetworkError)) or (
                    isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code >= 500
                )
                self.logger.warning("[NVD] Request failed", cve_id=cve_id, attempt=attempt, retryable=retryable, error=str(exc))
                if not retryable or attempt >= self.retries:
                    break
                await asyncio.sleep(self.backoff_seconds * attempt)

        assert last_error is not None
        raise last_error

    async def fetch_raw(self, cve_id: str) -> Any:
        return await self.fetch_cve(cve_id)
