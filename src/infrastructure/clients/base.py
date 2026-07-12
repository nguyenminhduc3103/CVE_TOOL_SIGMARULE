"""Base HTTP client."""
from __future__ import annotations

import httpx
from typing import Optional


class BaseHTTPClient:
    def __init__(self, base_url: Optional[str] = None, timeout: int = 10) -> None:
        self.base_url = base_url
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def get(self, endpoint: str, **kwargs):
        # Always inject a real User-Agent — some feeds (CISA KEV, NVD via
        # Cloudflare) reject requests with the default httpx/urllib UA.
        headers = kwargs.pop("headers", None) or {}
        headers.setdefault(
            "User-Agent", "cve-ti-platform/1.0 (+https://github.com/cve-ti)"
        )
        kwargs["headers"] = headers
        if self._client is None:
            self._client = httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout)
        return await self._client.get(endpoint, **kwargs)

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
