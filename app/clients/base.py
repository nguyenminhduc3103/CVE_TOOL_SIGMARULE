from __future__ import annotations

from typing import Any, Dict, Optional

import httpx


class BaseHTTPClient:
    """Reusable async HTTP client wrapper using httpx.AsyncClient.

    Note: This client is a thin wrapper. Real API calls and auth belong in
    provider-specific client implementations.
    """

    def __init__(self, base_url: str | None = None, timeout: int = 10) -> None:
        self.base_url = base_url
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self):
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self._client:
            await self._client.aclose()

    async def aclose(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        if not self._client:
            self._client = httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout)
        return await self._client.request(method, url, **kwargs)

    async def get(self, url: str, params: Optional[Dict[str, Any]] = None, **kwargs) -> httpx.Response:
        return await self.request("GET", url, params=params, **kwargs)
