"""EPSS HTTP client."""
from app.shared.clients.base import BaseHTTPClient
from app.shared.cache.response_cache import ResponseCache


class EPSSHTTPClient(BaseHTTPClient):
    BASE_URL = 'https://api.first.org'
    ENDPOINT = '/data/v1/epss'

    def __init__(self, timeout: float = 10.0, cache: ResponseCache | None = None) -> None:
        super().__init__(base_url=self.BASE_URL, timeout=timeout)
        self._cache = cache or ResponseCache()

    async def fetch_raw(self, cve_id: str):
        # Cache fast-path: EPSS scores change slowly, so 24h is safe.
        cached = self._cache.get("epss", cve_id)
        if cached is not None:
            if isinstance(cached, dict) and "__error__" in cached:
                return {}  # Treat cached upstream failure as empty payload.
            return cached

        try:
            response = await self.get(self.ENDPOINT, params={'cve': cve_id})
        except Exception:
            # Network-level error: short-cache empty result so callers don't
            # immediately re-hit the network on retry storms.
            self._cache.set("epss", cve_id, {}, ttl_seconds=60)
            return {}
        # Return parsed JSON body (dict), not the raw httpx.Response object —
        # downstream EPSSProvider/Parser calls dict-style .get() on the result.
        try:
            payload = response.json()
        except Exception:
            self._cache.set("epss", cve_id, {}, ttl_seconds=60)
            return {}
        self._cache.set("epss", cve_id, payload)
        return payload
