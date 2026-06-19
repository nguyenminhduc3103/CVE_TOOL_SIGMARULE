"""NVD HTTP client.

Layered design:
- Outer: per-CVE ResponseCache (24h TTL for success, 60s for cached failures).
- Inner: 3-attempt retry with exponential backoff, content-type guard,
  and status-aware error caching (5xx/429 retried, others fail-fast).
"""
import asyncio
import os

import httpx

from app.shared.clients.base import BaseHTTPClient
from app.shared.cache.response_cache import ResponseCache


def _settings_api_key() -> str | None:
    """Read api key from app settings, lazily to avoid circular imports.

    Imported here (not at module top) because `app.core.config` is allowed
    to import from `app.shared` in the future.
    """
    try:
        from app.core.config import settings  # noqa: WPS433
    except Exception:
        return None
    return getattr(settings, "nvd_api_key", None)


class NVDHTTPClient(BaseHTTPClient):
    BASE_URL = 'https://services.nvd.nist.gov'
    ENDPOINT = '/rest/json/cves/2.0'
    # NVD is SLOW even with a valid key — measured ~49s for a single CVE
    # in practice. 90s timeout gives us headroom for cold-cache first hit
    # without hanging the pipeline.
    DEFAULT_TIMEOUT = 90.0
    # Three attempts (initial + 2 retries) with longer backoff to ride out
    # transient timeouts / 503s from NVD's rate limiter / Cloudflare wall.
    MAX_ATTEMPTS = 3

    def __init__(self, timeout: float = DEFAULT_TIMEOUT, api_key: str | None = None, cache: ResponseCache | None = None) -> None:
        # Resolve API key from (in priority order):
        # 1. explicit constructor arg
        # 2. NVD_API_KEY env var
        # 3. settings.nvd_api_key (read from .env via pydantic-settings)
        # 4. None (unauthenticated — much stricter rate limits)
        self._api_key = (
            api_key
            or os.environ.get("NVD_API_KEY")
            or _settings_api_key()
        )
        super().__init__(base_url=self.BASE_URL, timeout=timeout)
        self._cache = cache or ResponseCache()

    def _request_headers(self) -> dict[str, str]:
        headers = {
            "User-Agent": "cve-ti-platform/1.0 (+https://github.com/cve-ti)",
        }
        if self._api_key:
            # NVD requires the key in the `apiKey` header (not query string).
            headers["apiKey"] = self._api_key
        return headers

    async def fetch_raw(self, cve_id: str):
        # Cache hit fast-path: skip the network entirely on a fresh entry.
        # Cached failures (HTTP error marker) are re-raised so callers see
        # the same error they would on a live call — but no network is hit.
        cached = self._cache.get("nvd", cve_id)
        if cached is not None:
            if isinstance(cached, dict) and "__error__" in cached:
                marker = cached["__error__"]
                status = marker if isinstance(marker, int) else 503
                raise httpx.HTTPStatusError(
                    f"NVD cached failure for {cve_id} (status={status})",
                    request=None,
                    response=httpx.Response(status_code=status),
                )
            return cached

        last_exc: Exception | None = None
        for attempt in range(1, self.MAX_ATTEMPTS + 1):
            try:
                response = await self.get(
                    self.ENDPOINT,
                    params={'cveId': cve_id},
                    headers=self._request_headers(),
                )
                # Surface non-2xx (503 from NVD/Cloudflare, 404, 5xx) so the
                # provider marks the call as failed instead of silently
                # returning an empty body that later turns into a bare
                # CoreCVEData with no fields.
                if response.status_code >= 400:
                    body_preview = (response.text or "")[:120]
                    raise httpx.HTTPStatusError(
                        f"NVD returned HTTP {response.status_code} for {cve_id}: {body_preview!r}",
                        request=response.request,
                        response=response,
                    )
                # NVD serves application/json for real responses; if the
                # content-type isn't JSON it's almost certainly a Cloudflare
                # challenge or maintenance page. Don't silently swallow it.
                ctype = (response.headers.get("content-type") or "").lower()
                if "json" not in ctype:
                    body_preview = (response.text or "")[:120]
                    # Cloudflare challenge / maintenance page — short-cache
                    # the failure so we don't keep re-fetching the same wall.
                    self._cache.set(
                        "nvd",
                        cve_id,
                        {"__error__": "cloudflare_block"},
                        ttl_seconds=60,
                    )
                    raise httpx.HTTPStatusError(
                        f"NVD returned non-JSON response (content-type={ctype!r}) for {cve_id}: {body_preview!r}",
                        request=response.request,
                        response=response,
                    )
                # Return parsed JSON body (dict), not the raw httpx.Response
                # object — downstream NVDParser calls dict-style .get() on it.
                try:
                    payload = response.json()
                except Exception as exc:
                    raise httpx.HTTPError(
                        f"NVD response for {cve_id} was not valid JSON: {exc}"
                    ) from exc
                # Cache successful response at full 24h TTL.
                self._cache.set("nvd", cve_id, payload)
                return payload
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                last_exc = exc
                if attempt >= self.MAX_ATTEMPTS:
                    raise
                # Exponential backoff between retries: 2s, 4s. NVD can be
                # very slow on cold cache, so don't give up too quickly.
                await asyncio.sleep(2.0 * (2 ** (attempt - 1)))
            except httpx.HTTPStatusError as exc:
                # Retry on 429/5xx (rate limit / transient outage) but bail
                # out fast on 4xx other than 429 (e.g. 404 for unknown CVE).
                status = exc.response.status_code if exc.response is not None else 0
                if status == 429 or status >= 500:
                    # On final attempt, cache the failure briefly so we don't
                    # hammer a struggling upstream on the next request.
                    if attempt >= self.MAX_ATTEMPTS:
                        self._cache.set(
                            "nvd",
                            cve_id,
                            {"__error__": status},
                            ttl_seconds=60,
                        )
                        raise
                    # Longer backoff for rate limiting: 3s, 6s.
                    await asyncio.sleep(3.0 * (2 ** (attempt - 1)))
                    continue
                raise
        # Unreachable, but keep static analyzers happy.
        if last_exc is not None:
            raise last_exc
        return {}