"""EPSS HTTP client."""
from app.shared.clients.base import BaseHTTPClient


class EPSSHTTPClient(BaseHTTPClient):
    BASE_URL = 'https://api.first.org'
    ENDPOINT = '/data/v1/epss'

    def __init__(self, timeout: float = 10.0) -> None:
        super().__init__(base_url=self.BASE_URL, timeout=timeout)

    async def fetch_raw(self, cve_id: str):
        response = await self.get(self.ENDPOINT, params={'cve': cve_id})
        # Return parsed JSON body (dict), not the raw httpx.Response object —
        # downstream EPSSProvider/Parser calls dict-style .get() on the result.
        try:
            return response.json()
        except Exception:
            return {}
