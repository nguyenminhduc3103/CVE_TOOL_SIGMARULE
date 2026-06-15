"""NVD HTTP client."""
from app.shared.clients.base import BaseHTTPClient


class NVDHTTPClient(BaseHTTPClient):
    BASE_URL = 'https://services.nvd.nist.gov'
    ENDPOINT = '/rest/json/cves/2.0'

    def __init__(self, timeout: float = 10.0) -> None:
        super().__init__(base_url=self.BASE_URL, timeout=timeout)

    async def fetch_raw(self, cve_id: str):
        response = await self.get(self.ENDPOINT, params={'cveId': cve_id})
        # Return parsed JSON body (dict), not the raw httpx.Response object —
        # downstream NVDParser calls dict-style .get() on the result.
        try:
            return response.json()
        except Exception:
            return {}
