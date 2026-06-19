"""NVD HTTP client."""
from app.shared.clients.base import BaseHTTPClient
from app.core.config import settings


class NVDHTTPClient(BaseHTTPClient):
    BASE_URL = 'https://services.nvd.nist.gov'
    ENDPOINT = '/rest/json/cves/2.0'

    def __init__(self, timeout: float = 10.0) -> None:
        super().__init__(base_url=self.BASE_URL, timeout=timeout)

    async def fetch_raw(self, cve_id: str):
        headers = {}
        if settings.nvd_api_key:
            headers['apiKey'] = settings.nvd_api_key

        response = await self.get(self.ENDPOINT, params={'cveId': cve_id}, headers=headers)
        # Raise HTTPStatusError for non-2xx responses to bubble up the status (e.g. 503, 403)
        response.raise_for_status()
        return response.json()
