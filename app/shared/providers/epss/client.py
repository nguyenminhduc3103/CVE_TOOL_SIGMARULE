"""EPSS client wrapper."""
from app.shared.clients.epss_client import EPSSHTTPClient
from app.shared.providers.base import BaseProvider


class EPSSClientWrapper(BaseProvider):
    def __init__(self):
        self.client = EPSSHTTPClient()

    async def enrich(self, cve_id: str):
        from app.shared.providers.epss.parser import EPSSParser
        # `client.fetch_raw` already returns a parsed JSON dict, not a Response.
        response = await self.client.fetch_raw(cve_id)
        return EPSSParser().normalize(response, cve_id)

    async def fetch(self, cve_id: str):
        return await self.enrich(cve_id)
