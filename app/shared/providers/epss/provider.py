"""EPSS provider orchestrator."""
from app.shared.providers.base import BaseProvider


class EPSSProvider(BaseProvider):
    def __init__(self):
        from app.shared.providers.epss.client import EPSSClientWrapper
        self.client = EPSSClientWrapper()

    async def enrich(self, cve_id: str):
        return await self.client.enrich(cve_id)

    async def fetch(self, cve_id: str):
        return await self.enrich(cve_id)
