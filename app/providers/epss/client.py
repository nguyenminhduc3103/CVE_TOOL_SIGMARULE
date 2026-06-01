from app.clients.epss_client import EPSSHTTPClient


class EPSSClientWrapper:
    def __init__(self) -> None:
        self._client = EPSSHTTPClient()

    async def fetch_raw(self, cve_id: str):
        # TODO: EPSS API specifics
        return await self._client.fetch_raw(cve_id)
