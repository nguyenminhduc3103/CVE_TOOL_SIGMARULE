from app.clients.nvd_client import NVDHTTPClient


# TODO: Providers should use the shared clients in app.clients
# This thin wrapper exists to keep provider-local client boundary.

class NVDClientWrapper:
    def __init__(self) -> None:
        self._client = NVDHTTPClient()

    async def fetch_raw(self, cve_id: str):
        # TODO: add retries / auth handling at client layer
        return await self._client.fetch_raw(cve_id)
