"""PoC provider-local client wrapper — thin proxy over shared PoCHTTPClient.

Follows the same pattern as providers/nvd/client.py (NVDClientWrapper).
All actual HTTP logic lives in app.shared.clients.poc_client.
"""
from app.shared.clients.poc_client import PoCHTTPClient


class PoCClientWrapper:
    """Thin wrapper — keeps provider-local client boundary."""

    def __init__(self) -> None:
        self._client = PoCHTTPClient()

    async def fetch_raw(self, cve_id: str):
        return await self._client.fetch_raw(cve_id)
