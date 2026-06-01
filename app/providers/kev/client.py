from __future__ import annotations

from app.clients.kev_client import KEVHTTPClient


class KEVClientWrapper:
    def __init__(self) -> None:
        self._client = KEVHTTPClient()

    async def fetch_raw(self, cve_id: str):
        # Provider-local shim kept for a consistent provider layout.
        return await self._client.fetch_raw(cve_id)

    @property
    def last_error_message(self) -> str | None:
        return self._client.last_error_message

    @property
    def last_failure_kind(self) -> str | None:
        return self._client.last_failure_kind
