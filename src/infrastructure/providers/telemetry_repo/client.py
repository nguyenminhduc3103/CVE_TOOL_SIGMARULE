"""Telemetry Repo Provider Client Wrapper."""
from __future__ import annotations

from typing import Any
from src.infrastructure.clients.telemetry_repo_client import TelemetryRepoHTTPClient


class TelemetryRepoClientWrapper:
    """Wrapper cho TelemetryRepoHTTPClient."""

    def __init__(self) -> None:
        self.client = TelemetryRepoHTTPClient()

    async def fetch_matching_logs(
        self,
        keywords: list[str],
        technique_ids: list[str],
        max_files: int = 5
    ) -> list[dict[str, Any]]:
        return await self.client.fetch_matching_telemetry_files(keywords, technique_ids, max_files)
