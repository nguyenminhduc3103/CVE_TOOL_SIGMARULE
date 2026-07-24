"""Telemetry Repo Provider — orchestrates client -> parser for dedicated telemetry repos."""
from __future__ import annotations

from typing import Any
from src.infrastructure.providers.base import BaseProvider
from src.infrastructure.providers.telemetry_repo.client import TelemetryRepoClientWrapper
from src.infrastructure.providers.telemetry_repo.parser import TelemetryRepoParser
from src.domain.models.telemetry import TelemetryItem
from config.logging import get_logger


class TelemetryRepoProvider(BaseProvider):
    """Provider kéo và chuẩn hóa Telemetry từ OTRF Mordor & EVTX-ATTACK-SAMPLES."""

    def __init__(self) -> None:
        self.client = TelemetryRepoClientWrapper()
        self.parser = TelemetryRepoParser()
        self.logger = get_logger(__name__)

    async def fetch_authentic_telemetry(
        self,
        keywords: list[str],
        technique_ids: list[str]
    ) -> list[TelemetryItem]:
        """Fetch authentic telemetry items matching keywords & technique_ids."""
        self.logger.info("[Telemetry Repo Provider] Fetching authentic telemetry", keywords=keywords, techniques=technique_ids)

        files = await self.client.fetch_matching_logs(keywords, technique_ids)
        items: list[TelemetryItem] = []

        for f in files:
            source = f.get("source", "TelemetryRepo")
            score = f.get("score", 10.0)
            file_path = f.get("file_path", "")
            raw_bytes = f.get("content_bytes", b"")

            parsed_events = self.parser.parse_file_content(file_path, raw_bytes)
            for evt in parsed_events:
                items.append(TelemetryItem(
                    source=source,
                    score=score,
                    label="Authentic",
                    confidence="HIGH",
                    event_id=evt.get("event_id"),
                    log_data=evt
                ))

        self.logger.info("[Telemetry Repo Provider] Extracted authentic items", count=len(items))
        return items

    async def fetch(self, cve_id: str) -> Any:
        return await self.fetch_authentic_telemetry([], [])

    async def enrich(self, cve_id: str) -> Any:
        return await self.fetch(cve_id)

