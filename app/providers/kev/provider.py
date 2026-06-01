from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.providers.base import BaseProvider
from app.providers.kev.client import KEVClientWrapper
from app.providers.kev.parser import KEVParser


class KEVProvider(BaseProvider):
    def __init__(self) -> None:
        self.client = KEVClientWrapper()
        self.parser = KEVParser()
        self.logger = get_logger(__name__)
        self.last_error_message: str | None = None

    async def enrich(self, cve_id: str) -> dict:
        self.logger.info("[KEV] Fetching CVE", cve_id=cve_id)
        self.last_error_message = None
        raw = await self.client.fetch_raw(cve_id)
        if raw is None:
            self.last_error_message = self.client.last_error_message or "KEV unavailable"
            self.logger.warning("[KEV] Failed", cve_id=cve_id, error=self.last_error_message)
            return None

        self.logger.info("[KEV] Response received", cve_id=cve_id)
        parsed = self.parser.normalize(raw, cve_id)
        self.logger.info("[KEV] Success", cve_id=cve_id)
        return parsed

    async def fetch(self, cve_id: str) -> Any:
        parsed = await self.enrich(cve_id)
        return parsed
