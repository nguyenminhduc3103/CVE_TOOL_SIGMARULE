from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.providers.base import BaseProvider
from app.providers.epss.client import EPSSClientWrapper
from app.providers.epss.parser import EPSSParser


class EPSSProvider(BaseProvider):
    def __init__(self) -> None:
        self.client = EPSSClientWrapper()
        self.parser = EPSSParser()
        self.logger = get_logger(__name__)

    async def enrich(self, cve_id: str) -> dict:
        self.logger.info("[EPSS] Fetching CVE", cve_id=cve_id)
        try:
            raw = await self.client.fetch_raw(cve_id)
            self.logger.info("[EPSS] Response received", cve_id=cve_id)
            parsed = self.parser.normalize(raw)
            self.logger.info("[EPSS] Success", cve_id=cve_id)
            return parsed
        except Exception as exc:
            self.logger.warning("[EPSS] Enrichment failed", cve_id=cve_id, error=str(exc).splitlines()[0])
            raise

    async def fetch(self, cve_id: str) -> Any:
        parsed = await self.enrich(cve_id)
        return parsed
