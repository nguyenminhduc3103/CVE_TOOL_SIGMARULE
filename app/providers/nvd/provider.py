from __future__ import annotations

from app.core.logging import get_logger
from app.models.core import CoreCVEData
from app.providers.base import BaseProvider
from app.providers.nvd.client import NVDClientWrapper
from app.providers.nvd.parser import NVDParser


class NVDProvider(BaseProvider):
    def __init__(self) -> None:
        self.client = NVDClientWrapper()
        self.parser = NVDParser()
        self.logger = get_logger(__name__)

    async def enrich(self, cve_id: str) -> CoreCVEData:
        self.logger.info("[NVD] Fetching CVE", cve_id=cve_id)
        try:
            raw = await self.client.fetch_raw(cve_id)
            self.logger.info("[NVD] Response received", cve_id=cve_id)
            parsed = self.parser.normalize(raw)
            self.logger.info("[NVD] Success", cve_id=cve_id)
            return parsed
        except Exception as exc:
            self.logger.warning("[NVD] Enrichment failed", cve_id=cve_id, error=str(exc).splitlines()[0])
            raise

    async def fetch(self, cve_id: str):
        # Backwards-compatible provider API for the current orchestration stub.
        parsed = await self.enrich(cve_id)
        return parsed.model_dump(mode="json", exclude_none=True)
