from __future__ import annotations

from app.core.logging import get_logger
from app.shared.models.core import CoreCVEData
from app.shared.providers.base import BaseProvider
from app.shared.providers.nvd.client import NVDClientWrapper
from app.shared.providers.nvd.parser import NVDParser


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
            # Some exceptions (e.g. httpx.ReadTimeout) have an empty str(),
            # so splitlines()[0] would IndexError. Fall back to the type name.
            message = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
            self.logger.warning("[NVD] Enrichment failed", cve_id=cve_id, error=message)
            raise

    async def fetch(self, cve_id: str):
        # Backwards-compatible provider API for the current orchestration stub.
        parsed = await self.enrich(cve_id)
        return parsed.model_dump(mode="json", exclude_none=True)
