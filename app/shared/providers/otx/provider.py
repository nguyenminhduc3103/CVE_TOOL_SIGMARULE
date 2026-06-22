from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.shared.providers.base import BaseProvider
from app.shared.providers.otx.client import OTXClientWrapper
from app.shared.providers.otx.parser import OTXParser
from app.shared.clients.otx_client import OTXFetchError


class OTXProvider(BaseProvider):
    """Provider thực hiện lấy thông tin đe dọa từ AlienVault OTX."""

    name: str = "otx"

    def __init__(self) -> None:
        """Khởi tạo OTXProvider với client wrapper và parser tương ứng."""
        self.client = OTXClientWrapper()
        self.parser = OTXParser()
        self.logger = get_logger(__name__)
        self.last_error_message: str | None = None

    async def enrich(self, cve_id: str) -> dict[str, Any]:
        """Thu thập và phân tích thông tin về nhóm tấn công liên quan tới CVE từ OTX.

        Args:
            cve_id: Mã định danh CVE.

        Returns:
            Dict chứa trường 'threat_actors' (list) và 'raw' (dữ liệu thô từ OTX).

        Raises:
            OTXFetchError: khi OTX API/parse fail (bubble up để orchestrator mark failed).
        """
        self.logger.info("[OTX] Đang thu thập thông tin tình báo đe dọa", cve_id=cve_id)
        self.last_error_message = None
        try:
            raw = await self.client.fetch_raw(cve_id)
        except OTXFetchError as exc:
            self.last_error_message = str(exc)
            self.logger.warning("[OTX] Thất bại khi thu thập dữ liệu", cve_id=cve_id, error=str(exc))
            raise  # Bubble up - orchestrator sẽ mark provider_status="failed"

        if not raw:
            # 404 path: OTX trả empty dict, không có threat intel nhưng cũng không phải lỗi
            self.logger.info("[OTX] Không có threat intel cho CVE này", cve_id=cve_id)
            return {"threat_actors": [], "raw": None}

        actors = self.parser.extract_threat_actors(raw)
        self.logger.info("[OTX] Thu thập thành công thông tin đe dọa", cve_id=cve_id, actors_count=len(actors))
        return {"threat_actors": actors, "raw": raw}

    async def fetch(self, cve_id: str) -> Any:
        """Thu thập và trả về dữ liệu của một CVE cụ thể."""
        return await self.enrich(cve_id)
