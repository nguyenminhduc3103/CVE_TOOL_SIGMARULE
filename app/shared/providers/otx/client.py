from __future__ import annotations

from typing import Any

from app.shared.clients.otx_client import OTXHTTPClient
from app.core.config import settings


class OTXClientWrapper:
    """Wrapper bao quanh OTXHTTPClient để nạp tự động cấu hình kết nối từ settings."""

    def __init__(self) -> None:
        """Khởi tạo client OTX với API URL và API Key từ cấu hình hệ thống."""
        self._client = OTXHTTPClient(
            base_url=settings.otx_api_url,
            api_key=settings.otx_api_key,
        )

    async def fetch_raw(self, cve_id: str) -> dict[str, Any]:
        """Tải dữ liệu Threat Intel thô của CVE từ OTX Client."""
        return await self._client.fetch_raw(cve_id)
