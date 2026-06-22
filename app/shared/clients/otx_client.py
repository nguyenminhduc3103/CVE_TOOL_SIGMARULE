from __future__ import annotations

import httpx
from typing import Any

from app.shared.clients.base import BaseHTTPClient
from app.core.logging import get_logger


class OTXFetchError(Exception):
    """Raised when OTX fetch fails (network, parse, or non-2xx response).

    Caller (OTXProvider) sẽ bubble up để orchestrator mark provider="failed"
    thay vì tự ý return dict rỗng (khiến provider_status bị sai).
    """


class OTXHTTPClient(BaseHTTPClient):
    """Client HTTP kết nối với API AlienVault OTX để lấy thông tin Threat Intelligence."""

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        timeout: float = 20.0,
    ) -> None:
        """Khởi tạo OTX HTTP Client với URL cấu hình và API Key (nếu có)."""
        super().__init__(base_url=base_url, timeout=int(timeout))
        self.api_key = api_key
        self.logger = get_logger(__name__)
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        """Khởi tạo và trả về đối tượng httpx.AsyncClient cấu hình sẵn."""
        if not self._client:
            headers = {
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            }
            if self.api_key:
                headers["X-OTX-API-KEY"] = self.api_key
                self.logger.info("[OTX] Đã thiết lập API Key để kết nối AlienVault OTX.")
            else:
                self.logger.info("[OTX] Đang kết nối AlienVault OTX dưới dạng ẩn danh (không sử dụng API Key).")

            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout,
                headers=headers,
                verify=False,
            )
        return self._client

    async def get(self, endpoint: str, **kwargs) -> httpx.Response:
        """Ghi đè phương thức get để đảm bảo AsyncClient được cấu hình đúng cách."""
        client = self._get_client()
        return await client.get(endpoint, **kwargs)

    async def fetch_raw(self, cve_id: str) -> dict[str, Any]:
        """Tải dữ liệu Threat Intel thô của một CVE từ AlienVault OTX API.

        Raise OTXFetchError khi network/parse fail (để caller mark provider failed).
        Trả {} chỉ khi OTX trả 404 (CVE genuinely không có trên OTX, không phải lỗi).
        """
        endpoint = f"/api/v1/indicators/cve/{cve_id}/general"
        try:
            self.logger.info("[OTX] Đang tải thông tin CVE từ AlienVault OTX", cve_id=cve_id, endpoint=endpoint)
            response = await self.get(endpoint)
            if response.status_code == 403:
                self.logger.error("[OTX] Yêu cầu bị chặn (403 Forbidden). Vui lòng cấu hình API Key OTX hợp lệ.")
            elif response.status_code == 404:
                # 404 = CVE không có trên OTX → trả empty dict hợp lệ (không phải lỗi)
                self.logger.warning("[OTX] Không tìm thấy thông tin cho CVE trên hệ thống OTX.", cve_id=cve_id)
                return {}
            response.raise_for_status()
            return response.json()
        except Exception as exc:
            self.logger.warning("[OTX] Lỗi khi kết nối hoặc parse dữ liệu từ AlienVault OTX", cve_id=cve_id, error=str(exc))
            # Fix: raise thay vì return {} để caller biết OTX thực sự fail
            raise OTXFetchError(f"OTX fetch failed for {cve_id}: {exc}") from exc
