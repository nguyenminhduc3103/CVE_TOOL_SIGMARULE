from __future__ import annotations

from typing import Any

from app.shared.clients.opencti_client import OpenCTIHTTPClient
from app.core.config import settings


class OpenCTIClientWrapper:

    def __init__(self) -> None:
        """Khởi tạo cấu hình và tham số kết nối OpenCTI Client từ settings."""
        self._client = OpenCTIHTTPClient(
            base_url=settings.opencti_url,
            cookie=settings.opencti_cookie,
            token=settings.opencti_token,
            username=settings.opencti_username,
            password=settings.opencti_password,
        )

    async def fetch_raw_collection(self, limit: int = 5) -> dict[str, Any]:
        """Tải gói dữ liệu STIX thô (raw STIX bundle) từ TAXII collection được cấu hình.

        Args:
            limit: Số lượng bản ghi tối đa cần lấy.

        Returns:
            Dict chứa gói dữ liệu STIX thô lấy về từ TAXII endpoint.
        """
        collection_id = settings.opencti_taxii_collection_id
        if not collection_id:
            raise ValueError(
                "OPENCTI_TAXII_COLLECTION_ID chưa được cấu hình. "
                "Vui lòng thiết lập biến này trong tệp tin .env."
            )
        return await self._client.fetch_collection_objects(
            collection_id=collection_id,
            limit=limit,
        )
