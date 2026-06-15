from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.models.core import CoreCVEData
from app.providers.base import BaseProvider
from app.providers.opencti.client import OpenCTIClientWrapper
from app.providers.opencti.parser import OpenCTIParser


class OpenCTIProvider(BaseProvider):
    """Provider phục vụ thu thập thông tin tình báo mối đe dọa (threat intelligence) từ OpenCTI qua giao thức TAXII.

    Quản lý kết nối, đóng gói phiên và phân tích cú pháp dữ liệu STIX thô
    thành các đối tượng mô hình CoreCVEData tiêu chuẩn của ứng dụng.
    """

    def __init__(self) -> None:
        """Khởi tạo OpenCTIProvider với client wrapper và parser tương ứng."""
        self.client = OpenCTIClientWrapper()
        self.parser = OpenCTIParser()
        self.logger = get_logger(__name__)

    async def fetch_recent_cves(self, limit: int = 5) -> list[CoreCVEData]:
        """Thu thập và phân tích các thông tin lỗ hổng (CVE) từ TAXII collection.

        Args:
            limit: Số lượng CVE tối đa muốn lấy về.

        Returns:
            Danh sách các đối tượng CoreCVEData được phân tích từ STIX bundle.
        """
        self.logger.info(
            "[OpenCTI] Đang lấy danh sách CVE mới nhất từ TAXII collection",
            limit=limit
        )
        try:
            raw_bundle = await self.client.fetch_raw_collection(limit=limit)
            parsed_cves = self.parser.parse_bundle(raw_bundle)

            # Giới hạn số lượng bản ghi trả về theo tham số limit
            results = parsed_cves[:limit]
            self.logger.info(
                "[OpenCTI] Đã thu thập thành công các CVE",
                count=len(results)
            )
            return results
        except Exception as exc:
            self.logger.error(
                "[OpenCTI] Thất bại khi thu thập các CVE từ TAXII collection",
                error=str(exc)
            )
            raise

    async def fetch(self, identifier: str) -> Any:
        """Thu thập và trả về dữ liệu đã được chuẩn hóa của một mã CVE ID cụ thể từ collection.
        """
        self.logger.info("[OpenCTI] Đang truy vấn collection để tìm mã CVE cụ thể", cve_id=identifier)
        try:
            # Lấy một lô bản ghi lớn từ collection để tìm kiếm định danh lỗ hổng
            raw_bundle = await self.client.fetch_raw_collection(limit=100)
            parsed_cves = self.parser.parse_bundle(raw_bundle)

            for cve in parsed_cves:
                if cve.cve_id.upper() == identifier.upper():
                    self.logger.info("[OpenCTI] Tìm thấy mã CVE khớp trong collection", cve_id=identifier)
                    return cve.model_dump(mode="json", exclude_none=True)

            self.logger.warning("[OpenCTI] Không tìm thấy CVE trong lô dữ liệu TAXII collection hiện tại", cve_id=identifier)
            return None
        except Exception as exc:
            self.logger.warning(
                "[OpenCTI] Gặp lỗi khi lấy dữ liệu cụ thể của mã CVE từ TAXII collection",
                cve_id=identifier,
                error=str(exc)
            )
            return None
