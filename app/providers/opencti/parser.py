from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from app.core.logging import get_logger
from app.models.core import CoreCVEData

# Biểu thức chính quy (regex) để tìm mã CVE chuẩn (Ví dụ: CVE-2023-1234)
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class OpenCTIParser:
    """Bộ phân tích cú pháp để chuẩn hóa các đối tượng STIX 2.1 (được trả về bởi OpenCTI TAXII)

    thành mô hình CoreCVEData tiêu chuẩn của ứng dụng.
    """

    def __init__(self) -> None:
        """Khởi tạo logger cho OpenCTIParser."""
        self.logger = get_logger(__name__)

    def parse_bundle(self, bundle: dict[str, Any]) -> list[CoreCVEData]:
        """Phân tích một STIX 2.1 bundle và trích xuất tất cả các đối tượng lỗ hổng (vulnerability).

        Args:
            bundle: Dictionary JSON thô chứa gói dữ liệu STIX.

        Returns:
            Danh sách các đối tượng CoreCVEData đã được chuẩn hóa.
        """
        self.logger.info("[OpenCTI] Bắt đầu phân tích STIX bundle")
        if not isinstance(bundle, dict):
            self.logger.warning("[OpenCTI] Bundle không phải là một dictionary", type=type(bundle))
            return []

        objects = bundle.get("objects") or []
        if not isinstance(objects, list):
            self.logger.warning("[OpenCTI] Thuộc tính 'objects' trong bundle không phải là một danh sách")
            return []

        normalized_cves: list[CoreCVEData] = []
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            # Chỉ lấy các đối tượng thuộc loại 'vulnerability'
            if obj.get("type") == "vulnerability":
                try:
                    cve_data = self.normalize(obj)
                    normalized_cves.append(cve_data)
                except Exception as exc:
                    self.logger.error(
                        "[OpenCTI] Thất bại khi phân tích đối tượng vulnerability",
                        object_id=obj.get("id"),
                        error=str(exc)
                    )

        self.logger.info(
            "[OpenCTI] Quá trình phân tích hoàn tất",
            total_vulnerabilities=len(normalized_cves)
        )
        return normalized_cves

    def normalize(self, raw: dict[str, Any]) -> CoreCVEData:
        """Chuẩn hóa một đối tượng vulnerability STIX 2.1 đơn lẻ thành CoreCVEData."""
        cve_id = self._extract_cve_id(raw)
        
        # Trích xuất các trường mốc thời gian xuất bản và cập nhật
        published_at = self._parse_datetime(raw.get("created") or raw.get("published_at"))
        modified_at = self._parse_datetime(raw.get("modified") or raw.get("modified_at"))

        # Khởi tạo mô hình CoreCVEData 
        parsed = CoreCVEData(
            cve_id=cve_id,
            description=None,
            published_at=published_at,
            modified_at=modified_at,
        )

        self.logger.info(
            "[OpenCTI] Đã chuẩn hóa lỗ hổng",
            cve_id=parsed.cve_id
        )
        return parsed

    def _extract_cve_id(self, raw: dict[str, Any]) -> str:
        """Trích xuất mã CVE ID từ tên lỗ hổng hoặc các liên kết ngoài (external_references)."""
        name = raw.get("name") or ""
        if CVE_PATTERN.match(name):
            return name.strip().upper()

        # Thử tìm kiếm trong danh sách liên kết ngoài (external_references)
        for ref in raw.get("external_references") or []:
            if not isinstance(ref, dict):
                continue
            
            ext_id = str(ref.get("external_id") or "")
            if CVE_PATTERN.match(ext_id):
                return ext_id.strip().upper()

        # Trường hợp dự phòng: Tìm kiếm regex trong chuỗi tên
        match = CVE_PATTERN.search(name)
        if match:
            return match.group(0).upper()

        # Nếu không tìm thấy, trả về ID mặc định của đối tượng
        return str(raw.get("id") or "UNKNOWN-CVE")

    def _parse_datetime(self, value: Any) -> datetime | None:
        """Phân tích cú pháp chuỗi thời gian thành đối tượng datetime của Python."""
        if not value:
            return None
        if isinstance(value, datetime):
            return value
        text = str(value).replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            # Thử phân tích chuỗi thời gian bằng cách lấy 19 ký tự đầu (định dạng YYYY-MM-DDTHH:MM:SS)
            try:
                return datetime.strptime(text[:19], "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                return None
