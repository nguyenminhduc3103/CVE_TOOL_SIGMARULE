"""Telemetry Repo Parser — giải mã và chuẩn hóa các bản ghi log từ kho Telemetry Chuyên Biệt."""
from __future__ import annotations

import json
from typing import Any

from src.shared.parsers.evtx_parser import EVTXMemoryParser
from config.logging import get_logger

logger = get_logger(__name__)


class TelemetryRepoParser:
    """Parser chuẩn hóa các file log (.evtx, .json) thành danh sách dict."""

    def __init__(self) -> None:
        self.evtx_parser = EVTXMemoryParser()

    def parse_file_content(self, file_path: str, content_bytes: bytes) -> list[dict[str, Any]]:
        """Parse nội dung file theo định dạng .evtx hoặc .json."""
        if not content_bytes:
            return []

        path_lower = file_path.lower()
        if path_lower.endswith(".evtx"):
            return self.evtx_parser.parse_evtx_bytes(content_bytes)

        if path_lower.endswith(".json"):
            try:
                text = content_bytes.decode("utf-8", errors="ignore")
                data = json.loads(text)
                if isinstance(data, list):
                    return data[:20]
                if isinstance(data, dict):
                    return [data]
            except Exception as exc:
                logger.warning("[Telemetry Repo Parser] JSON parse error", path=file_path, error=str(exc))

        return []
