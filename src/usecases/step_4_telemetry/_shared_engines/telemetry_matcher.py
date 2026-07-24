"""Telemetry Hybrid Matcher Engine — ghép nối Telemetry theo 3 cấp ưu tiên (Technique + Keyword).

3 Cấp Ưu Tiên:
- Ưu tiên 1 (Technique + Keyword): Khớp đồng thời ATT&CK Technique ID và Keyword tiến trình/payload.
- Ưu tiên 2 (Keyword Only): Khớp theo Keyword tiến trình/payload đặc thù của CVE.
- Ưu tiên 3 (Technique Broad Fallback): Khớp theo ATT&CK Technique ID dự phòng.
"""
from __future__ import annotations

from typing import Any
from src.domain.models.telemetry import TelemetryItem
from config.logging import get_logger

logger = get_logger(__name__)


class TelemetryHybridMatcher:
    """Engine thực hiện thuật toán Hybrid Matching cho Telemetry."""

    def match_logs(
        self,
        candidate_items: list[TelemetryItem],
        keywords: list[str],
        technique_ids: list[str]
    ) -> list[TelemetryItem]:
        """
        Lọc và xếp ưu tiên các bản ghi Telemetry dựa trên Keywords và Technique IDs.

        Returns:
            Danh sách TelemetryItem đã sắp xếp theo thứ tự ưu tiên 1 -> 2 -> 3.
        """
        if not candidate_items:
            return []

        p1_items: list[TelemetryItem] = []  # Technique + Keyword
        p2_items: list[TelemetryItem] = []  # Keyword Only
        p3_items: list[TelemetryItem] = []  # Technique Fallback

        kw_set = {k.lower() for k in keywords if k}
        tech_set = {t.upper() for t in technique_ids if t}

        for item in candidate_items:
            log_str = str(item.log_data).lower()
            snippet_str = (item.raw_snippet or "").lower()
            full_text = f"{log_str} {snippet_str}"

            has_kw = any(k in full_text for k in kw_set)
            has_tech = any(t.lower() in full_text for t in tech_set)

            if has_kw and has_tech:
                item.score = max(item.score, 9.0)
                p1_items.append(item)
            elif has_kw:
                item.score = max(item.score, 7.0)
                p2_items.append(item)
            elif has_tech:
                item.score = max(item.score, 5.0)
                p3_items.append(item)
            else:
                # Keep original item if already high score
                if item.score >= 7.0:
                    p2_items.append(item)

        # Merge results keeping priority order
        final_matched = p1_items + p2_items + p3_items
        logger.info(
            "[Telemetry Matcher] Hybrid Matching complete",
            p1_count=len(p1_items),
            p2_count=len(p2_items),
            p3_count=len(p3_items),
            total=len(final_matched)
        )
        return final_matched
