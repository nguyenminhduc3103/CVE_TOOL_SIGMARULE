"""Telemetry Scoring & Labeling Engine — gán Trust Score và dán nhãn minh bạch cho Telemetry.

Bảng điểm Trust Score & Labels:
- 10.0: OTRF Mordor / EVTX-ATTACK-SAMPLES (Authentic)
- 7.0 : Real .evtx / .json file đính kèm PoC (Authentic)
- 5.0 : Code Block Log trích từ README/Writeup (Extracted)
- 3.0 : Synthetic Log suy luận từ script exploit (Synthetic)
"""
from __future__ import annotations

from src.domain.models.telemetry import TelemetryItem
from config.logging import get_logger

logger = get_logger(__name__)


class TelemetryScoringEngine:
    """Engine đánh giá điểm uy tín và dán nhãn cho Telemetry Items."""

    def evaluate_and_label(self, item: TelemetryItem) -> TelemetryItem:
        """Phân loại và gán nhãn cho 1 TelemetryItem."""
        source_lower = item.source.lower()

        # OTRF / Mordor / EVTX-ATTACK-SAMPLES
        if any(src in source_lower for src in ["otrf", "mordor", "evtx-attack-samples", "sbousseaden"]):
            item.score = 10.0
            item.label = "Authentic"
            item.confidence = "HIGH"

        # GitHub PoC attached EVTX/JSON file
        elif "evtx" in source_lower or "poc_file" in source_lower:
            item.score = 7.0
            item.label = "Authentic"
            item.confidence = "MEDIUM-HIGH"

        # Extracted Code Block Log from README / Writeup
        elif "readme" in source_lower or "writeup" in source_lower or "doc" in source_lower:
            item.score = 5.0
            item.label = "Extracted"
            item.confidence = "MEDIUM"

        # Synthetic Log simulated from exploit script
        elif "script" in source_lower or "synthetic" in source_lower or "exploit.py" in source_lower:
            item.score = 3.0
            item.label = "Synthetic"
            item.confidence = "LOW"

        return item

    def categorize_items(
        self, items: list[TelemetryItem]
    ) -> tuple[list[TelemetryItem], list[TelemetryItem]]:
        """
        Tách danh sách telemetry thành 2 danh sách riêng biệt:
        1. authentic_logs (Score >= 5.0: Authentic & Extracted)
        2. synthetic_logs (Score < 5.0: Synthetic)

        Returns:
            (authentic_logs, synthetic_logs)
        """
        authentic_logs: list[TelemetryItem] = []
        synthetic_logs: list[TelemetryItem] = []

        for item in items:
            labeled_item = self.evaluate_and_label(item)
            if labeled_item.label in ("Authentic", "Extracted") and labeled_item.score >= 5.0:
                authentic_logs.append(labeled_item)
            else:
                synthetic_logs.append(labeled_item)

        # Sort authentic logs descending by score
        authentic_logs.sort(key=lambda x: x.score, reverse=True)
        synthetic_logs.sort(key=lambda x: x.score, reverse=True)

        logger.info(
            "[Scoring Engine] Categorized items",
            authentic_count=len(authentic_logs),
            synthetic_count=len(synthetic_logs)
        )
        return authentic_logs, synthetic_logs
