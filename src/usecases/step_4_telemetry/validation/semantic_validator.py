"""Bộ Thẩm Định Tương Thích Ngữ Nghĩa (Semantic Coherence Validator) Cho Step 4 Telemetry.

Kiểm tra và thẩm định xem danh sách Candidate Features và Sigma Logsources trong TelemetryPlan
có bao phủ đầy đủ 145 Hành vi Kỹ thuật Bắt buộc (mandatory_behaviors) đã trích xuất ở Step 2 hay không.
"""
from __future__ import annotations

import functools
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.domain.models.attack import TechnicalAnalysis
    from src.usecases.step_4_telemetry.models.telemetry_plan import TelemetryPlan

logger = logging.getLogger(__name__)

# Đường dẫn tới file ma trận ánh xạ ngữ nghĩa 145 primitives
_MATRIX_FILE = (
    Path(__file__).resolve().parent.parent / "_knowledge" / "semantic_behavior_matrix.json"
)


@functools.lru_cache(maxsize=1)
def load_semantic_matrix() -> dict[str, Any]:
    """Nạp file ma trận JSON ánh xạ ngữ nghĩa (Sử dụng LRU Cache nạp 1 lần duy nhất vào RAM)."""
    if not _MATRIX_FILE.exists():
        logger.warning(
            "[semantic_validator] Không tìm thấy file ma trận tại %s; vô hiệu hóa thẩm định ngữ nghĩa",
            _MATRIX_FILE,
        )
        return {}
    try:
        return json.loads(_MATRIX_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        logger.error("[semantic_validator] Đọc file ma trận JSON thất bại: %s", e)
        return {}


class SemanticCoherenceValidator:
    """Lớp kiểm định độ tương thích ngữ nghĩa giữa Hành vi ở Step 2 và Logsources ở Step 4."""

    @classmethod
    def validate(
        cls,
        plan: TelemetryPlan,
        analysis: TechnicalAnalysis | None,
    ) -> TelemetryPlan:
        """Thực hiện hậu kiểm thẩm định TelemetryPlan dựa trên TechnicalAnalysis từ Step 2."""
        if not analysis:
            return plan

        matrix = load_semantic_matrix()
        if not matrix:
            return plan

        behavior_map: dict[str, list[str]] = matrix.get("behavior_to_categories", {})

        # Bước 1: Trích xuất Hợp tập (Union) các Log Categories thực tế có trong Candidate Features VÀ Sigma Logsources
        actual_categories: set[str] = set()
        for tier in (plan.candidate_features.stable, plan.candidate_features.conditional):
            for feature in tier:
                if feature.telemetry_concept:
                    actual_categories.add(feature.telemetry_concept)

        for sig_ls in (plan.sigma_logsources or []):
            if sig_ls.category:
                actual_categories.add(sig_ls.category)

        gaps: list[str] = list(plan.telemetry_gaps or [])
        confidence_penalty = 0.0
        missing_core_behavior = False

        # Bước 2: Kiểm tra độ bao phủ cho từng Hành vi Bắt buộc (từ 145 primitives)
        mandatory_behaviors = analysis.mandatory_behaviors or []
        for behavior in mandatory_behaviors:
            expected_pool = behavior_map.get(behavior, [])
            # Thực hiện phép giao tập hợp: Nếu không trùng category nào ➔ Phát hiện khoảng trống (Gap Detected)
            if expected_pool and not (actual_categories & set(expected_pool)):
                gap_msg = (
                    f"Missing telemetry coverage for mandatory behavior '{behavior}'. "
                    f"Expected one of: {expected_pool}"
                )
                gaps.append(gap_msg)
                confidence_penalty += 0.20
                # Nếu bỏ sót các hành vi nguy hiểm cốt lõi ➔ Đánh dấu mức độ nghiêm trọng cao
                if behavior in ("code_execution", "server_side_request_forgery", "remote_file_inclusion", "command_execution"):
                    missing_core_behavior = True

        # Nếu không có hình phạt nào ➔ Trả về plan ban đầu (PASSED)
        if not confidence_penalty:
            return plan

        # Bước 3: Tính toán điểm tin cậy mới sau khi trừ điểm hình phạt
        new_confidence = max(0.0, round(plan.telemetry_confidence - confidence_penalty, 2))
        new_severity = "high" if missing_core_behavior else (plan.gap_severity or "medium")

        logger.info(
            "[semantic_validator] Đã áp dụng hình phạt=%.2f (cũ=%.2f -> mới=%.2f) số gap=%d",
            confidence_penalty,
            plan.telemetry_confidence,
            new_confidence,
            len(gaps),
        )

        # Bước 4: Cập nhật đối tượng TelemetryPlan mới qua model_copy
        return plan.model_copy(
            update={
                "telemetry_gaps": gaps,
                "gap_severity": new_severity,
                "telemetry_confidence": new_confidence,
            }
        )
