from __future__ import annotations

from typing import Any

from src.domain.models.cve import CoreCVEData
from src.domain.models.triage import TriageContext


class DecisionEngine:
    """Engine đưa ra quyết định GO / NO-GO dựa trên 5 trường hợp cụ thể của ma trận ưu tiên."""

    def evaluate(
        self,
        core: CoreCVEData,
        triage: TriageContext,
        capability_classification: Any,
    ) -> None:
        """Đánh giá và gán quyết định GO/NO-GO vào TriageContext."""
        # 1. Capability check (Out of Scope check)
        if capability_classification.value != "in_scope":
            triage.decision = "NO-GO"
            triage.decision_reason = (
                f"Capability assessment={capability_classification.value} (out of scope); "
                f"reason={capability_classification.reasoning}."
            )
            return

        # 2. Thu thập các chỉ số
        has_kev = triage.in_kev is True
        has_poc = triage.public_poc is True
        
        is_cvss_ok = (core.cvss_score or 0.0) >= 8.0
        is_epss_ok = (triage.epss_score or 0.0) >= 0.3
        satisfies_cvss_epss = is_cvss_ok or is_epss_ok

        # 3. Phân loại theo 5 Trường hợp cụ thể trong ma trận ưu tiên
        # Trường hợp 1
        if has_kev and has_poc and satisfies_cvss_epss:
            triage.decision = "GO"
            triage.decision_reason = (
                "Có CISA KEV, Public PoC và thỏa mãn CVSS >= 8.0 hoặc EPSS >= 0.3 (Độ ưu tiên: Khẩn cấp)."
            )
            return

        # Trường hợp 2
        if not has_kev and has_poc and satisfies_cvss_epss:
            triage.decision = "GO"
            triage.decision_reason = (
                "Không có CISA KEV, có Public PoC và thỏa mãn CVSS >= 8.0 hoặc EPSS >= 0.3 (Độ ưu tiên: Cao)."
            )
            return

        # Trường hợp 3
        if has_kev and not has_poc and satisfies_cvss_epss:
            triage.decision = "NO-GO"
            triage.decision_reason = (
                "Có CISA KEV, không có Public PoC và thỏa mãn CVSS >= 8.0 hoặc EPSS >= 0.3 (Độ ưu tiên: Trung bình)."
            )
            return

        # Trường hợp 4
        if has_kev and has_poc and not satisfies_cvss_epss:
            triage.decision = "GO"
            triage.decision_reason = (
                "Có CISA KEV, có Public PoC và không thỏa mãn CVSS >= 8.0 hoặc EPSS >= 0.3 (Độ ưu tiên: Trung bình)."
            )
            return

        # Trường hợp 5
        triage.decision = "NO-GO"
        triage.decision_reason = (
            "Các điều kiện còn lại không thỏa mãn (Quyết định: NO-GO, Độ ưu tiên: Thấp)."
        )
