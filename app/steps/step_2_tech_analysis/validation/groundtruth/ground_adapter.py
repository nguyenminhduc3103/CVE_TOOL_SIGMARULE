"""CAPEC Mapper — Adapter lấy expected profile từ 4-layer resolver.

Gọi OntologyManager.resolve() một lần duy nhất để lấy kết quả tốt nhất
từ chain: CTID (Layer 1) → CAPEC (Layer 2) → Whitelist CWE (Layer 3) →
UNKNOWN (Layer 4).

Kết quả được đóng gói thành CapecProfile để validate_stage dùng làm
ground truth so sánh với AI output.

Usage:
    from app.shared.groundtruth.capec_mapper import get_capec_profile
    profile = get_capec_profile("CVE-2021-44228", ["CWE-502"], "CVSS:3.1/AV:N/...")
    # profile.techniques -> {"T1190", "T1059", ...}
    # profile.expected_behaviors -> {"network_connection", "process_creation", ...}
    # profile.source -> "CTID" | "CAPEC" | ...
    # profile.quality -> "HIGH" | "PARTIAL" | "UNKNOWN"
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from app.steps.step_2_tech_analysis.rule_based.ontology_manager import (
    CveContext,
    OntologyManager,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class GroundTruthProfile:
    """Kết quả resolve từ OntologyManager — ground truth cho 1 CVE.

    Attributes:
        techniques: ATT&CK technique IDs expected (từ layer tốt nhất available).
        expected_behaviors: behavior strings expected từ CWE_BEHAVIOR_MAP.
        source: Nguồn ground truth (CTID/CAPEC/MIXED/WHITELIST/UNKNOWN).
        quality: Độ tin cậy của ground truth (HIGH/PARTIAL/UNKNOWN).
    """

    techniques: list[str] = field(default_factory=list)
    expected_behaviors: list[str] = field(default_factory=list)
    source: str = "UNKNOWN"
    quality: str = "UNKNOWN"

    def is_unknown(self) -> bool:
        """True nếu không có ground truth data để so sánh."""
        # Kiểm tra tính hợp lệ của Profile, nếu chất lượng là UNKNOWN tức là hệ thống không tìm ra đáp án tham chiếu
        return self.quality == "UNKNOWN"


def get_groundtruth_profile(
    cve_id: str,
    cwe_ids: list[str],
    cvss_vector: str | None = None,
) -> GroundTruthProfile:
    """Lấy expected profile cho CVE từ 4-layer resolver.

    Ưu tiên CTID (HIGH quality) → CAPEC bridge → Whitelist CWE → UNKNOWN.
    Gọi OntologyManager.resolve() một lần duy nhất — singleton không load
    lại data sau lần đầu.

    Args:
        cve_id: CVE identifier (vd "CVE-2021-44228").
        cwe_ids: List CWE IDs từ NVD (vd ["CWE-502", "CWE-400"]).
        cvss_vector: CVSS vector string (optional, dùng cho context filtering).

    Returns:
        GroundTruthProfile với techniques + expected_behaviors + metadata.
        Nếu không có data → profile với source="UNKNOWN", quality="UNKNOWN".
    """
    try:
        # Lấy instance của OntologyManager. Instance này đã tải bộ map CTID và CAPEC sẵn.
        mgr = OntologyManager()
        
        # Khởi tạo đối tượng Context mang theo thông tin đầy đủ về lỗ hổng: CVE, danh sách các CWE (nguyên nhân cốt lõi) và chuỗi CVSS (mức độ nghiêm trọng, vector)
        ctx = CveContext(
            cve_id=cve_id,
            cwe_ids=tuple(cwe_ids) if cwe_ids else (),
            cvss_vector=cvss_vector,
        )
        
        # Hàm resolve() là bộ não cốt lõi chạy qua 4 lớp từ uy tín nhất (CTID) xuống thấp dần để tìm ra kịch bản hành vi và kỹ thuật
        expected = mgr.resolve(ctx)

        # Sau khi OntologyManager trả về kết quả, gói kết quả đó vào class định dạng chuẩn GroundTruthProfile
        profile = GroundTruthProfile(
            techniques=list(expected.expected_techniques), # Chuyển set technique tìm được thành list
            expected_behaviors=list(expected.expected_behaviors), # Chuyển set các hành vi hệ thống thành list
            source=expected.ground_truth_source, # Ghi nhận nguồn gốc tìm ra (CTID hay CAPEC hay gì khác)
            quality=expected.ground_truth_quality, # Ghi nhận mức độ tin cậy (HIGH, PARTIAL)
        )

        # Log thông tin chi tiết về profile đã phân giải ra để debug và theo dõi pipeline
        logger.debug(
            "[ground_adapter] %s resolved: source=%s quality=%s "
            "techniques=%d behaviors=%d",
            cve_id,
            profile.source,
            profile.quality,
            len(profile.techniques),
            len(profile.expected_behaviors),
        )
        
        # Trả về Profile tham chiếu để chuẩn bị đem đi so sánh với AI Output
        return profile

    except Exception as exc:
        # Nếu quá trình phân giải bị lỗi (ví dụ format lỗi, code lỗi), log lại và fallback an toàn về một Profile rỗng
        logger.warning(
            "[ground_adapter] Error resolving profile for %s: %s",
            cve_id, exc,
        )
        # GroundTruthProfile rỗng sẽ mặc định mang chất lượng UNKNOWN, giúp Validation không bị dừng giữa chừng
        return GroundTruthProfile()
