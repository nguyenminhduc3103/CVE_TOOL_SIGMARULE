"""Validate Stage — Lớp 3 External Ground Truth Validation (Task 4).

Entry point: run_validate_stage()

Đây là lớp validation thứ 3 trong Step 2, chạy SAU khi AI đã sinh ra
TechnicalAnalysis + AttackMapping và 2 lớp nội bộ đã pass:
    - Lớp 1: format + whitelist TTP (_validation.py)
    - Lớp 2: semantic context CVE (_validation.py)
    - Lớp 3: ★ này — so sánh với ground truth ngoại vi (CTID/CAPEC)

Flow:
    1. Guard: nếu cả tech + attack đều None → UNKNOWN verdict
    2. get_groundtruth_profile() → GroundTruthProfile (CTID > CAPEC > Whitelist)
    3. Set ops: matched/missing/extra techniques, matched behaviors
    4. scan_behaviors_for_fp() → whitelist_hits
    5. compute_technique_match_rate / compute_behavior_match_rate
    6. assess_false_positive_risk → FP risk
    7. compute_verdict → (overall_score, verdict, reason)
    8. Return ValidationResult

Được gọi từ TriageOrchestrator._run_analysis_stage() sau khi
run_step2_tech_analysis() hoàn thành.
"""
from __future__ import annotations

import logging

from app.steps.step_2_tech_analysis.validation.groundtruth.ground_adapter import get_groundtruth_profile
from app.shared.models.attack import AttackMapping, TechnicalAnalysis
from app.steps.step_2_tech_analysis.validation.validation_models import ValidationResult
from app.steps.step_2_tech_analysis.validation.scoring import (
    assess_false_positive_risk,
    compute_behavior_match_rate,
    compute_set_diff,
    compute_technique_match_rate,
    compute_verdict,
)
from app.steps.step_2_tech_analysis.validation.whitelist_manager import (
    scan_behaviors_for_fp,
)

logger = logging.getLogger(__name__)


async def run_validate_stage(
    tech_analysis: TechnicalAnalysis | None,
    attack_mapping: AttackMapping | None,
    cve_id: str,
    cwe_ids: list[str],
    cvss_vector: str | None = None,
    description: str | None = None,
) -> ValidationResult:
    """Main entry point — Lớp 3 External Ground Truth Validation.

    Khai báo async để khớp với _run_analysis_stage() async context, nhưng
    toàn bộ logic là synchronous (OntologyManager đã load data vào RAM).

    Args:
        tech_analysis: TechnicalAnalysis từ Step 2 (có thể None nếu AI fail).
        attack_mapping: AttackMapping từ Step 2 (có thể None).
        cve_id:         CVE identifier (vd "CVE-2021-44228").
        cwe_ids:        List CWE IDs từ NVD (vd ["CWE-502"]).
        cvss_vector:    CVSS vector string (optional, dùng cho context).
        description:    CVE description (reserved, chưa dùng trong MVP).

    Returns:
        ValidationResult với đầy đủ scores, verdict, và metadata.
        Không bao giờ raise exception — graceful fallback về UNKNOWN.
    """
    logger.info(
        "[validate_stage] Starting validation for %s "
        "(ai_ok=%s, attack_ok=%s)",
        cve_id,
        tech_analysis is not None,
        attack_mapping is not None,
    )

    # ----------------------------------------------------------------
    # Guard: cả hai đều None → không có gì để validate
    # ----------------------------------------------------------------
    # Lớp phòng vệ đầu tiên: Nếu AI sinh lỗi hoặc không trả về JSON hợp lệ khiến cả 2 biến đều rỗng
    # Trả về luôn kết quả là UNKNOWN vì không có nguyên liệu để làm gì tiếp theo
    if tech_analysis is None and attack_mapping is None:
        logger.warning(
            "[validate_stage] %s: both tech_analysis and attack_mapping are None "
            "— returning UNKNOWN verdict",
            cve_id,
        )
        return ValidationResult(
            verdict="UNKNOWN",
            verdict_reason="Both TechnicalAnalysis and AttackMapping are None. "
                           "Step 2 may have failed completely.",
            ground_truth_source="UNKNOWN",
            ground_truth_quality="UNKNOWN",
        )

    # ----------------------------------------------------------------
    # Bước 1: Lấy ground truth profile từ 4-layer resolver
    # ----------------------------------------------------------------
    try:
        # Gọi Adapter ground_adapter để lấy bộ "đáp án đúng" dựa trên CVE ID và CWE
        profile = get_groundtruth_profile(
            cve_id=cve_id,
            cwe_ids=cwe_ids or [],
            cvss_vector=cvss_vector,
        )
    except Exception as exc:
        # Nếu bộ phân giải lỗi, rơi vào trạng thái an toàn (UNKNOWN) thay vì crash
        logger.warning(
            "[validate_stage] %s: get_groundtruth_profile failed: %s — UNKNOWN",
            cve_id, exc,
        )
        return ValidationResult(
            verdict="UNKNOWN",
            verdict_reason=f"Ground truth resolution failed: {exc}",
            ground_truth_source="UNKNOWN",
            ground_truth_quality="UNKNOWN",
        )

    # ----------------------------------------------------------------
    # Bước 2: Thu thập AI output
    # ----------------------------------------------------------------
    ai_techniques: list[str] = []
    ai_behaviors: list[str] = []

    # Trích xuất danh sách kỹ thuật từ AI, loại bỏ các giá trị vô nghĩa như "none", "unknown", "n/a"
    if attack_mapping is not None:
        ai_techniques = [
            t for t in (attack_mapping.techniques or [])
            if t and t.lower() not in ("none", "unknown", "n/a")
        ]
    # Trích xuất danh sách hành vi hệ thống từ AI, tương tự loại bỏ giá trị vô nghĩa
    if tech_analysis is not None:
        ai_behaviors = [
            b for b in (tech_analysis.mandatory_behaviors or [])
            if b and b.lower() not in ("none", "unknown", "n/a")
        ]

    # ----------------------------------------------------------------
    # Bước 3: Set operations — technique comparison
    # ----------------------------------------------------------------
    # Đưa danh sách kỹ thuật của AI và của "Đáp án" vào hàm so sánh
    # matched_techs: các kỹ thuật AI đoán trúng
    # missing_techs: các kỹ thuật AI bỏ quên
    # extra_techs: các kỹ thuật AI tưởng tượng/suy luận thêm
    matched_techs, missing_techs, extra_techs = compute_set_diff(
        ai_items=ai_techniques,
        expected_items=profile.techniques,
    )

    # ----------------------------------------------------------------
    # Bước 4: Behavior comparison
    # ----------------------------------------------------------------
    # Tương tự như trên nhưng áp dụng cho hành vi hệ thống (tiến trình, dòng lệnh...)
    matched_behaviors, _, _ = compute_set_diff(
        ai_items=ai_behaviors,
        expected_items=profile.expected_behaviors,
    )

    # ----------------------------------------------------------------
    # Bước 5: FP scan — whitelist filter
    # ----------------------------------------------------------------
    # Đưa các hành vi của AI qua phễu lọc OS Whitelist. Nếu dính (ví dụ svchost.exe), sẽ trả về list danh sách vi phạm.
    whitelist_hits = scan_behaviors_for_fp(ai_behaviors, platform="any")

    # ----------------------------------------------------------------
    # Bước 6: Scoring
    # ----------------------------------------------------------------
    # Chấm điểm độ phủ Kỹ thuật
    technique_match_rate = compute_technique_match_rate(
        ai_techniques=ai_techniques,
        expected_techniques=profile.techniques,
        ground_truth_quality=profile.quality,
    )
    # Chấm điểm độ phủ Hành vi
    behavior_match_rate = compute_behavior_match_rate(
        ai_behaviors=ai_behaviors,
        expected_behaviors=profile.expected_behaviors,
    )
    # Đánh giá mức độ rủi ro False Positive (cảnh báo giả)
    fp_risk = assess_false_positive_risk(
        whitelist_hits=whitelist_hits,
        total_behaviors=len(ai_behaviors),
    )
    # Tính điểm tổng kết (overall) và ra Phán Quyết Cuối Cùng (verdict)
    overall_score, verdict, reason = compute_verdict(
        technique_match_rate=technique_match_rate,
        behavior_match_rate=behavior_match_rate,
        fp_risk=fp_risk,
        ground_truth_quality=profile.quality,
    )

    # ----------------------------------------------------------------
    # Bước 7: Build ValidationResult
    # ----------------------------------------------------------------
    # Tổng hợp toàn bộ dữ liệu (điểm, verdict, chi tiết khớp/lệch) vào đối tượng ValidationResult
    result = ValidationResult(
        technique_match_rate=technique_match_rate,
        behavior_match_rate=behavior_match_rate,
        overall_confidence_score=overall_score,
        verdict=verdict,
        verdict_reason=reason,
        matched_techniques=matched_techs,
        missing_techniques=missing_techs,
        extra_techniques=extra_techs,
        matched_behaviors=matched_behaviors,
        whitelist_hits=whitelist_hits,
        false_positive_risk=fp_risk,
        ground_truth_source=profile.source,
        ground_truth_quality=profile.quality,
    )

    # In log báo cáo chốt hạ tiến trình Validation
    logger.info(
        "[validate_stage] %s done: verdict=%s score=%s "
        "technique_match=%.0f%% fp_risk=%s gt_source=%s",
        cve_id,
        verdict,
        f"{overall_score:.2f}" if overall_score is not None else "N/A",
        (technique_match_rate * 100) if technique_match_rate is not None else 0,
        fp_risk,
        profile.source,
    )

    return result
