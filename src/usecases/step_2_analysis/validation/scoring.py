"""Scoring Engine — Tính scores và verdict cho Validate Stage (Task 4).

Cung cấp các hàm tính toán độc lập (pure functions, dễ test):
    - compute_technique_match_rate: recall-based technique comparison
    - compute_behavior_match_rate:  recall-based behavior comparison
    - assess_false_positive_risk:   đánh giá FP risk từ whitelist hits
    - compute_verdict:              tính verdict tổng hợp + overall score

Triết lý scoring:
    - Dùng recall-based (|intersection| / |expected|) thay vì precision,
      vì mục tiêu là kiểm tra AI có MỚ SÓT kỹ thuật quan trọng không.
    - Extra techniques AI thêm không bị phạt trực tiếp (có thể đúng
      nhưng chưa có trong ground truth), chỉ cần track để audit.
    - FP risk từ whitelist là signal quan trọng: nếu luật Sigma trigger
      vào svchost.exe hay bash → đó là luật kém chất lượng.
"""
from __future__ import annotations

import logging
from typing import Literal

logger = logging.getLogger(__name__)

VerdictType = Literal["PASS", "PARTIAL", "FAIL", "UNKNOWN"]
FPRiskType = Literal["LOW", "MEDIUM", "HIGH"]

# Thresholds
_PASS_THRESHOLD = 0.70    # >= 70% technique match → PASS candidate
_PARTIAL_THRESHOLD = 0.40  # >= 40% → PARTIAL
# FP risk thresholds
_FP_HIGH_THRESHOLD = 0.50    # >= 50% behaviors là whitelist → HIGH
_FP_MEDIUM_THRESHOLD = 0.20  # >= 20% → MEDIUM
# Weighted average weights
_TECHNIQUE_WEIGHT = 0.60
_BEHAVIOR_WEIGHT = 0.40


def compute_technique_match_rate(
    ai_techniques: list[str],
    expected_techniques: list[str],
    ground_truth_quality: str,
) -> float | None:
    """Tính tỷ lệ technique AI khớp expected (recall-based).

    Formula: |intersection(ai_techniques, expected_techniques)| / |expected_techniques|

    Args:
        ai_techniques:        Techniques AI sinh ra (đã qua validate_ttp_list).
        expected_techniques:  Ground truth techniques (CTID/CAPEC/Whitelist).
        ground_truth_quality: "HIGH" | "PARTIAL" | "UNKNOWN".

    Returns:
        float trong [0.0, 1.0] nếu có thể tính.
        None nếu ground_truth_quality == "UNKNOWN" hoặc expected rỗng.
    """
    # Nếu không có Ground Truth hợp lệ (UNKNOWN), ta không có đáp án để chấm điểm
    if ground_truth_quality == "UNKNOWN":
        logger.debug("[scoring] technique_match_rate=None (ground_truth_quality=UNKNOWN)")
        return None
        
    # Nếu Ground Truth có nhưng lại rỗng (không có technique nào ghi nhận), cũng không chấm được
    if not expected_techniques:
        logger.debug("[scoring] technique_match_rate=None (expected_techniques empty)")
        return None

    # Biến danh sách kỹ thuật của AI thành Set (tập hợp không trùng), viết hoa (upper) và xóa khoảng trắng
    ai_set = {t.upper().strip() for t in ai_techniques if t}
    # Làm tương tự cho danh sách Ground Truth
    expected_set = {t.upper().strip() for t in expected_techniques if t}

    if not expected_set:
        return None

    # Toán tử `&` lấy phần giao của 2 tập hợp (các kỹ thuật AI đoán đúng)
    intersection = ai_set & expected_set
    
    # Tính tỷ lệ: Kỹ thuật đoán đúng / Tổng số kỹ thuật cần có (Recall)
    rate = len(intersection) / len(expected_set)
    logger.debug(
        "[scoring] technique_match_rate=%.2f (matched=%d/%d)",
        rate, len(intersection), len(expected_set),
    )
    # Trả về kết quả làm tròn 4 chữ số thập phân
    return round(rate, 4)


def compute_behavior_match_rate(
    ai_behaviors: list[str],
    expected_behaviors: list[str],
) -> float | None:
    """Tính tỷ lệ behavior AI khớp expected behaviors từ CAPEC (recall-based).

    Formula: |intersection(ai_behaviors, expected_behaviors)| / |expected_behaviors|

    Args:
        ai_behaviors:       Behaviors AI sinh ra (mandatory_behaviors).
        expected_behaviors: Expected behaviors từ CWE_BEHAVIOR_MAP (CAPEC layer).

    Returns:
        float trong [0.0, 1.0] nếu có thể tính.
        None nếu expected_behaviors rỗng (không có ground truth behaviors).
    """
    # Nếu danh sách behaviors tiêu chuẩn rỗng -> không thể chấm điểm
    if not expected_behaviors:
        logger.debug("[scoring] behavior_match_rate=None (expected_behaviors empty)")
        return None

    # Biến hành vi AI thành tập hợp, viết HOA (upper) và bỏ khoảng trắng để chuẩn hóa
    # Nhất quán với compute_set_diff() cũng dùng .upper() — tránh mismatch kết quả
    ai_set = {b.strip().upper() for b in ai_behaviors if b}
    expected_set = {b.strip().upper() for b in expected_behaviors if b}

    if not expected_set:
        return None

    # Lấy phần giao (những hành vi AI đoán trúng so với tiêu chuẩn)
    intersection = ai_set & expected_set
    
    # Tính tỷ lệ Recall = (Số lượng giao) / (Tổng số tiêu chuẩn)
    rate = len(intersection) / len(expected_set)
    logger.debug(
        "[scoring] behavior_match_rate=%.2f (matched=%d/%d)",
        rate, len(intersection), len(expected_set),
    )
    # Làm tròn 4 số thập phân
    return round(rate, 4)


def assess_false_positive_risk(
    whitelist_hits: list[str],
    total_behaviors: int,
) -> FPRiskType:
    """Đánh giá rủi ro False Positive dựa trên tỷ lệ whitelist hits.

    Logic:
        ratio = len(whitelist_hits) / max(total_behaviors, 1)
        ratio >= 0.5 → HIGH   (>50% behaviors là hệ thống → luật rất dễ FP)
        ratio >= 0.2 → MEDIUM (20-50% → cần review)
        else        → LOW

    Args:
        whitelist_hits:  Behaviors nằm trong OS whitelist (từ whitelist_manager).
        total_behaviors: Tổng số behaviors AI sinh ra.

    Returns:
        "LOW" | "MEDIUM" | "HIGH"
    """
    # Nếu AI không sinh ra behavior nào thì rủi ro đương nhiên là LOW
    if total_behaviors <= 0:
        return "LOW"

    # Tính tỷ lệ số hành vi vi phạm whitelist / tổng số hành vi
    ratio = len(whitelist_hits) / total_behaviors
    
    # Dựa vào các mốc đã định nghĩa ở đầu file để gán mức rủi ro
    if ratio >= _FP_HIGH_THRESHOLD:
        risk: FPRiskType = "HIGH"
    elif ratio >= _FP_MEDIUM_THRESHOLD:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    logger.debug(
        "[scoring] fp_risk=%s (whitelist_hits=%d total_behaviors=%d ratio=%.2f)",
        risk, len(whitelist_hits), total_behaviors, ratio,
    )
    return risk


def compute_verdict(
    technique_match_rate: float | None,
    behavior_match_rate: float | None,
    fp_risk: FPRiskType,
    ground_truth_quality: str,
) -> tuple[float | None, VerdictType, str]:
    """Tính verdict tổng hợp và overall_confidence_score.

    Priority rules:
        1. UNKNOWN: ground_truth_quality == "UNKNOWN" → không có gì để so
        2. PASS:    technique_match_rate >= 0.7 AND fp_risk in (LOW, MEDIUM)
        3. PARTIAL: technique_match_rate >= 0.4 (dù FP risk thế nào)
        4. FAIL:    technique_match_rate < 0.4 HOẶC fp_risk == HIGH + rate < 0.7

    overall_score:
        technique_match_rate * 0.6 + behavior_match_rate * 0.4
        None nếu cả 2 đều None.

    Args:
        technique_match_rate: Từ compute_technique_match_rate().
        behavior_match_rate:  Từ compute_behavior_match_rate().
        fp_risk:              Từ assess_false_positive_risk().
        ground_truth_quality: "HIGH" | "PARTIAL" | "UNKNOWN".

    Returns:
        Tuple (overall_score, verdict, reason):
            - overall_score: float | None
            - verdict:       "PASS" | "PARTIAL" | "FAIL" | "UNKNOWN"
            - reason:        mô tả ngắn lý do verdict
    """
    # 1. Trường hợp chất lượng tiêu chuẩn là UNKNOWN -> Không có dữ liệu để so sánh
    if ground_truth_quality == "UNKNOWN":
        return None, "UNKNOWN", (
            "No ground truth data available for this CVE "
            "(not in CTID and no CWE→CAPEC mapping found)."
        )

    # Tính điểm tổng hợp (overall score)
    t = technique_match_rate
    b = behavior_match_rate
    
    # Nếu có cả điểm kỹ thuật và hành vi thì tính trung bình có trọng số (60% tech - 40% behavior)
    if t is not None and b is not None:
        overall = round(t * _TECHNIQUE_WEIGHT + b * _BEHAVIOR_WEIGHT, 4)
    # Nếu chỉ có điểm kỹ thuật thì lấy điểm đó
    elif t is not None:
        overall = round(t, 4)
    # Nếu chỉ có điểm hành vi thì lấy điểm đó
    elif b is not None:
        overall = round(b, 4)
    else:
        overall = None

    # Nếu không có điểm nào (overall = None), trả về UNKNOWN
    if overall is None:
        return None, "UNKNOWN", (
            "Ground truth data is present but contains no techniques or behaviors to match against."
        )

    # Sử dụng overall score thay vì chỉ technique_match_rate
    eff_rate = overall

    # 2. Xử lý PASS: Điểm tổng hợp cao (>=70%) và Rủi ro FP không phải mức HIGH
    if eff_rate >= _PASS_THRESHOLD and fp_risk in ("LOW", "MEDIUM"):
        reason = (
            f"AI matching score is {eff_rate:.0%} of expected ground truth "
            f"with {fp_risk} false positive risk."
        )
        return overall, "PASS", reason

    # 3. Xử lý FAIL trực tiếp: Nếu rủi ro FP là HIGH (kể cả có đoán đúng nhiều kỹ thuật đi chăng nữa) 
    # luật này sẽ quét nhầm vào process hệ thống, vô giá trị trong thực tế
    if fp_risk == "HIGH":
        reason = (
            f"High false positive risk: AI behaviors heavily overlap with "
            f"OS-level whitelisted processes. Sigma rule likely too broad "
            f"(score={eff_rate:.0%})."
        )
        return overall, "FAIL", reason

    # 4. Xử lý PARTIAL: Điểm tổng hợp ở ngưỡng chấp nhận được (>= 40% nhưng chưa được 70%)
    if eff_rate >= _PARTIAL_THRESHOLD:
        reason = (
            f"Partial match: AI score is {eff_rate:.0%} "
            f"(threshold for PASS is {_PASS_THRESHOLD:.0%}). "
            f"FP risk: {fp_risk}."
        )
        return overall, "PARTIAL", reason

    # 5. Mặc định là FAIL: Điểm tổng hợp dưới chuẩn (< 40%)
    reason = (
        f"Low match score ({eff_rate:.0%} < {_PARTIAL_THRESHOLD:.0%}). "
        f"AI may have missed critical attack patterns for this CVE."
    )
    return overall, "FAIL", reason


def compute_set_diff(
    ai_items: list[str],
    expected_items: list[str],
) -> tuple[list[str], list[str], list[str]]:
    """Tính intersection, missing, extra giữa AI và expected (case-insensitive).

    Args:
        ai_items:       Items AI sinh ra (techniques hoặc behaviors).
        expected_items: Items expected từ ground truth.

    Returns:
        (matched, missing, extra):
            matched: intersection(ai, expected)
            missing: expected - ai  (AI bỏ sót)
            extra:   ai - expected  (AI thêm ngoài GT)
    """
    # Chuẩn hóa 2 danh sách thành tập hợp viết hoa để tìm kiếm không bị lọt do sai khác case
    ai_norm = {i.strip().upper() for i in ai_items if i}
    expected_norm = {i.strip().upper() for i in expected_items if i}

    # Toán tử `&`: Tìm phần tử chung (Các item AI đoán trúng so với tiêu chuẩn)
    matched = sorted(ai_norm & expected_norm)
    # Toán tử `-`: Lấy phần của A không nằm trong B (Các item tiêu chuẩn có mà AI lại không có -> Bỏ sót)
    missing = sorted(expected_norm - ai_norm)
    # Toán tử `-` ngược lại: (Các item AI tự vẽ ra thêm mà trong tiêu chuẩn không ghi nhận)
    extra = sorted(ai_norm - expected_norm)

    return matched, missing, extra
