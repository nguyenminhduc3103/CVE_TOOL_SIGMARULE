"""Gap Analysis cho Step 2 - tính coverage AI vs Ground Truth.

PHASE 2/3 REFACTOR (2026-06):
- 3 chiều đánh giá:
    1. CWE coverage: AI cwe_ids vs NVD cwe_ids
    2. Behavior coverage: AI mandatory_behaviors vs expected behaviors
    3. TTP coverage: AI techniques vs expected techniques từ OntologyManager
- Source of truth DUY NHẤT: OntologyManager.resolve() (4-layer fallback)
  - Trước: 2 hàm compute_ground_truth() + map_attack() dùng 2 bảng khác nhau
    → AI so sánh với ground truth không nhất quán
  - Sau: Cả 2 dùng cùng OntologyManager singleton → cùng expected_techniques
- None semantics: nếu không có ground truth → coverage = None
  - Trước: expected_behaviors rỗng → divide 0 → fallback 1.0 (100% giả tạo)
  - Sau: trả None → downstream biết "không đánh giá được"
- Semantic penalty: chỉ phạt extras mâu thuẫn context (qua is_contradiction())
  - Trước: mọi extra đều bị -5% (Strict Penalty paradox)
  - Sau: extras hợp lý với CVE context → KHÔNG phạt, extras sai context → -10%
"""
from __future__ import annotations

import logging
from typing import Any

from app.steps.step_2_tech_analysis._shared_engines.ontology_manager import (
    CveContext,
    ExpectedTTPs,
    OntologyManager,
)

logger = logging.getLogger(__name__)

# Penalty weight cho extras mâu thuẫn context CVE (qua is_contradiction)
CONTRADICTION_PENALTY = 0.10  # 10% mỗi contradiction
# Threshold verdict (giữ backward-compat với orchestrator cũ)
VERDICT_PASS = 0.7
VERDICT_PARTIAL = 0.4


# ==============================================================
# Ground Truth - 4-Layer Resolver (SINGLE SOURCE OF TRUTH)
# ==============================================================

def compute_ground_truth(
    cve_id: str | None,
    description: str | None,
    cwe_ids: list[str] | None,
    cvss_vector: str | None,
) -> dict[str, Any]:
    """Tính ground truth expected cho 1 CVE thông qua OntologyManager.

    SINGLE SOURCE OF TRUTH: cùng instance OntologyManager được dùng bởi
    map_attack() → AI output và ground truth dùng chính xác cùng expected_techniques.

    Returns dict với format:
        {
            "expected_cwes": set[str],
            "expected_behaviors": set[str],
            "expected_techniques": set[str],
            "expected_tactics": set[str],
            "ground_truth_source": "CTID" | "CAPEC" | "WHITELIST" | "MIXED" | "UNKNOWN",
            "ground_truth_quality": "HIGH" | "PARTIAL" | "UNKNOWN",
        }

    Backward compat: dict này có cùng 4 expected_* keys như version cũ + 2
    metadata keys mới. Code cũ chỉ đọc 4 expected_* keys vẫn work.
    """
    ctx = CveContext(
        cve_id=cve_id or "",
        description=description or "",
        cwe_ids=tuple(cwe_ids or ()),
        cvss_vector=cvss_vector,
    )
    mgr = OntologyManager()
    expected: ExpectedTTPs = mgr.resolve(ctx)

    # Log quality warning nếu UNKNOWN - downstream sẽ skip retry
    if expected.is_unknown():
        logger.warning(
            "[Step 2 - Ground Truth] %s: NO ground truth available (CWE=%s, CVSS=%s). "
            "Coverage will be None - verdict will be UNKNOWN.",
            cve_id, cwe_ids, cvss_vector,
        )

    return expected.to_dict()


# ==============================================================
# Coverage Calculation - 3 chiều, None-aware
# ==============================================================

def _safe_ratio(numerator: int, denominator: int) -> float | None:
    """Tính ratio an toàn: trả None nếu denominator = 0 (không phải 1.0 fake).

    Đây là fix cốt lõi cho "100% Coverage Hallucination":
    - Trước: behavior_coverage = 1.0 khi expected_behaviors rỗng → AI được
      100% score ảo khi ground truth không có data
    - Sau: trả None → downstream biết "không evaluate được" → verdict UNKNOWN
    """
    if denominator == 0:
        return None
    return numerator / denominator


# ==============================================================
# MITRE ATT&CK Parent-Child Resolution
# ==============================================================

def _parent_of(technique: str) -> str | None:
    """Trả về parent technique của 1 sub-technique (vd 'T1059.004' → 'T1059').

    Args:
        technique: ATT&CK ID dạng 'T1059' (parent) hoặc 'T1059.004' (child).

    Returns:
        Parent ID nếu là sub-technique, None nếu đã là parent.
    """
    if not technique or not technique.startswith("T"):
        return None
    if "." in technique:
        return technique.split(".", 1)[0]
    return None


def _expand_with_parents(techniques: set[str]) -> set[str]:
    """Mở rộng set techniques bằng cách thêm parent của mỗi sub-technique.

    Args:
        techniques: Set technique IDs (vd {'T1059.004', 'T1190'}).

    Returns:
        Set mới với parents added (vd {'T1059.004', 'T1059', 'T1190'}).

    Use case:
        - Khi AI trả sub-technique (T1059.004) → expand để match parent (T1059)
          trong expected set.
        - Khi expected có sub-technique → expand để match parent từ AI.
    """
    expanded: set[str] = set(techniques)
    for t in techniques:
        parent = _parent_of(t)
        if parent:
            expanded.add(parent)
    return expanded


def _match_techniques_parent_child(
    ai_techniques: set[str],
    expected_techniques: set[str],
) -> tuple[set[str], set[str], set[str], set[str]]:
    """Tính intersection/missing/extra với parent-child awareness.

    Quy tắc matching:
      - AI technique X khớp expected technique Y nếu:
        (a) X == Y, HOẶC
        (b) X là sub-technique và parent(X) trong expected, HOẶC
        (c) X là parent và expected chứa 1+ sub-technique của X
            (chấp nhận parent-level answer khi GT hyper-specific).

    Args:
        ai_techniques: Set technique IDs từ AI output (đã bao gồm subtechniques).
        expected_techniques: Set technique IDs từ ground truth.

    Returns:
        Tuple (covered_expected, missing_expected, extra_ai, matched_ai):
        - covered_expected: subset of expected được AI cover (dùng để tính coverage)
        - missing_expected: subset of expected KHÔNG được cover
        - extra_ai: subset of AI techniques KHÔNG match expected (gốc, không expand)
        - matched_ai: subset of AI techniques match expected (để log)
    """
    if not expected_techniques:
        # No expected → mọi AI technique đều là "extra"
        return set(), set(), set(ai_techniques), set()

    # Build map: parent → [children] từ expected
    expected_parents: dict[str, list[str]] = {}
    for et in expected_techniques:
        parent = _parent_of(et)
        if parent:
            expected_parents.setdefault(parent, []).append(et)

    covered_expected: set[str] = set()
    matched_ai: set[str] = set()

    for ai_t in ai_techniques:
        # Case (a): exact match
        if ai_t in expected_techniques:
            covered_expected.add(ai_t)
            matched_ai.add(ai_t)
            continue
        # Case (b): AI is sub-technique, parent in expected
        ai_parent = _parent_of(ai_t)
        if ai_parent and ai_parent in expected_techniques:
            covered_expected.add(ai_parent)
            matched_ai.add(ai_t)
            continue
        # Case (c): AI is parent, expected has child of AI
        if ai_t in expected_parents:
            for child in expected_parents[ai_t]:
                covered_expected.add(child)
            matched_ai.add(ai_t)
            continue

    # Extra = AI techniques that didn't match
    extra_ai = ai_techniques - matched_ai
    missing_expected = expected_techniques - covered_expected

    return covered_expected, missing_expected, extra_ai, matched_ai


def compute_coverage(
    ai_output: dict[str, Any],
    ground_truth: dict[str, Any],
) -> dict[str, Any]:
    """Tính coverage score cho AI output so với ground truth.

    Returns:
        {
            "cwe_coverage", "behavior_coverage", "ttp_coverage" (float | None),
            "overall_coverage" (float | None, average of non-None),
            "missing_cwes", "missing_behaviors", "missing_techniques" (list),
            "extra_techniques" (AI đưa thêm),
            "contradictory_techniques" (subset extras MÂU THUẪN context),
            "ground_truth_quality": "HIGH" | "PARTIAL" | "UNKNOWN",
            "ground_truth_source": "CTID" | "CAPEC" | "WHITELIST" | "MIXED" | "UNKNOWN",
            "needs_retry": bool,
            "verdict": "PASS" | "PARTIAL" | "FAIL" | "UNKNOWN",
            "notes": list[str],  # human-readable diagnostic
        }
    """
    notes: list[str] = []
    gt_quality = ground_truth.get("ground_truth_quality", "UNKNOWN")
    gt_source = ground_truth.get("ground_truth_source", "UNKNOWN")

    # ------------------------------------------------------------------
    # CWE coverage
    # ------------------------------------------------------------------
    nvd_cwes = set(ai_output.get("cwe_ids") or [])
    expected_cwes = ground_truth["expected_cwes"]
    missing_cwes = sorted(expected_cwes - nvd_cwes)
    cwe_coverage = _safe_ratio(len(nvd_cwes & expected_cwes), len(expected_cwes))
    if cwe_coverage is None:
        notes.append("no_ground_truth_available:expected_cwes_empty")

    # ------------------------------------------------------------------
    # Behavior coverage
    # ------------------------------------------------------------------
    tech = ai_output.get("technical_analysis") or {}
    ai_behaviors = set(tech.get("mandatory_behaviors") or [])
    expected_behaviors = ground_truth["expected_behaviors"]
    missing_behaviors = sorted(expected_behaviors - ai_behaviors)
    behavior_coverage = _safe_ratio(len(ai_behaviors & expected_behaviors), len(expected_behaviors))
    if behavior_coverage is None:
        notes.append("no_ground_truth_available:expected_behaviors_empty")

    # ------------------------------------------------------------------
    # TTP coverage (with parent-child matching)
    # ------------------------------------------------------------------
    atk = ai_output.get("attack_mapping") or {}
    # Phase 2: combine techniques + subtechniques thành 1 pool
    ai_techniques_raw = set(atk.get("techniques") or [])
    ai_subtechniques = set(atk.get("subtechniques") or [])
    # Strip parent prefix nếu AI lỡ liệt kê parent trong subtechniques
    # (vd {"subtechniques": ["T1059.004", "T1059"]}) - tránh duplicate
    ai_techniques_combined = (
        ai_techniques_raw
        | {s for s in ai_subtechniques if "." in s}  # subtechniques có dấu chấm
        | {s.split(".", 1)[0] for s in ai_subtechniques if "." in s}  # parents từ subtechniques
    )
    # Dedup expected_techniques (CAPEC + Whitelist có thể overlap)
    expected_techniques = set(ground_truth["expected_techniques"])

    # Phase 1: parent-child matching
    covered_expected, missing_set, extra_set, _matched_ai = _match_techniques_parent_child(
        ai_techniques_combined, expected_techniques
    )
    missing_techniques = sorted(missing_set)
    extra_techniques = sorted(extra_set)
    ttp_coverage = _safe_ratio(len(covered_expected), len(expected_techniques))
    if ttp_coverage is None:
        notes.append("no_ground_truth_available:expected_techniques_empty")

    # ------------------------------------------------------------------
    # Semantic penalty: chỉ phạt extras MÂU THUẪN context CVE
    # ------------------------------------------------------------------
    # Trước: extra_techniques tự động trừ 5%/cái → AI đúng hơn whitelist
    # vẫn bị phạt ("Strict Penalty paradox")
    # Sau: dùng OntologyManager.is_contradiction() → extras hợp lý với
    # CVE context KHÔNG bị phạt
    contradictory_techniques: list[str] = []
    if extra_techniques and ttp_coverage is not None:
        mgr = OntologyManager()
        ctx = CveContext(
            cve_id=ai_output.get("cve_id", ""),
            description=tech.get("execution_mechanism") or "",  # best-effort context
            cwe_ids=tuple(nvd_cwes),
            cvss_vector=None,  # CVSS không có trong ai_output - skip
        )
        for t in extra_techniques:
            if mgr.is_contradiction(t, ctx):
                contradictory_techniques.append(t)
        if contradictory_techniques:
            penalty = CONTRADICTION_PENALTY * len(contradictory_techniques)
            ttp_coverage = max(0.0, ttp_coverage - penalty)
            notes.append(
                f"semantic_penalty:{len(contradictory_techniques)}_contradictions"
                f"_applied_-{penalty:.0%}"
            )

    # ------------------------------------------------------------------
    # Overall coverage: trung bình các component NON-None
    # ------------------------------------------------------------------
    components: list[float] = []
    for c in (cwe_coverage, behavior_coverage, ttp_coverage):
        if c is not None:
            components.append(c)

    if components:
        overall = sum(components) / len(components)
    else:
        overall = None  # Tất cả đều None → không đánh giá được
        notes.append("overall_coverage_unavailable:all_components_none")

    # ------------------------------------------------------------------
    # Quality gaps: detect AI output quality issues (not about ground truth
    # matching, but about AI being lazy/incomplete in its analysis). These
    # trigger retry even if coverage is 100% so the LLM gets feedback to
    # improve specific fields.
    # ------------------------------------------------------------------
    quality_gaps: list[str] = []
    # Check 1: evasive_indicators empty/invalid (only if CVE has software path)
    if tech.get("attack_flow"):
        evasive_raw = tech.get("evasive_indicators") or []
        # Filter out ["none"] placeholder
        evasive_meaningful = [x for x in evasive_raw if str(x).lower().strip() != "none"]
        if not evasive_meaningful:
            quality_gaps.append("evasive_indicators_empty")
    # Check 2: reasoning empty
    reasoning_raw = tech.get("reasoning") or []
    reasoning_meaningful = [x for x in reasoning_raw if str(x).lower().strip() != "none"]
    if not reasoning_meaningful:
        quality_gaps.append("reasoning_empty")
    # Check 3: mapping_reasons < 2
    mapping_reasons_raw = atk.get("mapping_reasons") or []
    mapping_reasons_meaningful = [
        x for x in mapping_reasons_raw if str(x).lower().strip() != "none"
    ]
    if len(mapping_reasons_meaningful) < 2:
        quality_gaps.append("mapping_reasons_insufficient")
    if quality_gaps:
        notes.append(f"quality_gaps:{','.join(quality_gaps)}")

    # ------------------------------------------------------------------
    # needs_retry: retry khi có vấn đề về chất lượng HOẶC coverage
    # ------------------------------------------------------------------
    # Quality gaps (AI empty/lazy fields) LUÔN trigger retry - kể cả khi
    # ground truth UNKNOWN. Lý do: UNKNOWN ground truth ≠ "nothing to improve".
    # AI vẫn có thể produce empty/insufficient output cần được fix.
    # overall = None (tất cả components None) mới thật sự skip retry vì
    # không có gì để so sánh.
    if overall is None:
        needs_retry = False
    else:
        # Retry nếu:
        #  (a) overall < 1.0 (thiếu items), HOẶC
        #  (b) có extras mâu thuẫn context (AI bịa thứ vô lý với CVE), HOẶC
        #  (c) có quality_gaps (AI trả empty/lazy fields dù coverage tốt)
        #  (d) gt_quality == UNKNOWN + quality_gaps detected (Fix B)
        needs_retry = (
            overall < 1.0
            or bool(contradictory_techniques)
            or bool(quality_gaps)
        )

    # ------------------------------------------------------------------
    # Verdict
    # ------------------------------------------------------------------
    # Nếu ground truth quality = UNKNOWN → verdict = UNKNOWN bất chấp
    # cwe_coverage có thể computable (vì expected_cwes = set(cwe_ids) luôn
    # non-empty nếu cwe_ids được truyền vào). CWE matching không đủ để
    # kết luận PASS khi behavior/TTP ground truth không tồn tại.
    if gt_quality == "UNKNOWN":
        verdict = "UNKNOWN"
    elif overall is None:
        verdict = "UNKNOWN"
    elif overall >= VERDICT_PASS:
        verdict = "PASS"
    elif overall >= VERDICT_PARTIAL:
        verdict = "PARTIAL"
    else:
        verdict = "FAIL"

    return {
        "cwe_coverage": round(cwe_coverage, 3) if cwe_coverage is not None else None,
        "behavior_coverage": round(behavior_coverage, 3) if behavior_coverage is not None else None,
        "ttp_coverage": round(ttp_coverage, 3) if ttp_coverage is not None else None,
        "overall_coverage": round(overall, 3) if overall is not None else None,
        "missing_cwes": missing_cwes,
        "missing_behaviors": missing_behaviors,
        "missing_techniques": missing_techniques,
        "extra_techniques": extra_techniques,
        "contradictory_techniques": contradictory_techniques,
        "ground_truth_quality": gt_quality,
        "ground_truth_source": gt_source,
        "quality_gaps": quality_gaps,
        "needs_retry": needs_retry,
        "verdict": verdict,
        "notes": notes,
    }


def build_gap_report(
    ai_output: dict[str, Any],
    ground_truth: dict[str, set[str]],
    coverage: dict[str, Any],
) -> dict[str, Any]:
    """Build gap report từ AI output + ground truth + coverage.

    Returns:
        {
            "status": "PASSED_MITRE_WHITELIST" | "PARTIAL_COVERAGE_NEEDS_RETRY"
                     | "FAILED_STRICT_TAXONOMY" | "NO_GROUND_TRUTH_AVAILABLE",
            "current_coverage_score": float (0-100 percentage) | None,
            "gap_analysis": {
                "missing_behaviors": [...],
                "missing_techniques": [...],
                "missing_tactics": [...],
                "contradictory_techniques": [...],
            },
            "diagnostic_reason": str,
            "ground_truth_quality": str,
        }
    """
    tech = ai_output.get("technical_analysis") or {}
    atk = ai_output.get("attack_mapping") or {}

    ai_behaviors = set(tech.get("mandatory_behaviors") or [])
    ai_techniques = set(atk.get("techniques") or [])
    ai_tactics = set(atk.get("tactics") or [])

    missing_behaviors = sorted(ground_truth["expected_behaviors"] - ai_behaviors)
    missing_techniques = sorted(ground_truth["expected_techniques"] - ai_techniques)
    missing_tactics = sorted(ground_truth["expected_tactics"] - ai_tactics)
    contradictory = coverage.get("contradictory_techniques", [])
    quality_gaps = coverage.get("quality_gaps", [])

    score = coverage["overall_coverage"]  # Có thể là None
    gt_quality = coverage.get("ground_truth_quality", "UNKNOWN")

    # Ground truth UNKNOWN → status NO_GROUND_TRUTH_AVAILABLE bất chấp score
    if gt_quality == "UNKNOWN" or score is None:
        status = "NO_GROUND_TRUTH_AVAILABLE"
    elif quality_gaps:
        # Quality gaps detected → still need retry even if score is high
        status = "PARTIAL_COVERAGE_NEEDS_RETRY"
    elif score >= 1.0:
        status = "PASSED_MITRE_WHITELIST"
    elif score >= 0.4:
        status = "PARTIAL_COVERAGE_NEEDS_RETRY"
    else:
        status = "FAILED_STRICT_TAXONOMY"

    if missing_behaviors and missing_techniques:
        diagnostic = (
            f"AI output missing {len(missing_behaviors)} behaviors "
            f"and {len(missing_techniques)} techniques inherent to the exploit chain."
        )
    elif missing_behaviors:
        diagnostic = f"AI output missing {len(missing_behaviors)} behaviors."
    elif missing_techniques:
        diagnostic = f"AI output missing {len(missing_techniques)} techniques."
    elif contradictory:
        diagnostic = (
            f"AI output includes {len(contradictory)} techniques that "
            f"contradict the CVE context."
        )
    elif quality_gaps:
        diagnostic = (
            f"AI output has quality gaps: {quality_gaps}. "
            "These fields are empty or insufficient and must be populated."
        )
    else:
        diagnostic = "Coverage sufficient."

    return {
        "status": status,
        "current_coverage_score": round(score * 100, 1) if score is not None else None,
        "gap_analysis": {
            "missing_behaviors": missing_behaviors,
            "missing_techniques": missing_techniques,
            "missing_tactics": missing_tactics,
            "contradictory_techniques": contradictory,
            "quality_gaps": quality_gaps,
        },
        "diagnostic_reason": diagnostic,
        "ground_truth_quality": coverage.get("ground_truth_quality", "UNKNOWN"),
    }
