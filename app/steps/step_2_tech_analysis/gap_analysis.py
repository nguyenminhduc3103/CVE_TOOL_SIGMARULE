"""Gap Analysis cho Step 2 - tính coverage AI vs Ground Truth.

3 chiều đánh giá:
1. CWE coverage: AI cwe_ids vs NVD cwe_ids
2. Behavior coverage: AI mandatory_behaviors vs expected behaviors
3. TTP coverage: AI techniques vs expected techniques từ CWE + behaviors

Trả về coverage score + missing items list (để retry AI bổ sung).
"""
from __future__ import annotations

from typing import Any

from app.steps.step_2_tech_analysis._shared_engines.attack_mapper import (
    BEHAVIOR_ATTACK_GRAPH,
    VULNERABILITY_CLASS_ATTACK_GRAPH,
)
from app.steps.step_2_tech_analysis._shared_engines.cwe_mapper import map_cwe_profiles
from app.steps.step_2_tech_analysis._shared_engines.exploit_ontology import infer_exploit_ontology


def compute_ground_truth(
    cve_id: str | None,
    description: str | None,
    cwe_ids: list[str] | None,
    cvss_vector: str | None,
) -> dict[str, set[str]]:
    """Tính ground truth expected cho 1 CVE (rule-based, deterministic).

    Returns:
        {
            "expected_cwes": set[str],
            "expected_behaviors": set[str],
            "expected_techniques": set[str],
            "expected_tactics": set[str],
        }
    """
    # CWE từ NVD (Ground Truth)
    expected_cwes = set(cwe_ids or [])

    # Behaviors từ CWE mapper + ontology
    cwe_profiles = map_cwe_profiles(cwe_ids)
    ontology = infer_exploit_ontology(cwe_ids, description, cvss_vector, None)
    expected_behaviors: set[str] = set()
    for profile in cwe_profiles:
        expected_behaviors.update(profile.mandatory_behaviors)
    expected_behaviors.update(ontology.behaviors)

    # Techniques từ behaviors
    expected_techniques: set[str] = set()
    expected_tactics: set[str] = set()
    for behavior in expected_behaviors:
        if behavior in BEHAVIOR_ATTACK_GRAPH:
            expected_techniques.update(BEHAVIOR_ATTACK_GRAPH[behavior]["techniques"])
            expected_tactics.update(BEHAVIOR_ATTACK_GRAPH[behavior]["tactics"])

    # Fallback từ vulnerability class
    if cwe_ids:
        from app.steps.step_2_tech_analysis._shared_engines.behavior_analyzer import _derive_vulnerability_class
        try:
            vc = _derive_vulnerability_class(cve_id, description, cwe_profiles, ontology, None)
            if vc in VULNERABILITY_CLASS_ATTACK_GRAPH:
                expected_techniques.update(VULNERABILITY_CLASS_ATTACK_GRAPH[vc])
        except Exception:
            pass

    return {
        "expected_cwes": expected_cwes,
        "expected_behaviors": expected_behaviors,
        "expected_techniques": expected_techniques,
        "expected_tactics": expected_tactics,
    }


def compute_coverage(
    ai_output: dict[str, Any],
    ground_truth: dict[str, set[str]],
) -> dict[str, Any]:
    """Tính coverage score cho AI output so với ground truth.

    Returns:
        {
            "cwe_coverage", "behavior_coverage", "ttp_coverage" (0-1),
            "overall_coverage" (0-1, average),
            "missing_cwes", "missing_behaviors", "missing_techniques" (list),
            "extra_techniques" (AI bịa thêm),
            "verdict": "PASS" | "PARTIAL" | "FAIL",
        }
    """
    # CWE
    nvd_cwes = set(ai_output.get("cwe_ids") or [])
    expected_cwes = ground_truth["expected_cwes"]
    missing_cwes = sorted(expected_cwes - nvd_cwes)
    cwe_coverage = (
        len(nvd_cwes & expected_cwes) / len(expected_cwes) if expected_cwes else 1.0
    )

    # Behavior
    tech = ai_output.get("technical_analysis") or {}
    ai_behaviors = set(tech.get("mandatory_behaviors") or [])
    expected_behaviors = ground_truth["expected_behaviors"]
    missing_behaviors = sorted(expected_behaviors - ai_behaviors)
    behavior_coverage = (
        len(ai_behaviors & expected_behaviors) / len(expected_behaviors)
        if expected_behaviors
        else 1.0
    )

    # TTP
    atk = ai_output.get("attack_mapping") or {}
    ai_techniques = set(atk.get("techniques") or [])
    expected_techniques = ground_truth["expected_techniques"]
    missing_techniques = sorted(expected_techniques - ai_techniques)
    extra_techniques = sorted(ai_techniques - expected_techniques)
    ttp_coverage = (
        len(ai_techniques & expected_techniques) / len(expected_techniques)
        if expected_techniques
        else 1.0
    )

    # Penalty: extra techniques (AI bịa thêm) reduce coverage. Each extra
    # technique drops 5% so a result with 4 extras still scores ~80% instead
    # of 100% — caller can use `extra_techniques` to inspect what was fabricated.
    if extra_techniques:
        ttp_coverage = max(0.0, ttp_coverage - 0.05 * len(extra_techniques))

    # If a retry was requested but the AI still produced extras, we want the
    # orchestrator's retry loop to fire. Flag it so the caller can react.
    needs_retry = bool(extra_techniques)

    overall = (cwe_coverage + behavior_coverage + ttp_coverage) / 3

    return {
        "cwe_coverage": round(cwe_coverage, 3),
        "behavior_coverage": round(behavior_coverage, 3),
        "ttp_coverage": round(ttp_coverage, 3),
        "overall_coverage": round(overall, 3),
        "missing_cwes": missing_cwes,
        "missing_behaviors": missing_behaviors,
        "missing_techniques": missing_techniques,
        "extra_techniques": extra_techniques,
        "needs_retry": needs_retry,
        "verdict": (
            "PASS" if overall >= 0.7
            else "PARTIAL" if overall >= 0.4
            else "FAIL"
        ),
    }


def build_gap_report(
    ai_output: dict[str, Any],
    ground_truth: dict[str, set[str]],
    coverage: dict[str, Any],
) -> dict[str, Any]:
    """Build gap report từ AI output + ground truth + coverage.

    Returns:
        {
            "status": "FAILED_STRICT_TAXONOMY" | "PARTIAL_COVERAGE_NEEDS_RETRY" | "PASSED_MITRE_WHITELIST",
            "current_coverage_score": float (0-100 percentage),
            "gap_analysis": {
                "missing_behaviors": [...],
                "missing_techniques": [...],
                "missing_tactics": [...],
            },
            "diagnostic_reason": str,
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

    score = coverage["overall_coverage"]
    if score >= 1.0:
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
    else:
        diagnostic = "Coverage sufficient."

    return {
        "status": status,
        "current_coverage_score": round(score * 100, 1),
        "gap_analysis": {
            "missing_behaviors": missing_behaviors,
            "missing_techniques": missing_techniques,
            "missing_tactics": missing_tactics,
        },
        "diagnostic_reason": diagnostic,
    }
