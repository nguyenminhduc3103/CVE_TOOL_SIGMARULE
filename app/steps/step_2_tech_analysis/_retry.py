"""Retry payload builder cho Step 2 orchestrator.

Tách riêng để orchestrator.py gọn hơn - chỉ giữ retry loop body
(bước 5) ở orchestrator.
"""
from __future__ import annotations

import json
from typing import Any

# Ngưỡng retry (mirror từ orchestrator để dùng cho MAX_RETRIES trong prompt)
MAX_RETRIES = 3


def _build_retry_payload(
    description: str,
    cvss_vector: str,
    cwe_ids: list[str],
    previous_output: dict,
    gap_analysis: dict,
    retry_num: int,
    cve_id: str | None = None,
) -> str:
    """Build user prompt cho retry call (JSON + prepended feedback block).

    Feedback block (free-form text) được AI đọc tốt hơn JSON lồng JSON,
    vì nó là instruction trực tiếp cho behavior correction.
    """
    extra_techniques = gap_analysis.get("extra_techniques") or []
    missing_techniques = gap_analysis.get("missing_techniques") or []
    missing_behaviors = gap_analysis.get("missing_behaviors") or []
    missing_tactics = gap_analysis.get("missing_tactics") or []
    quality_gaps = gap_analysis.get("quality_gaps") or []

    feedback_parts: list[str] = []
    if extra_techniques:
        feedback_parts.append(
            f"⚠️ CORRECTION FROM PREVIOUS ATTEMPT (retry {retry_num}/{MAX_RETRIES}):\n"
            f"You previously included INCORRECT extra techniques not supported "
            f"by the CVE context: {extra_techniques}.\n"
            f"REMOVE these. In the new output, return ONLY techniques that are "
            f"explicitly justified by the CVE description, references, CWE, or CVSS vector.\n"
            f"For ATT&CK mappings (tactics, techniques, subtechniques) — your new "
            f"output REPLACES the previous attempt entirely. Do NOT preserve "
            f"hallucinated content."
        )
    if missing_techniques:
        feedback_parts.append(
            f"You are MISSING these required techniques: {missing_techniques}. "
            f"Add them with explicit justification."
        )
    if missing_tactics:
        feedback_parts.append(
            f"You are MISSING these required tactics: {missing_tactics}."
        )
    if missing_behaviors:
        feedback_parts.append(
            f"You are MISSING these required behaviors: {missing_behaviors}. "
            f"Add them."
        )
    # Quality gaps: tell LLM which specific fields were empty/lazy
    if quality_gaps:
        gap_instructions = {
            "evasive_indicators_empty": (
                "the 'evasive_indicators' field was empty or set to ['none']. "
                "You MUST analyze how an attacker would obfuscate this exploit "
                "(WAF bypass via string obfuscation like ${lower:l}, encoding, "
                "ROP chains, polymorphic payloads, etc.) and populate 1-3 concrete items."
            ),
            "reasoning_empty": (
                "the 'reasoning' field was empty. You MUST provide 2-4 brief "
                "bullet points walking through the exploit chain end-to-end, "
                "citing CVE description, CWE, and CVSS vector components."
            ),
            "mapping_reasons_insufficient": (
                "the 'mapping_reasons' field had fewer than 2 meaningful items. "
                "You MUST add more reasons tying each ATT&CK technique choice "
                "back to specific CVE context."
            ),
        }
        specific_fixes = [gap_instructions.get(g, g) for g in quality_gaps]
        feedback_parts.append(
            f"⚠️ QUALITY GAPS DETECTED (retry {retry_num}/{MAX_RETRIES}):\n"
            + "\n".join(f"  - {fix}" for fix in specific_fixes)
        )

    feedback_block = ""
    if feedback_parts:
        feedback_block = "\n\n".join(feedback_parts) + "\n\n---\n\n"

    # Inject MITRE hint (Cách 3 - RAG cheat sheet) ở đầu prompt để AI retry
    # có baseline techniques trùng với gap_analysis.expected_techniques.
    from app.steps.step_2_tech_analysis._mitre_hint import build_mitre_hint
    mitre_hint = build_mitre_hint(
        cve_id=cve_id,
        description=description,
        cwe_ids=cwe_ids,
        cvss_vector=cvss_vector,
    )
    if mitre_hint:
        feedback_block = f"{mitre_hint}\n\n{feedback_block}"

    payload = {
        "step1_context": {
            "description": description,
            "cvss_vector": cvss_vector,
            "cwe_ids": cwe_ids,
        },
        "previous_ai_output": previous_output,
        "system_gap_report": gap_analysis,
        "retry_count": retry_num,
        "max_retries": MAX_RETRIES,
    }
    json_payload = json.dumps(payload, indent=2, ensure_ascii=False)
    return feedback_block + json_payload
