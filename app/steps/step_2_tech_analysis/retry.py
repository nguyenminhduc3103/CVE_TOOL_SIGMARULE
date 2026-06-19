"""Retry payload builder cho Step 2 orchestrator (partial-fill mode).

Tách riêng để orchestrator.py gọn hơn. Chỉ build user prompt cho 1 retry call.

PARTIAL-FILL MODE (fix wipeout bug CVE-2023-22515):
- Lấy JSON attempt 1 làm base.
- Liệt kê field invalid + reason per-field.
- Yêu cầu AI CHỈ điền vào field invalid, KHÔNG động vào field valid.
- KHÔNG merge old+new (cách cũ gây wipeout khi retry trả output gần rỗng).
"""
from __future__ import annotations

import json
from typing import Any

# Single source of truth cho retry budget.
from app.steps.step_2_tech_analysis.constants import MAX_RETRIES


# Mapping từ field path trong invalid_fields → label AI dễ đọc.
_FIELD_LABELS: dict[str, str] = {
    "attack_mapping.techniques": "ATT&CK techniques (T-codes)",
    "attack_mapping.tactics": "ATT&CK tactics (TA-codes)",
    "attack_mapping.subtechniques": "ATT&CK subtechniques (T-code.dotted)",
    "attack_mapping.mapping_reasons": "ATT&CK mapping reasons",
    "technical_analysis.mandatory_behaviors": "mandatory behaviors (exploit steps)",
    "technical_analysis.evasive_indicators": "evasive indicators (obfuscation/evasion)",
    "technical_analysis.entry_vector": "entry vector (how attacker reaches vulnerable code)",
    "technical_analysis.execution_mechanism": "execution mechanism (what code runs)",
    "technical_analysis.attack_flow.observable_side_effects": "observable side effects",
    "technical_analysis.reasoning": "exploit chain reasoning",
}


def _format_invalid_fields(invalid_fields: dict[str, str]) -> str:
    """Format dict {field_path: reason} thành block text cho AI.

    Mỗi field được giải thích rõ ràng + label dễ hiểu.
    """
    lines: list[str] = []
    for field_path, reason in invalid_fields.items():
        label = _FIELD_LABELS.get(field_path, field_path)
        lines.append(f"  - {field_path} ({label}): {reason}")
    return "\n".join(lines) if lines else "  (none)"


def _build_retry_payload(
    description: str,
    cvss_vector: str,
    cwe_ids: list[str],
    attempt_1_output: dict[str, Any],
    invalid_fields: dict[str, str],
    retry_num: int,
    cve_id: str | None = None,
) -> str:
    """Build user prompt cho retry call (partial-fill).

    Cấu trúc prompt:
      === INSTRUCTIONS === (per-field correction, KHÔNG động field valid)
      === CONTEXT === (CVE description, CVSS, CWE)
      === PREVIOUS ATTEMPT === (JSON attempt 1, nguyên vẹn)

    Args:
        description: CVE description (context).
        cvss_vector: CVSS vector string.
        cwe_ids: List CWE IDs của CVE.
        attempt_1_output: Dict từ AI attempt 1 (giữ nguyên các field valid).
        invalid_fields: Dict {field_path: reason} của các field cần điền lại.
        retry_num: 1..MAX_RETRIES.
        cve_id: CVE ID (optional, chỉ để log/debug).

    Returns:
        String prompt đầy đủ (instructions + context + JSON).
    """
    invalid_block = _format_invalid_fields(invalid_fields)

    instructions = (
        f"⚠️ PARTIAL-FILL RETRY (attempt {retry_num}/{MAX_RETRIES})\n\n"
        f"The previous attempt had INVALID or MISSING values for these "
        f"Specific fields:\n"
        f"{invalid_block}\n\n"
        f"INSTRUCTIONS:\n"
        f"1. Fix ONLY the fields listed above. Return them with correct values "
        f"supported by the CVE description, CVSS vector, and CWE IDs.\n"
        f"2. DO NOT modify any other field. Copy them EXACTLY as in the "
        f"\"PREVIOUS ATTEMPT\" JSON below.\n"
        f"3. Return a SINGLE JSON object (not a diff, not partial JSON) — "
        f"the orchestrator will merge per-field, so missing fields will be "
        f"treated as \"no change\".\n"
    )

    context = (
        f"=== CONTEXT ===\n"
        f"cve_id: {cve_id or 'unknown'}\n"
        f"description: {description}\n"
        f"cvss_vector: {cvss_vector}\n"
        f"cwe_ids: {cwe_ids or []}\n"
    )

    previous = (
        f"=== PREVIOUS ATTEMPT (preserve all fields except those listed "
        f"above) ===\n"
        f"{json.dumps(attempt_1_output, indent=2, ensure_ascii=False)}"
    )

    return f"{instructions}\n{context}\n\n{previous}\n"
