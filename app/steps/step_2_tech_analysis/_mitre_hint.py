"""MITRE hint helper - RAG-lite cheat sheet cho AI prompts.

Đây là Cách 3 (RAG cheat sheet) trong 3 cách fix bug "AI output wipeout":
Inject 1 dòng `[Valid MITRE for this CVE: Txxxx, Tyyyy]` vào user prompt
→ AI dùng làm "cheat sheet" để cover whitelist, đỡ bị phạt extras.

Why:
- AI thường chỉ pick 1-2 techniques obvious (vd T1190 cho RCE web) nhưng
  ground truth (CAPEC/CTID) yêu cầu nhiều techniques đặc trưng hơn
  (vd T1027 obfuscation, T1539 steal cookie, T1574 hijack execution).
- Hint từ OntologyManager.resolve() = cùng expected_techniques mà
  gap_analysis dùng để chấm điểm → consistency tuyệt đối.

Trade-off vs Cách 1 (Structured Enum) / Cách 2 (Auto-Correct code):
- ✅ 0 schema change, 0 code layer thêm
- ✅ AI vẫn có quyền pick ngoài hint (nếu justify được) → linh hoạt
- ⚠️ AI có thể vẫn ignore hint nếu prompt khác ghi đè
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def build_mitre_hint(
    cve_id: str | None,
    description: str | None,
    cwe_ids: list[str] | None,
    cvss_vector: str | None,
) -> str:
    """Build 1 dòng hint nhỏ gọn để inject vào AI prompt.

    Format:
        [Valid MITRE for this CVE (source=CAPEC, quality=PARTIAL): T1027, T1036.001, ...]
        [Valid MITRE for this CVE: None — no ground truth available]

    Trả "" nếu lỗi (fail-safe: prompt vẫn work như trước).
    """
    try:
        from app.steps.step_2_tech_analysis._shared_engines.ontology_manager import (
            CveContext,
            OntologyManager,
        )
        ctx = CveContext(
            cve_id=cve_id or "",
            description=description or "",
            cwe_ids=tuple(cwe_ids or ()),
            cvss_vector=cvss_vector,
        )
        mgr = OntologyManager()
        expected = mgr.resolve(ctx)
        if expected.is_unknown():
            return (
                "[Valid MITRE for this CVE: None — no ground truth available. "
                "Pick techniques that strictly match the CVE description + CWE + CVSS vector.]"
            )
        techs = sorted(expected.expected_techniques)
        if not techs:
            return (
                "[Valid MITRE for this CVE: no techniques mapped. "
                "Pick techniques strictly from CVE description + CWE + CVSS.]"
            )
        src = expected.ground_truth_source
        q = expected.ground_truth_quality
        return (
            f"[Valid MITRE for this CVE (source={src}, quality={q}): "
            f"{', '.join(techs)}. Use these as the baseline; you may add others "
            f"only if explicitly justified by CVE description/CWE/CVSS.]"
        )
    except Exception as exc:
        logger.warning("build_mitre_hint failed for %s: %s", cve_id, exc)
        return ""