"""AI Service cho Step 2 - Technical & ATT&CK Analyzer.

CHỈ làm 1 việc: gọi AI Groq/LLM + parse JSON response thành DICT thuần.

KHÔNG tạo Pydantic model ở đây. KHÔNG có fallback logic ở đây.
Tất cả Pydantic conversion + fallback sẽ làm ở orchestrator.py.

Returns:
    dict (raw AI JSON đã clean) hoặc raises AIServiceError nếu fail.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from app.shared.ai.core import AIServiceError, BaseAIClient

logger = logging.getLogger(__name__)


_PROMPTS_DIR = Path(__file__).parent.parent / "prompts"


class AIBehaviorService:
    """Service gọi AI để phân tích CVE behavior + ATT&CK mapping.

    Single Responsibility: gọi LLM + parse JSON. Output là dict thuần (Pydantic
    conversion làm ở orchestrator).
    """

    _SYSTEM_FILE = "analyze_behavior.system.txt"
    _SHARED_FILE = "_shared_mitre_rules.md"
    _USER_FILE = "analyze_behavior.user.txt"
    # Analyze (chính): Groq 70B — quality tốt cho reasoning CVE phức tạp.
    # Free tier: 100k TPD + 6K TPM.
    _MODEL = "llama-3.3-70b-versatile"
    # Retry (sửa lỗi): Google Gemini 2.5 Flash — 1M TPM, fix bug
    # "Request too large" khi retry payload ~8.5K vượt Groq 6K TPM.
    # Đổi từ 1.5-flash sang 2.5-flash vì key này chỉ enable được 2.0+ models
    # (1.5-flash trả 404 not found). 2.5-flash là model mới nhất có sẵn,
    # quality reasoning tốt hơn 2.0, cùng OpenAI-compatible API.
    _RETRY_MODEL = "gemini-2.5-flash"

    def __init__(self, base_client: BaseAIClient) -> None:
        self.client = base_client
        # Load shared MITRE rules once; both analyze + retry templates reference them.
        shared_rules = (_PROMPTS_DIR / self._SHARED_FILE).read_text(encoding="utf-8")
        analyze_template = (
            _PROMPTS_DIR / self._SYSTEM_FILE
        ).read_text(encoding="utf-8")
        # Replace placeholder with shared rules content at construction time so
        # call_llm receives the full prompt (byte-identical to pre-split version).
        self.system_prompt_template = analyze_template.replace(
            "{{SHARED_MITRE_RULES}}", shared_rules
        )
        self.user_prompt_template = (
            _PROMPTS_DIR / self._USER_FILE
        ).read_text(encoding="utf-8")
        # Track BOTH analyze + retry models used in this run (instance-scoped
        # so each CVE call starts fresh). Order-preserving + deduplicated:
        # analyze model always first; retry model appended only if a retry
        # actually fired via `record_retry_model()`.
        self._models_used: list[str] = []

    def _record_model(self, model: str) -> None:
        """Append `model` to `_models_used` if not already present."""
        if model and model not in self._models_used:
            self._models_used.append(model)

    def record_retry_model(self) -> None:
        """Mark that the retry model was used. Call BEFORE the retry call so
        it shows up even if the retry itself fails (e.g. rate-limit)."""
        self._record_model(self._RETRY_MODEL)

    def get_models_used(self) -> list[str]:
        """Return deduplicated, order-preserved list of models actually used
        for this CVE. analyze model first; retry model appended only if a
        retry was attempted.
        """
        return list(self._models_used)

    async def fetch_raw_response(
        self,
        cve_id: str,
        description: str,
        cvss_score: float,
        cvss_vector: str,
        cwe_ids: list[str],
        cpes: list[str],
        references: list[str],
        published_at: str,
        modified_at: str,
    ) -> dict[str, Any]:
        """Gọi AI + parse JSON. Return dict thuần (không phải Pydantic).

        Raises:
            AIServiceError: nếu AI fail (rate-limit, timeout, JSON parse fail, etc.)
        """
        formatted_user = self.user_prompt_template.format(
            cve_id=cve_id,
            description=description or "N/A",
            cvss_score=cvss_score,
            cvss_vector=cvss_vector or "N/A",
            cwe_ids=", ".join(cwe_ids) if cwe_ids else "None",
            cpes=", ".join(cpes) if cpes else "None",
            references="\n".join(references) if references else "None",
            published_at=published_at or "N/A",
            modified_at=modified_at or "N/A",
        )

        try:
            response_text = await self.client.call_llm(
                system_prompt=self.system_prompt_template,
                user_prompt=formatted_user,
                model=self._MODEL,
            )
            # Record analyze model ONLY after a successful dispatch (the call
            # itself didn't raise). Retry model is recorded separately by
            # the orchestrator via record_retry_model() before its call.
            self._record_model(self._MODEL)
            cleaned_text = self._clean_json(response_text)
            data = json.loads(cleaned_text)
            return data
        except (json.JSONDecodeError, AIServiceError) as e:
            logger.error("AIBehaviorService failed for %s: %s", cve_id, e)
            raise AIServiceError(f"Behavior Analysis failed: {e}") from e

    @staticmethod
    def _clean_json(text: str) -> str:
        """Strip markdown fences / leading prose để json.loads parse được."""
        fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if fenced:
            return fenced.group(1).strip()
        first = text.find("{")
        last = text.rfind("}")
        if first != -1 and last != -1 and last > first:
            return text[first : last + 1].strip()
        return text.strip()
