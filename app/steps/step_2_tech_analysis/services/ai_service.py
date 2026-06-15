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
    _USER_FILE = "analyze_behavior.user.txt"
    # Pick one. Comment/uncomment to switch.
    _MODEL = "llama-3.3-70b-versatile"  # full-fat 70B — best quality, but Groq free tier rate-limits TPD (100k)

    def __init__(self, base_client: BaseAIClient) -> None:
        self.client = base_client
        self.system_prompt_template = (
            _PROMPTS_DIR / self._SYSTEM_FILE
        ).read_text(encoding="utf-8")
        self.user_prompt_template = (
            _PROMPTS_DIR / self._USER_FILE
        ).read_text(encoding="utf-8")

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
