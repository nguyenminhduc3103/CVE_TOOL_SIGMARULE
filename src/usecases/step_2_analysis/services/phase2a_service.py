"""AI Service cho Step 2 — Phase 2 ATT&CK mapping (gọi LLM, parse JSON, validate contract; fallback logic ở orchestrator)."""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from config.settings import settings
from src.infrastructure.ai.core import AIServiceError, BaseAIClient
from src.usecases.step_2_analysis.models.llm_contracts import Phase2LLMResponse

logger = logging.getLogger(__name__)


_PROMPTS_DIR = Path(__file__).parent.parent / "prompts"


class AIBehaviorService:
    """Service gọi AI Phase 2 — ATT&CK mapping. Output dict thuần (Pydantic ở orchestrator)."""

    _PHASE2_SYSTEM_FILE = "analyze_behavior_phase2.system.txt"
    _USER_FILE = "analyze_behavior.user.txt"

    def __init__(self, base_client: BaseAIClient | None = None) -> None:
        # Create client with Phase 2 config if not provided
        if base_client is None:
            base_client = BaseAIClient(
                api_keys=settings.get_phase2_api_keys(),
                base_url=settings.get_phase2_base_url(),
            )
        self.client = base_client
        self._MODEL: str = settings.get_phase2_model()
        self._BASE_URL: str | None = settings.get_phase2_base_url()
        phase2_template = (_PROMPTS_DIR / self._PHASE2_SYSTEM_FILE).read_text(encoding="utf-8")
        self._phase2_system_prompt = phase2_template
        self.user_prompt_template = (_PROMPTS_DIR / self._USER_FILE).read_text(encoding="utf-8")
        logger.debug(
            "AIBehaviorService initialized (Phase 2): model=%s, base_url=%s",
            self._MODEL,
            self._BASE_URL,
        )

    async def fetch_attack_mapping(
        self,
        cve_id: str,
        description: str,
        phase1_output: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Phase 2 AI call — return ATT&CK mapping dict only."""
        phase2_system = self._phase2_system_prompt

        # Build Phase 2 input payload
        p1 = phase1_output or {}
        input_payload = {
            "cve_id": cve_id,
            "description": description or "",
            "exec_surface": p1.get("execution_surface") or "unknown",
            "delivery_vector": p1.get("delivery_vector") or "unknown",
            "mandatory_behaviors": p1.get("mandatory_behaviors") or [],
            "reasoning": p1.get("reasoning") or [],
            "poc_documentation": p1.get("poc_description") or "",
            "poc_request_info": p1.get("poc_request_info") or {},
            "poc_evidence": p1.get("poc_request_info", {}).get("path") if isinstance(p1.get("poc_request_info"), dict) else "",
        }
        formatted_user = self.user_prompt_template.format(
            input_json=json.dumps(input_payload, ensure_ascii=False, indent=2),
        )

        try:
            response_text = await self.client.call_llm(
                system_prompt=phase2_system,
                user_prompt=formatted_user,
                model=self._MODEL,
            )
            cleaned_text = self._clean_json(response_text)
            data = json.loads(cleaned_text)
            validated = Phase2LLMResponse.model_validate(data)
            return validated.model_dump(mode="python")
        except (json.JSONDecodeError, AIServiceError) as e:
            logger.error("AIBehaviorService.fetch_attack_mapping failed for %s: %s", cve_id, e)
            raise AIServiceError(f"Phase 2 Attack Mapping failed: {e}") from e
        except Exception as e:
            logger.error("AIBehaviorService.fetch_attack_mapping validation failed for %s: %s", cve_id, e)
            raise AIServiceError(f"Phase 2 Attack Mapping validation failed: {e}") from e

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
