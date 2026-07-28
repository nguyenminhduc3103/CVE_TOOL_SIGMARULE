"""Phase 1 AI Service - Behavior Analysis (FACTS ONLY). Tách riêng khỏi Phase 2 ATT&CK mapping để tránh bias do CVSS heuristic (vd CVE client-side MSHTML)."""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from config.settings import settings
from src.infrastructure.ai.core import AIServiceError, BaseAIClient
from src.usecases.step_2_analysis.models.llm_contracts import Phase1LLMResponse

logger = logging.getLogger(__name__)


_PROMPTS_DIR = Path(__file__).parent.parent / "prompts"


class AIPhase1Service:
    """Phase 1 AI service - Behavior Analysis only (khong map ATT&CK). Output schema includes execution_surface, delivery_vector, user_interaction_required."""

    _SYSTEM_FILE = "analyze_behavior_phase1.system.txt"
    _USER_FILE = "analyze_behavior.user.txt"
    # Default model - same as Phase 2 (backward compat).
    # Override via env PHASE1_AI_MODEL to use OpenRouter free model.
    _DEFAULT_MODEL = "llama-3.3-70b-versatile"

    def __init__(self, base_client: BaseAIClient) -> None:
        self.client = base_client
        # Resolve Phase 1 model từ settings (PHASE1_AI_MODEL > ANALYZE_AI_MODEL).
        self._MODEL: str = settings.get_phase1_model() or self._DEFAULT_MODEL
        # Phase 1 system prompt does NOT reference _shared_mitre_rules.md (no ATT&CK mapping in scope here).
        self.system_prompt_template = (
            _PROMPTS_DIR / self._SYSTEM_FILE
        ).read_text(encoding="utf-8")
        self.user_prompt_template = (
            _PROMPTS_DIR / self._USER_FILE
        ).read_text(encoding="utf-8")
        # Log model + base_url để user thấy Phase 1 đang dùng model nào (vd Gemini thay vì Groq).
        logger.info(
            "[Phase 1] model=%s base_url=%s",
            self._MODEL, settings.get_phase1_base_url() or "(default - same as Phase 2)",
        )

    async def fetch_behavior(
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
        poc_references: list[str] | None = None,
        threat_actors: list[str] | None = None,
    ) -> dict[str, Any]:
        """Phase 1 AI call - return behavior dict (no ATT&CK mapping)."""
        input_payload = {
            "cve_id": cve_id,
            "description": description or "N/A",
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector or "N/A",
            "cwe_ids": cwe_ids or [],
            "cpes": cpes or [],
            "references": references or [],
            "published_at": published_at or "N/A",
            "modified_at": modified_at or "N/A",
            "poc_references": (poc_references or [])[: self._MAX_POC_REFS],
            "threat_actors": (threat_actors or [])[: self._MAX_THREAT_ACTORS],
        }
        formatted_user = self.user_prompt_template.format(
            input_json=json.dumps(input_payload, ensure_ascii=False, indent=2),
        )

        try:
            # Phase 1 có the dung provider riêng (OpenRouter, Google AI Studio, ...)
            # Neu Phase 1 config khac Phase 2 → truyen override_api_key/base_url
            # de base_client.call_llm() build AsyncOpenAI rieng.
            phase1_keys = settings.get_phase1_api_keys()
            main_keys = settings.get_api_keys()
            main_base_url = getattr(settings, "ai_base_url", None)
            phase1_base_url = settings.get_phase1_base_url()

            # Check xem Phase 1 co provider rieng khong
            has_separate_provider = (
                (phase1_keys != main_keys)
                or (phase1_base_url != main_base_url)
            )

            if has_separate_provider:
                # Build AsyncOpenAI rieng cho Phase 1 (khong touch round-robin cua Phase 2)
                if not phase1_keys:
                    raise AIServiceError(
                        "Phase 1 separate provider configured but no API key."
                    )
                logger.info("[Phase 1] Calling %s via separate provider", self._MODEL)
                response_text = await self.client.call_llm(
                    system_prompt=self.system_prompt_template,
                    user_prompt=formatted_user,
                    model=self._MODEL,
                    override_api_key=phase1_keys[0],
                    override_base_url=phase1_base_url,
                )
            else:
                # Fallback: dung chung primary client (backward compat)
                logger.info("[Phase 1] Calling %s via primary client (no separate provider)", self._MODEL)
                response_text = await self.client.call_llm(
                    system_prompt=self.system_prompt_template,
                    user_prompt=formatted_user,
                    model=self._MODEL,
                )
            cleaned_text = self._clean_json(response_text)
            data = json.loads(cleaned_text)
            validated = Phase1LLMResponse.model_validate(data)
            return validated.model_dump(mode="python")
        except (json.JSONDecodeError, AIServiceError) as e:
            logger.error("AIPhase1Service failed for %s: %s", cve_id, e)
            raise AIServiceError(f"Phase 1 Behavior Analysis failed: {e}") from e
        except Exception as e:
            logger.error("AIPhase1Service validation failed for %s: %s", cve_id, e)
            raise AIServiceError(f"Phase 1 Behavior Analysis validation failed: {e}") from e

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

    # Cap giữ input payload gọn (tránh prompt overflow).
    _MAX_POC_REFS = 3
    _MAX_THREAT_ACTORS = 5