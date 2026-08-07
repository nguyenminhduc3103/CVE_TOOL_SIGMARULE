# Telemetry Plan AI Service — new Step 4. Mirrors Step 2/6 AI service pattern.
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from config.settings import settings
from src.infrastructure.ai.core import BaseAIClient
from src.usecases.step_4_telemetry._knowledge.loader import load_telemetry_concepts
from src.usecases.step_4_telemetry._knowledge.sigma_category_statistics import load_statistics
from src.usecases.step_4_telemetry.models.llm_contract import TelemetryLLMResponse
from src.usecases.step_4_telemetry.models.telemetry_plan import TelemetryPlan
from src.usecases.step_4_telemetry.services.logsource_resolver import (
    extract_categories,
    resolve,
)

if TYPE_CHECKING:
    from src.domain.models.enriched import EnrichedCVEContext

logger = logging.getLogger(__name__)

_PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"


class TelemetryPlanAI:
    """Single-pass AI service that emits a strict TelemetryPlan."""

    def __init__(self, base_client: BaseAIClient | None = None) -> None:
        self.client = base_client or BaseAIClient()
        self._system_prompt = (
            _PROMPTS_DIR / "telemetry_plan.system.txt"
        ).read_text(encoding="utf-8")
        self._user_template = (
            _PROMPTS_DIR / "telemetry_plan.user.txt"
        ).read_text(encoding="utf-8")

    async def plan(self, enriched: EnrichedCVEContext) -> TelemetryPlan:
        """Build the AI TelemetryPlan from an EnrichedCVEContext."""
        payload = self._build_input_payload(enriched)
        user_prompt = self._user_template.format(
            input_json=json.dumps(payload, ensure_ascii=False, indent=2),
        )

        model = settings.get_step4_model()
        response_text = await self.client.call_llm(
            system_prompt=self._system_prompt,
            user_prompt=user_prompt,
            model=model,
            max_retries=3,
            response_format_json=True,
        )

        cleaned = self._clean_json(response_text)
        data = json.loads(cleaned)

        llm_response = TelemetryLLMResponse.model_validate(data)
        plan = TelemetryPlan(
            cve_id=enriched.core.cve_id,
            ai_model=model,
            **llm_response.model_dump(),
        )
        plan = self._resolve_sigma_logsources(plan)
        from src.usecases.step_4_telemetry.validation.semantic_validator import SemanticCoherenceValidator
        plan = SemanticCoherenceValidator.validate(plan, enriched.analysis)
        logger.info(
            "step4.plan cve_id=%s primary=%s correlation=%s confidence=%.2f model=%s",
            plan.cve_id,
            plan.detection_axis.primary,
            plan.correlation_required,
            plan.telemetry_confidence,
            model,
        )
        return plan

    def _resolve_sigma_logsources(self, plan: TelemetryPlan) -> TelemetryPlan:
        """Deterministic post-pass: derive `sigma_logsources` from the AI plan.

        `knowledge` is loaded once per `plan()` invocation so the resolver
        itself stays a true pure function and is trivially testable.
        """
        knowledge = load_statistics()
        categories = extract_categories(plan.candidate_features)
        logsources = resolve(knowledge, plan.target_environment, categories)
        return plan.model_copy(update={"sigma_logsources": logsources})

    def _build_input_payload(self, enriched: EnrichedCVEContext) -> dict[str, Any]:
        """Bundle the TelemetryInput that the AI consumes."""
        return {
            "context": {
                "cve_id": enriched.core.cve_id,
                "description": enriched.core.description,
                "cwe_ids": enriched.core.cwe_ids or [],
            },
            "target": self._normalize_target(enriched),
            "analysis": self._safe_dump(enriched.analysis),
            "attack": self._safe_dump(enriched.attack),
            "intel": self._safe_dump(enriched.intel),
            "telemetry_concepts_kb": load_telemetry_concepts(),
        }

    @staticmethod
    def _normalize_target(enriched: EnrichedCVEContext) -> dict[str, list[str]]:
        # Normalize affected_products into the 3-bucket shape via tools.normalize_cpe.
        from tools.normalize_cpe import normalize_products

        raw = enriched.core.affected_products or []
        normalized = normalize_products(raw)
        return normalized.model_dump()

    @staticmethod
    def _safe_dump(model: Any) -> dict[str, Any]:
        if model is None:
            return {}
        if hasattr(model, "model_dump"):
            return model.model_dump(exclude_none=True)
        if isinstance(model, dict):
            return model
        return {}

    @staticmethod
    def _clean_json(text: str) -> str:
        text = text.strip()
        fence = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
        if fence:
            text = fence.group(1).strip()
        first = text.find("{")
        if first == -1:
            return text
        text_from_first = text[first:].strip()
        try:
            obj, _ = json.JSONDecoder().raw_decode(text_from_first)
            return json.dumps(obj)
        except json.JSONDecodeError:
            last = text_from_first.rfind("}")
            if last != -1:
                return text_from_first[: last + 1]
            return text_from_first