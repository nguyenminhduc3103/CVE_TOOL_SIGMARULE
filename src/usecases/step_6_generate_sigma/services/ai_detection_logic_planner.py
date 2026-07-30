"""AI Detection Logic Planner (Step 6 Phase A).

Mirrors step_4_telemetry/services/ai_telemetry_service.py.
Any failure → AIServiceError → orchestrator falls back to rule-based.
"""
from __future__ import annotations

import json
import logging
import re
import sys
from pathlib import Path
from typing import Any

from config.settings import settings
from src.domain.models.attack import AttackMapping, TechnicalAnalysis
from src.infrastructure.ai.core import AIServiceError, BaseAIClient
from src.usecases.step_6_generate_sigma.domain.detection_plan import (
    DetectionIntent,
    DetectionLogic,
    DetectionPlan,
)
from src.usecases.step_6_generate_sigma.models.llm_contract import (
    Step6LLMResponse,
    assert_no_forbidden_fields,
)

logger = logging.getLogger(__name__)

_PROMPTS_DIR = Path(__file__).parent.parent / "prompts"


class AIDetectionLogicPlanner:
    """AI service cho Step 6 — emits DetectionPlan (semantic intent only)."""

    _SYSTEM_FILE = "dlp.system.txt"
    _USER_FILE = "dlp.user.txt"
    _DEFAULT_MODEL = "gemini-3.5-flash-lite"

    def __init__(self, base_client: BaseAIClient) -> None:
        self.client = base_client
        self._MODEL: str = settings.get_step6_model() or self._DEFAULT_MODEL
        self._system_prompt_template = (
            _PROMPTS_DIR / self._SYSTEM_FILE
        ).read_text(encoding="utf-8")
        self._user_prompt_template = (
            _PROMPTS_DIR / self._USER_FILE
        ).read_text(encoding="utf-8")
        logger.info(
            "[Step 6] AI service initialized: model=%s base_url=%s",
            self._MODEL,
            settings.get_step6_base_url() or "(default)",
        )

    async def plan(
        self,
        cve_id: str,
        analysis: TechnicalAnalysis | dict[str, object] | None,
        attack: AttackMapping | dict[str, object] | None,
        telemetry: dict[str, Any] | None,
        references: list[str] | None = None,
    ) -> DetectionPlan:
        # One-shot AI planning; parse/validate fail → raise, orchestrator fallback rule-based.
        input_payload = self._build_input_payload(cve_id, analysis, attack, telemetry, references)
        formatted_user = self._user_prompt_template.format(
            cve_id=cve_id,
            **input_payload,
        )

        response_text = await self._call_llm_with_overrides(formatted_user, cve_id)

        plan, _ = self._parse_and_validate(response_text, cve_id)
        if plan is None:
            raise AIServiceError(
                "Step 6 Detection Logic Planning failed (JSON/validation). See log for raw preview."
            )

        plan.ai_model = self._MODEL
        return plan

    async def _call_llm_with_overrides(self, formatted_user: str, cve_id: str) -> str:
        # One LLM call; honor STEP6_AI_* overrides, then primary client.
        try:
            if self._has_separate_provider():
                step6_keys = settings.get_step6_api_keys()
                if not step6_keys:
                    raise AIServiceError("Step 6 separate provider configured but no API key.")
                logger.info("[Step 6] Calling %s via separate provider", self._MODEL)
                return await self.client.call_llm(
                    system_prompt=self._system_prompt_template,
                    user_prompt=formatted_user,
                    model=self._MODEL,
                    override_api_key=step6_keys[0],
                    override_base_url=settings.get_step6_base_url(),
                    max_tokens=16384,
                    response_format_json=True,
                )
            logger.info("[Step 6] Calling %s via primary client", self._MODEL)
            return await self.client.call_llm(
                system_prompt=self._system_prompt_template,
                user_prompt=formatted_user,
                model=self._MODEL,
                max_tokens=16384,
                response_format_json=True,
            )
        except AIServiceError:
            raise
        except Exception as exc:
            logger.error("[Step 6] AI call failed for %s: %s", cve_id, exc)
            raise AIServiceError(f"Step 6 Detection Logic Planning failed: {exc}") from exc

    def _parse_and_validate(
        self, response_text: str, cve_id: str,
    ) -> tuple[DetectionPlan | None, int]:
        # (plan, retries); (None, 1) signals caller to retry once.
        cleaned = self._clean_json(response_text)
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            preview = (response_text or "")[:1200]
            sys.stderr.write(
                f"\n[Step 6 RAW RESPONSE for {cve_id}]\n{preview}\n[/Step 6 RAW]\n"
            )
            sys.stderr.flush()
            preview_log = preview[:500].replace("\n", "\\n")
            logger.error("[Step 6] JSON parse failed for %s: %s | raw_preview=%s", cve_id, exc, preview_log)
            return None, 1

        try:
            assert_no_forbidden_fields(data)
        except ValueError as exc:
            logger.error("[Step 6] AI emitted forbidden fields for %s: %s", cve_id, exc)
            return None, 1

        try:
            validated = Step6LLMResponse.model_validate(data)
        except Exception as exc:
            logger.warning("[Step 6] Pydantic validation failed for %s: %s; attempting soft-fix", cve_id, exc)
            # Soft-fix small deviations (e.g. risk_bias) before giving up
            fixed = self._soft_fix_llm_response(data)
            if fixed is None:
                logger.error("[Step 6] Soft-fix failed for %s; raising AIServiceError", cve_id)
                return None, 1
            try:
                validated = Step6LLMResponse.model_validate(fixed)
            except Exception as exc2:
                logger.error("[Step 6] Validation still failed after soft-fix for %s: %s", cve_id, exc2)
                return None, 1

        return self._to_domain(validated), 0

    @staticmethod
    def _soft_fix_llm_response(data: dict[str, Any]) -> dict[str, Any] | None:
        """Coerce small LLM deviations (e.g. risk_bias values) instead of failing whole plan."""
        if not isinstance(data, dict):
            return None
        rb = data.get("risk_bias")
        if isinstance(rb, str) and rb not in {"conservative", "neutral", "aggressive"}:
            # AI may emit Step 2 priority vocab: high/medium → aggressive, low → conservative.
            ml = rb.lower()
            if ml in {"high", "medium", "moderate", "elevated"}:
                data["risk_bias"] = "aggressive"
            elif ml in {"low", "minimal", "minor"}:
                data["risk_bias"] = "conservative"
            else:
                data["risk_bias"] = "neutral"
            logger.debug("[Step 6] Soft-fixed risk_bias=%r → %r", rb, data["risk_bias"])
        return data

    def _build_input_payload(
        self,
        cve_id: str,
        analysis: TechnicalAnalysis | dict[str, object] | None,
        attack: AttackMapping | dict[str, object] | None,
        telemetry: dict[str, Any] | None,
        references: list[str] | None,
    ) -> dict[str, Any]:
        def _get(obj, key, default=None):
            if obj is None:
                return default
            if isinstance(obj, dict):
                return obj.get(key, default)
            return getattr(obj, key, default)

        telemetry = telemetry or {}

        return {
            "mandatory_behaviors": _get(analysis, "mandatory_behaviors", []) or [],
            "evasive_indicators": _get(analysis, "evasive_indicators", []) or [],
            "exploit_requirements": _get(analysis, "exploit_requirements", []) or [],
            "reasoning": _get(analysis, "reasoning", []) or [],
            "execution_surface": (
                _get(analysis, "execution_surface").value
                if _get(analysis, "execution_surface") and hasattr(_get(analysis, "execution_surface"), "value")
                else _get(analysis, "execution_surface")
            ),
            "delivery_vector": _get(analysis, "delivery_vector"),
            "exploit_vector": _get(analysis, "exploit_vector"),
            "user_interaction": _get(analysis, "user_interaction_required"),
            "exploit_complexity": _get(analysis, "exploit_complexity"),
            "candidate_telemetry_domains": telemetry.get("candidate_telemetry_domains", []) or [],
            "canonical_telemetry": telemetry.get("canonical_telemetry", []) or [],
            "sigma_logsources": telemetry.get("sigma_logsources", []) or [],
            "validated_fields": telemetry.get("validated_fields", []) or [],
            "stable_features": telemetry.get("stable_features", []) or [],
            "conditional_features": telemetry.get("conditional_features", []) or [],
            "optional_features": telemetry.get("optional_features", []) or [],
            "correlation_required": bool(telemetry.get("correlation_required", False)),
            "pipeline_feasibility": telemetry.get("pipeline_feasibility") or telemetry.get("telemetry_feasibility_score"),
            "references": references or [],
        }

    def _to_domain(self, llm: Step6LLMResponse) -> DetectionPlan:
        """Convert Step6LLMResponse → DetectionPlan (domain model)."""
        return DetectionPlan(
            detections=[
                DetectionIntent(
                    intent=d.intent,
                    priority=d.priority,
                    rationale=d.rationale,
                    selection_hint=d.selection_hint,
                )
                for d in llm.detections
            ],
            logic=DetectionLogic(
                operator=llm.logic.operator,
                operands=list(llm.logic.operands),
                threshold=llm.logic.threshold,
            ),
            falsepositives=list(llm.falsepositives),
            risk_bias=llm.risk_bias,
            rationale=llm.rationale,
            planner_confidence=llm.planner_confidence,
            source="ai",
            ai_model=self._MODEL,
            ai_retry_count=0,
        )

    def _has_separate_provider(self) -> bool:
        step6_keys = settings.get_step6_api_keys()
        step6_base_url = settings.get_step6_base_url()
        step4_keys = settings.get_step4_api_keys()
        step4_base_url = settings.get_step4_base_url()
        main_keys = settings.get_api_keys()
        main_base_url = getattr(settings, "ai_base_url", None)
        return (
            (step6_keys != step4_keys)
            or (step6_keys != main_keys)
            or (step6_base_url != step4_base_url)
            or (step6_base_url != main_base_url)
        )

    @staticmethod
    def _clean_json(text: str) -> str:
        # Strip markdown fences / leading prose so json.loads can parse.
        text = text.strip()

        fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if fenced:
            return fenced.group(1).strip()

        first = text.find("{")
        if first == -1:
            return text.strip()

        depth = 0
        in_string = False
        escape = False
        last = -1
        for i in range(first, len(text)):
            c = text[i]
            if escape:
                escape = False
                continue
            if c == "\\":
                escape = True
                continue
            if c == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    last = i
                    break

        if last == -1:
            return text[first:].strip()
        return text[first: last + 1].strip()


__all__ = ["AIDetectionLogicPlanner"]