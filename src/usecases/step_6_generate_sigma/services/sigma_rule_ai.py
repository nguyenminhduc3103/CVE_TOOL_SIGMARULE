# Sigma Rule AI Service — Step 6 orchestrator.
# Pipeline: resolve telemetry -> build minimal payload -> call LLM -> validate -> return.
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from config.settings import settings
from src.domain.models.attack import AttackMapping, TechnicalAnalysis
from src.domain.models.cve import CoreCVEData
from src.infrastructure.ai.core import BaseAIClient
from src.usecases.step_4_telemetry.models.telemetry_plan import TelemetryPlan
from src.usecases.step_6_generate_sigma.models.result import (
    SigmaRuleLLMResponse,
    Step6Result,
)
from src.usecases.step_6_generate_sigma.validators.step6_validator import (
    Step6ValidationError,
    Step6Validator,
)

if TYPE_CHECKING:
    from src.domain.models.telemetry_discovery import PoCSummary

logger = logging.getLogger(__name__)

_PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"


class SigmaRuleAI:
    # Single-pass AI service that emits a strict Step6Result (Architect v9).
    def __init__(self, ai_client: BaseAIClient | None = None) -> None:
        # ai_client: duck-typed BaseAIClient (call_llm(...) -> str); tests may pass stub.
        self.client = ai_client or BaseAIClient()
        self._system_prompt = (
            _PROMPTS_DIR / "sigma_rule.system.txt"
        ).read_text(encoding="utf-8")
        self._user_template = (
            _PROMPTS_DIR / "sigma_rule.user.txt"
        ).read_text(encoding="utf-8")

    async def plan(
        self,
        cve: CoreCVEData,
        behavior: TechnicalAnalysis | dict | None,
        telemetry: TelemetryPlan | dict,
        attack: AttackMapping | dict | None = None,
        poc: Any = None,
    ) -> Step6Result:
        # Build AI Step6Result. Accepts model OR dict for behavior/telemetry/attack; poc is PoCSummary-or-dict.
        telemetry_plan = self._resolve_telemetry_input(telemetry)
        poc_description, poc_network_payloads = self._extract_poc(poc)
        payload = self._build_input_payload(
            cve, behavior, attack, telemetry_plan,
            poc_description=poc_description,
            poc_network_payloads=poc_network_payloads,
        )
        user_prompt = self._user_template.format(
            input_json=json.dumps(payload, ensure_ascii=False, indent=2),
        )

        model = settings.get_step6_model()
        response_text = await self.client.call_llm(
            system_prompt=self._system_prompt,
            user_prompt=user_prompt,
            model=model,
            max_retries=3,
            response_format_json=True,
        )

        cleaned = self._clean_json(response_text)
        data = json.loads(cleaned)

        llm_response = SigmaRuleLLMResponse.model_validate(data)
        result = Step6Result(
            cve_id=cve.cve_id,
            ai_model=model,
            detections=llm_response.detections,
            correlations=llm_response.correlations,
            reasoning=llm_response.reasoning,
        )

        # Business validation (tách khỏi Pydantic per architect v9).
        Step6Validator(telemetry_plan).validate(result)

        logger.info(
            "step6.plan cve_id=%s detections=%d correlations=%d model=%s",
            result.cve_id,
            len(result.detections),
            len(result.correlations),
            model,
        )
        return result

    async def run(  # legacy alias for downstream import contract (CLI + e2e test).
        self,
        core: CoreCVEData,
        analysis: TechnicalAnalysis | dict | None,
        attack: AttackMapping | dict | None = None,
        telemetry: TelemetryPlan | dict | None = None,
        poc: Any = None,
        **_unused: Any,  # noqa: ARG004 — accepts legacy `references` kwarg
    ) -> Step6Result:
        # Back-compat alias for plan(). Extra kwargs (e.g. legacy references) are ignored.
        if telemetry is None:
            raise Step6ValidationError(
                "telemetry is required (telemetry=... in legacy .run() signature)"
            )
        return await self.plan(
            cve=core,
            behavior=analysis,
            telemetry=telemetry,
            attack=attack,
            poc=poc,
        )

    @staticmethod
    def _resolve_telemetry_input(telemetry: TelemetryPlan | dict) -> TelemetryPlan:
        # Accept TelemetryPlan or dict (dict is rebuilt via Pydantic validation).
        if isinstance(telemetry, TelemetryPlan):
            return telemetry
        if isinstance(telemetry, dict):
            return TelemetryPlan.model_validate(telemetry)
        raise Step6ValidationError(
            f"telemetry must be TelemetryPlan or dict, got {type(telemetry).__name__}"
        )

    def _build_input_payload(
        self,
        cve: CoreCVEData,
        behavior: TechnicalAnalysis | dict | None,
        attack: AttackMapping | dict | None,
        telemetry_plan: TelemetryPlan,
        *,
        poc_description: str = "",
        poc_network_payloads: list[Any] | None = None,
    ) -> dict[str, Any]:
        # MINIMAL payload: context (Step 1) + behavior (Step 2) + search_space (Step 4).
        behavior_payload = self._safe_dump(behavior)
        # attack_chain lives on AttackMapping (Phase 2B); expose under behavior.attack_chain.
        attack_chain = self._extract_attack_chain(attack)
        if attack_chain is not None:
            behavior_payload["attack_chain"] = attack_chain
        return {
            "context": {
                "cve_id": cve.cve_id,
                "description": cve.description or "",
                "poc_description": poc_description or "",
                "poc_network_payloads": list(poc_network_payloads or []),
            },
            "behavior": behavior_payload,
            "search_space": {
                "detection_strategy": telemetry_plan.detection_strategy,
                "correlation_required": telemetry_plan.correlation_required,
                "candidate_features": [
                    {
                        "category": feat.telemetry_concept,
                        "feature": feat.semantic,
                        "priority": priority,
                        "evidence": list(feat.evidence),
                    }
                    for priority, feats in [
                        ("stable", telemetry_plan.candidate_features.stable),
                        ("conditional", telemetry_plan.candidate_features.conditional),
                        ("optional", telemetry_plan.candidate_features.optional),
                    ]
                    for feat in feats
                ],
                "candidate_logsources": [
                    # Serialize each SigmaLogsource verbatim (validator uses same shape for search-space).
                    {
                        "category": ls.category,
                        "product": ls.product,
                        "allowed_fields": dict(ls.allowed_fields),
                    }
                    for ls in telemetry_plan.sigma_logsources
                ],
                "telemetry_gaps": list(telemetry_plan.telemetry_gaps or []),
            },
        }

    @staticmethod
    def _extract_poc(poc: Any) -> tuple[str, list[Any]]:
        # Pull (poc_description, poc_network_payloads) from PoCSummary/dict; stable tuple shape.
        if poc is None:
            return "", []
        if isinstance(poc, dict):
            description = str(poc.get("poc_description", "") or "")
            payloads = poc.get("poc_network_payloads", []) or []
        else:
            description = str(getattr(poc, "poc_description", "") or "")
            payloads = getattr(poc, "poc_network_payloads", None) or []
        if not isinstance(payloads, list):
            payloads = []
        return description, list(payloads)

    @staticmethod
    def _extract_attack_chain(attack: Any) -> list[Any] | None:
        # Pull attack_chain from AttackMapping (or its dict dump).
        if attack is None:
            return None
        if isinstance(attack, dict):
            chain = attack.get("attack_chain")
        elif hasattr(attack, "attack_chain"):
            chain = attack.attack_chain
        else:
            return None
        if chain is None:
            return None
        return list(chain)

    @staticmethod
    def _safe_dump(model: Any) -> dict[str, Any]:
        # Dump a Pydantic model, dict, or None -> dict (used for behavior payload).
        if model is None:
            return {}
        if hasattr(model, "model_dump"):
            return model.model_dump(exclude_none=True)
        if isinstance(model, dict):
            return dict(model)
        return {}

    @staticmethod
    def _clean_json(text: str) -> str:
        # Strip markdown fences and any prose before/after the JSON object.
        fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if fence:
            return fence.group(1)
        first = text.find("{")
        last = text.rfind("}")
        if first != -1 and last != -1 and last > first:
            return text[first:last + 1]
        return text


__all__ = ["SigmaRuleAI"]
