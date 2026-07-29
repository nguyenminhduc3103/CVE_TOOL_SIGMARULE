"""Step 6 Orchestrator — wires Phase A (Planner) + Phase D (Builder).

Scope: Phase A Detection Planner (AI) + Phase D Sigma Builder (deterministic).
Out of scope: validation, quality, noise, deployment, explanation, reporting.
Inputs: Step 2 TechnicalAnalysis/AttackMapping + Step 4 TelemetryAssessment.
"""
from __future__ import annotations

import logging
from typing import Any

from config.settings import settings
from src.domain.models.attack import AttackMapping, TechnicalAnalysis
from src.domain.models.cve import CoreCVEData
from src.infrastructure.ai.core import AIServiceError, BaseAIClient
from src.usecases.step_6_generate_sigma._knowledge import loader
from src.usecases.step_6_generate_sigma.builders.sigma_builder import (
    build_sigma_rule,
)
from src.usecases.step_6_generate_sigma.domain.detection_plan import (
    DetectionPlan,
)
from src.usecases.step_6_generate_sigma.domain.step6_result import Step6Result
from src.usecases.step_6_generate_sigma.fallbacks.rule_based_planner import (
    build_rule_based_plan,
)
from src.usecases.step_6_generate_sigma.services.ai_detection_logic_planner import (
    AIDetectionLogicPlanner,
)

logger = logging.getLogger(__name__)


class Step6Orchestrator:
    """Connector between Step 2/4 inputs and deterministic Sigma pipeline.

    Phase A: AI Detection Planner → DetectionPlan.
    Phase D: Sigma Builder → SigmaRule + YAML.
    """

    def __init__(
        self,
        ai_client: BaseAIClient | None = None,
    ) -> None:
        self.ai_client = ai_client
        self._ai_planner: AIDetectionLogicPlanner | None = None
        if ai_client is not None:
            self._ai_planner = AIDetectionLogicPlanner(ai_client)

    async def run(
        self,
        core: CoreCVEData,
        analysis: TechnicalAnalysis | dict[str, object] | None,
        attack: AttackMapping | dict[str, object] | None,
        telemetry: dict[str, Any] | None,
        references: list[str] | None = None,
    ) -> Step6Result:
        """Run Phase A → Phase D. Returns Step6Result(detection_plan, rules, yaml_output)."""
        telemetry = telemetry or {}
        cve_id = getattr(core, "cve_id", None) or "CVE-UNKNOWN"
        family_signature = (
            self._get_attr(analysis, "signature")
            or self._get_attr(analysis, "family")
        )

        # Phase A — Detection Logic Planner
        plan, _plan_source = await self._phase_a_plan(
            cve_id=cve_id,
            analysis=analysis,
            attack=attack,
            telemetry=telemetry,
            references=references,
            family_signature=family_signature,
        )

        # Phase D — Deterministic Sigma Builder
        rules, yaml_output, _level_resolution = build_sigma_rule(
            plan=plan,
            core=core,
            analysis=analysis,
            attack=attack,
            telemetry=telemetry,
            family_signature=family_signature,
        )

        return Step6Result(
            detection_plan=plan,
            rules=rules,
            yaml_output=yaml_output,
        )

    async def _phase_a_plan(
        self,
        cve_id: str,
        analysis: TechnicalAnalysis | dict[str, object] | None,
        attack: AttackMapping | dict[str, object] | None,
        telemetry: dict[str, Any] | None,
        references: list[str] | None,
        family_signature: str | None,
    ) -> tuple[DetectionPlan, str]:
        # Phase A: try AI, then rule-based fallback on failure or low confidence.
        thresholds = loader.get_planner_confidence_thresholds() or {}
        fallback_threshold = float(thresholds.get("fallback_threshold", 0.4))

        ai_enabled = bool(settings.step6_ai_enabled) and self._ai_planner is not None

        if not ai_enabled:
            plan = build_rule_based_plan(
                technical_analysis=self._as_dict(analysis),
                telemetry=telemetry,
                family_signature=family_signature,
                fallback_reason="AI disabled (settings.step6_ai_enabled=False)",
            )
            return plan, "rule_based"

        # Try AI
        try:
            plan = await self._ai_planner.plan(
                cve_id=cve_id,
                analysis=analysis,
                attack=attack,
                telemetry=telemetry,
                references=references,
            )
        except AIServiceError as exc:
            logger.warning("[Step 6] AI planner failed for %s: %s", cve_id, exc)
            plan = build_rule_based_plan(
                technical_analysis=self._as_dict(analysis),
                telemetry=telemetry,
                family_signature=family_signature,
                fallback_reason=f"AI planner failed: {exc}",
            )
            return plan, "rule_based"

        # Confidence gate
        if plan.planner_confidence < fallback_threshold:
            logger.info(
                "[Step 6] AI planner confidence %.2f < %.2f → fallback",
                plan.planner_confidence, fallback_threshold,
            )
            plan = build_rule_based_plan(
                technical_analysis=self._as_dict(analysis),
                telemetry=telemetry,
                family_signature=family_signature,
                fallback_reason=f"AI confidence {plan.planner_confidence:.2f} below threshold {fallback_threshold}",
            )
            return plan, "rule_based"

        return plan, "ai"

    @staticmethod
    def _get_attr(obj: object | None, key: str, default: object | None = None) -> object | None:
        if obj is None:
            return default
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    @staticmethod
    def _as_dict(obj: object | None) -> dict[str, Any] | None:
        if obj is None:
            return None
        if isinstance(obj, dict):
            return obj
        result: dict[str, Any] = {}
        for attr in (
            "mandatory_behaviors", "attack_flow", "family", "signature",
            "vulnerability_class", "vulnerability_type", "execution_surface",
            "delivery_vector", "exploit_vector", "user_interaction",
            "exploit_complexity", "cwe_metadata", "cwe", "references",
        ):
            if hasattr(obj, attr):
                v = getattr(obj, attr)
                if v is not None:
                    result[attr] = v
        return result or None


__all__ = ["Step6Orchestrator"]
