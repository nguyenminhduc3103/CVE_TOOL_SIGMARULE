"""AI Service cho Step 4 — Telemetry Selector.

Refactor 2026-07: AI emit ABSTRACT/SEMANTIC terms, code layer enforce schema.

  AI emit (loose)           code layer (deterministic)
  ─────────────────────     ────────────────────────────
  candidate_logsources  →   logsource_mapper   → sigma_logsources
  candidate_fields      →   taxonomy_validator → required_fields
                                                  ↘ validated_fields
                                                  ↘ invalid_fields
                                                  ↘ taxonomy_warnings
  (n/a)                  →   telemetry_feasibility engine
                                                  ↘ telemetry_feasibility_score
                                                  ↘ telemetry_feasibility_breakdown

Single Responsibility: gọi LLM + parse JSON + validate contract. Output là
TelemetryAssessment với AI-emit + code-layer fields combined.

Fallback: Nếu AI fail (rate-limit, JSON parse, contract validation) → fallback
sang _shared_engines rule-based.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from config.settings import settings
from src.domain.models.attack import AttackMapping, TechnicalAnalysis
from src.domain.models.telemetry import (
    DetectionFeatures,
    TelemetryAssessment,
    TelemetryRequirements,
)
from src.infrastructure.ai.core import AIServiceError, BaseAIClient
from src.usecases.step_4_telemetry._shared_engines.correlation_advisor import (
    advise_correlation,
)
from src.usecases.step_4_telemetry._shared_engines.field_mapper import (
    map_required_fields,
)
from src.usecases.step_4_telemetry._shared_engines.logsource_mapper import (
    map_logsources,
    map_logsources_from_candidates,
)
from src.usecases.step_4_telemetry._shared_engines.taxonomy_validator import (
    validate_fields_by_logsources,
)
from src.usecases.step_4_telemetry._shared_engines.telemetry_feasibility import (
    compute_telemetry_feasibility,
)
from src.usecases.step_4_telemetry._shared_engines.telemetry_selector import (
    select_detection_axis,
)
from src.usecases.step_4_telemetry.models.llm_contract import TelemetryLLMResponse

logger = logging.getLogger(__name__)


_PROMPTS_DIR = Path(__file__).parent.parent / "prompts"


class AITelemetrySelector:
    """AI service cho Step 4 — Telemetry selection.

    Mirror pattern step_2_analysis/services/phase1_service.py:
      - resolve model + base_url từ settings
      - gọi LLM với system + user prompt
      - parse JSON (strip markdown fence)
      - validate TelemetryLLMResponse
      - chạy code layer (mapper + validator + feasibility) → TelemetryAssessment

    Fail ở bất kỳ bước nào → raise AIServiceError để telemetry_stage fallback rule-based.
    """

    _SYSTEM_FILE = "select_telemetry.system.txt"
    _USER_FILE = "select_telemetry.user.txt"
    # Default: Gemini 2.5 Flash (1M TPM free). Override via env STEP4_AI_MODEL.
    _DEFAULT_MODEL = "gemini-2.5-flash"
    # Cap description length tránh tràn TPM khi CVE có description dài.
    _MAX_DESCRIPTION_CHARS = 1200

    def __init__(self, base_client: BaseAIClient) -> None:
        self.client = base_client
        self._MODEL: str = settings.get_step4_model() or self._DEFAULT_MODEL
        self._system_prompt_template = (
            _PROMPTS_DIR / self._SYSTEM_FILE
        ).read_text(encoding="utf-8")
        self._user_prompt_template = (
            _PROMPTS_DIR / self._USER_FILE
        ).read_text(encoding="utf-8")
        logger.info(
            "[Step 4] AI service initialized: model=%s base_url=%s",
            self._MODEL,
            settings.get_step4_base_url() or "(default)",
        )

    async def select(
        self,
        cve_id: str,
        analysis: TechnicalAnalysis,
        attack: AttackMapping,
    ) -> TelemetryAssessment:
        """Run AI telemetry selection.

        Raises:
            AIServiceError: Nếu AI fail (rate-limit, JSON parse, validation).
        """
        input_payload = self._build_input_payload(cve_id, analysis, attack)
        formatted_user = self._user_prompt_template.format(
            input_json=json.dumps(input_payload, ensure_ascii=False, indent=2),
        )

        # Phase 4: Phase 4 có thể dùng provider riêng (vd Gemini thay vì Groq).
        has_separate_provider = self._has_separate_provider()
        try:
            if has_separate_provider:
                step4_keys = settings.get_step4_api_keys()
                if not step4_keys:
                    raise AIServiceError(
                        "Step 4 separate provider configured but no API key."
                    )
                logger.info(
                    "[Step 4] Calling %s via separate provider",
                    self._MODEL,
                )
                response_text = await self.client.call_llm(
                    system_prompt=self._system_prompt_template,
                    user_prompt=formatted_user,
                    model=self._MODEL,
                    override_api_key=step4_keys[0],
                    override_base_url=settings.get_step4_base_url(),
                )
            else:
                logger.info(
                    "[Step 4] Calling %s via primary client",
                    self._MODEL,
                )
                response_text = await self.client.call_llm(
                    system_prompt=self._system_prompt_template,
                    user_prompt=formatted_user,
                    model=self._MODEL,
                )

            cleaned = self._clean_json(response_text)
            data = json.loads(cleaned)
            validated = TelemetryLLMResponse.model_validate(data)
        except (json.JSONDecodeError, AIServiceError) as exc:
            logger.error(
                "[Step 4] AI call failed for %s: %s",
                cve_id, exc,
            )
            raise AIServiceError(f"Step 4 Telemetry selection failed: {exc}") from exc
        except Exception as exc:
            logger.error(
                "[Step 4] AI validation failed for %s: %s",
                cve_id, exc,
            )
            raise AIServiceError(
                f"Step 4 Telemetry selection validation failed: {exc}"
            ) from exc

        # AI emit OK → run code layer → TelemetryAssessment.
        return self._build_assessment(cve_id, analysis, attack, validated)

    def _build_input_payload(
        self,
        cve_id: str,
        analysis: TechnicalAnalysis,
        attack: AttackMapping,
    ) -> dict[str, Any]:
        """Build JSON payload for user prompt. Truncate description tránh tràn TPM."""
        flow = analysis.attack_flow if analysis else None
        description = (analysis.vulnerability_type or "") if analysis else ""
        if flow and flow.observable_side_effects:
            description = (description + "\n" + " | ".join(flow.observable_side_effects))[: self._MAX_DESCRIPTION_CHARS]

        return {
            "cve_id": cve_id,
            "vulnerability_class": (
                analysis.vulnerability_class.value if analysis and analysis.vulnerability_class else None
            ),
            "vulnerability_type": analysis.vulnerability_type if analysis else None,
            "execution_surface": analysis.execution_surface if analysis else None,
            "delivery_vector": analysis.delivery_vector if analysis else None,
            "user_interaction_required": (
                analysis.user_interaction_required if analysis else None
            ),
            "mandatory_behaviors": (analysis.mandatory_behaviors or []) if analysis else [],
            "evasive_indicators": (analysis.evasive_indicators or []) if analysis else [],
            "exploit_requirements": (analysis.exploit_requirements or []) if analysis else [],
            "cwe_ids": (
                analysis.cwe_metadata.cwe_ids if analysis and analysis.cwe_metadata else None
            ),
            "attack_flow": {
                "entry_vector": flow.entry_vector if flow else None,
                "execution_mechanism": flow.execution_mechanism if flow else None,
                "observable_side_effects": (
                    flow.observable_side_effects if flow else None
                ),
            } if flow else None,
            "attck_tactics": (attack.tactics or []) if attack else [],
            "attck_techniques": (attack.techniques or []) if attack else [],
            "attck_subtechniques": (attack.subtechniques or []) if attack else [],
            "description_short": description or None,
        }

    def _build_assessment(
        self,
        cve_id: str,
        analysis: TechnicalAnalysis,
        attack: AttackMapping,
        llm: TelemetryLLMResponse,
    ) -> TelemetryAssessment:
        """Run code layer (mapper + validator + feasibility) → TelemetryAssessment.

        Code layer DETERMINISTIC — không phụ thuộc LLM. Nếu AI emit sai category/field,
        validator drop ra `invalid_fields` + `taxonomy_warnings`.
        """
        mandatory_behaviors = (analysis.mandatory_behaviors if analysis else None) or []
        techniques = (attack.techniques if attack else None) or []

        # 1. Map candidate_logsources → sigma_logsources
        sigma_logsources = map_logsources_from_candidates(
            candidate_logsources=llm.candidate_logsources,
            mandatory_behaviors=mandatory_behaviors,
            techniques=techniques,
        )

        # Fallback nếu AI emit candidate quá ít → rule-based mapping
        if not sigma_logsources:
            fallback_logsources, _, _, _ = map_logsources(
                mandatory_behaviors=mandatory_behaviors,
                techniques=techniques,
            )
            sigma_logsources = fallback_logsources

        categories = [item.category for item in sigma_logsources]

        # 2. Validate candidate_fields against taxonomy
        validated_fields, invalid_fields, taxonomy_warnings = (
            validate_fields_by_logsources(categories, llm.candidate_fields)
        )

        # required_fields = validated ∪ whitelist theo category (đảm bảo ≥ validated_fields)
        whitelist_fields = map_required_fields(categories, mandatory_behaviors)
        required_fields_set = set(validated_fields) | set(whitelist_fields)
        required_fields = sorted(
            required_fields_set,
            key=lambda f: (f not in validated_fields, f),
        )

        # 3. Compute telemetry_feasibility_score (rule-based)
        feasibility_score, feasibility_breakdown = compute_telemetry_feasibility(
            sigma_logsources=sigma_logsources,
            validated_fields=validated_fields,
            invalid_fields=invalid_fields,
            candidate_logsources=llm.candidate_logsources,
            correlation_required=llm.correlation_required,
            rule_strategy=llm.rule_strategy,
        )

        # 4. correlation_required: AI không set → correlation_advisor fallback
        correlation_required = llm.correlation_required
        if not correlation_required:
            _, _notes = advise_correlation(categories)

        # 5. Pre/post/impact detection (legacy fields, derived from behaviors)
        pre_exploit_detection = [
            b for b in mandatory_behaviors
            if b in {"public_facing_exploit", "web_request", "auth_bypass"}
        ]
        post_exploit_detection = [
            b for b in mandatory_behaviors
            if b in {"process_creation", "file_write", "registry_modification",
                     "image_load", "network_callback"}
        ]
        impact_detection = [
            b for b in mandatory_behaviors
            if b in {"privilege_escalation", "webshell_drop", "tool_download"}
        ]

        # 6. Detection axis: ưu tiên AI emit, fallback rule-based
        detection_axis = llm.detection_axis
        if not detection_axis:
            detection_axis, _ = select_detection_axis(
                mandatory_behaviors, categories, techniques,
            )

        # 7. Required events (Sysmon EID) — AI emit
        required_events = llm.required_events or None

        return TelemetryAssessment(
            # AI emit (loose)
            candidate_logsources=llm.candidate_logsources or None,
            candidate_fields=llm.candidate_fields or None,
            detection_axis=detection_axis or None,
            primary_axis=llm.primary_axis,
            required_events=required_events,
            # Schema định nghĩa telemetry_requirements là str (text).
            telemetry_requirements=llm.telemetry_requirements or None,
            telemetry_gaps=llm.telemetry_gaps or None,
            gap_severity=llm.gap_severity,
            rule_strategy=llm.rule_strategy or None,
            detection_strategy=llm.rule_strategy or None,  # alias backward compat
            correlation_required=correlation_required,
            field_taxonomy_notes=llm.field_taxonomy_notes or None,
            telemetry_confidence=llm.telemetry_confidence,
            observable_detection_features=(
                llm.observable_detection_features
                if llm.observable_detection_features
                and not _is_empty_detection_features(llm.observable_detection_features)
                else None
            ),
            # Code layer (deterministic)
            sigma_logsources=sigma_logsources or None,
            required_fields=required_fields or None,
            validated_fields=validated_fields or None,
            invalid_fields=invalid_fields or None,
            taxonomy_warnings=taxonomy_warnings or None,
            telemetry_feasibility_score=feasibility_score,
            telemetry_feasibility_breakdown=feasibility_breakdown,
            # Legacy fields
            pre_exploit_detection=pre_exploit_detection or None,
            post_exploit_detection=post_exploit_detection or None,
            impact_detection=impact_detection or None,
            # Metadata
            ai_used=True,
            ai_retry_count=0,
            ai_model=self._MODEL,
        )

    def _has_separate_provider(self) -> bool:
        """Step 4 có provider riêng (vd Gemini) khác primary (Groq)."""
        main_keys = settings.get_api_keys()
        main_base_url = getattr(settings, "ai_base_url", None)
        step4_keys = settings.get_step4_api_keys()
        step4_base_url = settings.get_step4_base_url()
        return (
            (step4_keys != main_keys)
            or (step4_base_url != main_base_url)
        )

    @staticmethod
    def _clean_json(text: str) -> str:
        """Strip markdown fences / leading prose để json.loads parse được."""
        fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if fenced:
            return fenced.group(1).strip()
        first = text.find("{")
        last = text.rfind("}")
        if first != -1 and last != -1 and last > first:
            return text[first: last + 1].strip()
        return text.strip()


def _is_empty_detection_features(features: DetectionFeatures) -> bool:
    """True nếu cả 3 tier đều rỗng."""
    return (
        not features.stable_features
        and not features.observable_features
        and not features.optional_features
    )
