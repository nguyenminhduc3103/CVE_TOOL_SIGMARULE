# AI service for Step 4 telemetry selection: LLM semantic emitter + code-layer resolver.
from __future__ import annotations

import json
import logging
import re
import sys
from pathlib import Path
from typing import Any

from config.settings import settings
from src.domain.models.attack import AttackMapping, TechnicalAnalysis
from src.domain.models.telemetry import (
    DetectionFeature,
    TelemetryAssessment,
)
from src.infrastructure.ai.core import AIServiceError, BaseAIClient
from src.usecases.step_4_telemetry._resolver import (
    map_to_sigma,
    resolve,
    validate_candidate_fields,
    validate_domains,
)
from src.usecases.step_4_telemetry._shared_engines.correlation_advisor import (
    advise_correlation,
)
from src.usecases.step_4_telemetry._shared_engines.logsource_mapper import (
    map_logsources,
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
    _DEFAULT_MODEL = "gemini-2.5-flash-lite"
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
                    max_tokens=16384,
                    response_format_json=True,
                    max_retries=3,
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
                    max_tokens=16384,
                    response_format_json=True,
                    max_retries=3,
                )

            cleaned = self._clean_json(response_text)
            data = json.loads(cleaned)
            validated = TelemetryLLMResponse.model_validate(data)
        except (json.JSONDecodeError, AIServiceError) as exc:
            preview = (response_text or "")[:1200]
            sys.stderr.write(
                f"\n[Step 4 RAW RESPONSE for {cve_id}]\n{preview}\n[/Step 4 RAW]\n"
            )
            sys.stderr.flush()
            preview_log = preview[:500].replace("\n", "\\n")
            logger.error("[Step 4] AI call failed for %s: %s | raw_preview=%s", cve_id, exc, preview_log)
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
        """Run code layer (Knowledge Resolver + Sigma Mapper + Field Mapper +
        Feasibility) → TelemetryAssessment.

        Refactor 2026-07: AI emit semantic domains → resolver map canonical →
        Sigma Mapper sinh SigmaLogsource. Validator match fields với canonical
        field DB. Effective confidence = AI × validation ratio.
        """
        mandatory_behaviors = (analysis.mandatory_behaviors if analysis else None) or []
        techniques = (attack.techniques if attack else None) or []

        # === L2: Validate domains ===
        valid_domains, invalid_domains, domain_warnings = validate_domains(
            llm.candidate_telemetry_domains,
            llm.candidate_semantic_tags,
        )

        # === L3: Knowledge Resolver ===
        execution_surfaces = self._infer_execution_surfaces(analysis)
        attacker_platforms = self._infer_platforms(analysis, attack)
        canonical_bundle = resolve(
            domains=valid_domains,
            execution_surfaces=execution_surfaces,
            attacker_platforms=attacker_platforms,
        )

        # === L5: Sigma Mapper ===
        sigma_logsources, sigma_events, field_name_map = map_to_sigma(
            canonical_bundle.canonical_telemetry,
            canonical_bundle.canonical_fields,
        )

        # Fallback nếu KB không match gì → rule-based mapping
        if not sigma_logsources:
            fallback_logsources, _, _, _ = map_logsources(
                mandatory_behaviors=mandatory_behaviors,
                techniques=techniques,
            )
            sigma_logsources = fallback_logsources

        categories = [item.category for item in sigma_logsources]

        # === L5 (field): validate candidate fields vs canonical field DB ===
        validated_fields, invalid_fields, field_warnings = validate_candidate_fields(
            llm.candidate_canonical_fields,
            canonical_bundle.canonical_fields,
        )

        # required_fields = Sigma-mapped canonical field names
        required_fields = sorted(set(
            [field_name_map.get(f, f) for f in validated_fields]
            + [cf.backends.get("sigma", cf.canonical) for cf in canonical_bundle.canonical_fields]
        ))

        # === Feasibility + effective confidence ===
        feasibility_score, feasibility_breakdown = compute_telemetry_feasibility(
            sigma_logsources=sigma_logsources,
            validated_fields=validated_fields,
            invalid_fields=invalid_fields,
            correlation_required=llm.correlation_required,
            rule_strategy=llm.recommended_rule_strategy,
        )

        # === correlation_required ===
        correlation_required = llm.correlation_required
        if not correlation_required:
            _, _notes = advise_correlation(categories)

        # === Detection axis (AI preferred, fallback rule-based) ===
        detection_axis = llm.detection_axis
        if not detection_axis:
            detection_axis, _ = select_detection_axis(
                mandatory_behaviors, categories, techniques,
            )

        # === Required events (từ canonical telemetry KB) ===
        required_events = llm.required_events or sigma_events or None

        # === Telemetry requirements — structured dict ===
        # Ưu tiên AI emit; nếu rỗng sinh từ canonical telemetry
        telemetry_requirements = llm.telemetry_requirements or {}
        if not telemetry_requirements:
            for ct in canonical_bundle.canonical_telemetry:
                if ct.events:
                    telemetry_requirements[ct.id] = ct.events

        # === Aggregate warnings ===
        tier_warnings: list[str] = []
        valid_stable, valid_conditional, valid_optional, tier_warnings = self._enforce_tier_semantics(
            llm.stable_features,
            llm.conditional_features,
            llm.optional_features,
        )

        all_warnings = (
            domain_warnings
            + field_warnings
            + canonical_bundle.resolution_warnings
            + tier_warnings
        )

        # === AI hallucination ratio (Phase 7): |required - validated| / max(required, 1) ===
        n_required = len(required_fields or [])
        n_validated = len(validated_fields or [])
        ai_hallucination_ratio = (
            round(abs(n_required - n_validated) / max(n_required, 1), 2)
            if n_required else 0.0
        )

        return TelemetryAssessment(
            # AI emit (semantic — NEW)
            candidate_telemetry_domains=valid_domains or None,
            invalid_domains=invalid_domains or None,
            candidate_semantic_tags=llm.candidate_semantic_tags or None,
            candidate_canonical_fields=llm.candidate_canonical_fields or None,
            detection_axis=detection_axis or None,
            primary_axis=llm.primary_axis,
            required_events=required_events,
            telemetry_requirements=telemetry_requirements or None,
            telemetry_gaps=llm.telemetry_gaps or None,
            gap_severity=llm.gap_severity,
            recommended_rule_strategy=llm.recommended_rule_strategy or None,
            correlation_required=correlation_required,
            field_taxonomy_notes=llm.field_taxonomy_notes or None,
            telemetry_confidence=llm.telemetry_confidence,
            stable_features=valid_stable or None,
            conditional_features=valid_conditional or None,
            optional_features=valid_optional or None,
            telemetry_selection_rationale=llm.telemetry_selection_rationale or None,
            ai_hallucination_ratio=ai_hallucination_ratio,
            # Code layer (deterministic) — NEW canonical fields
            canonical_telemetry=[ct.id for ct in canonical_bundle.canonical_telemetry] or None,
            canonical_fields=[cf.canonical for cf in canonical_bundle.canonical_fields] or None,
            skipped_domains=canonical_bundle.skipped_domains or None,
            sigma_logsources=sigma_logsources or None,
            required_fields=required_fields or None,
            validated_fields=validated_fields or None,
            invalid_fields=invalid_fields or None,
            taxonomy_warnings=all_warnings or None,
            field_name_map=field_name_map or None,
            telemetry_feasibility_score=feasibility_score,
            telemetry_feasibility_breakdown=feasibility_breakdown,
            # DEPRECATED backward-compat (set None in new code)
            candidate_logsources=None,
            candidate_fields=None,
            rule_strategy=llm.recommended_rule_strategy or None,
            detection_strategy=llm.recommended_rule_strategy or None,
            observable_detection_features=None,
            # Metadata
            ai_used=True,
            ai_retry_count=0,
            ai_model=self._MODEL,
        )

    @staticmethod
    def _infer_execution_surfaces(analysis: TechnicalAnalysis | None) -> list[str]:
        """Infer execution surfaces từ Step 2's execution_surface enum."""
        if not analysis or not analysis.execution_surface:
            return ["server_side", "client_side", "local"]
        surface = analysis.execution_surface.value if hasattr(analysis.execution_surface, "value") else str(analysis.execution_surface)
        # Map các giá trị phổ biến
        if surface in {"server_side", "server"}:
            return ["server_side"]
        if surface in {"client_side", "client"}:
            return ["client_side"]
        if surface in {"local", "local_privilege_escalation"}:
            return ["local"]
        if surface in {"cloud"}:
            return ["cloud", "server_side"]
        return ["server_side", "client_side", "local"]

    @staticmethod
    def _infer_platforms(
        analysis: TechnicalAnalysis | None,
        attack: AttackMapping | None,
    ) -> list[str]:
        """Infer attacker_platforms từ Step 2.

        Heuristic:
          - vulnerability_class contains 'cloud' → ['aws', 'azure']
          - attack_flow.execution_mechanism contains 'container'/'kubernetes' → thêm
          - Default: ['windows']
        """
        platforms: list[str] = []
        if analysis:
            vclass = ""
            if analysis.vulnerability_class:
                vclass = (
                    analysis.vulnerability_class.value
                    if hasattr(analysis.vulnerability_class, "value")
                    else str(analysis.vulnerability_class)
                )
            vclass_l = vclass.lower()
            if "cloud" in vclass_l:
                platforms.extend(["aws", "azure"])
            if analysis.attack_flow:
                mechanism = (analysis.attack_flow.execution_mechanism or "").lower()
                if "container" in mechanism or "docker" in mechanism:
                    platforms.append("container")
                if "kubernetes" in mechanism or "k8s" in mechanism:
                    platforms.extend(["kubernetes"])
                if "linux" in mechanism:
                    platforms.append("linux")
                if "windows" in mechanism:
                    platforms.append("windows")
        # Default to Windows cho CVE phổ biến nhất
        if not platforms:
            platforms = ["windows"]
        return list(dict.fromkeys(platforms))  # dedup preserve order

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
    def _enforce_tier_semantics(
        stable: list[DetectionFeature] | None,
        conditional: list[DetectionFeature] | None,
        optional: list[DetectionFeature] | None,
    ) -> tuple[list[DetectionFeature], list[DetectionFeature], list[DetectionFeature], list[str]]:
        """Phase 7 (2026-07): Enforce stable_features invariant.

        AI có thể emit feature vào sai tier (vd `Image=\\services.exe` stable — sai,
        vì services.exe là parent process, attacker rename được). Validator đọc
        _STABLE_FEATURE_FIELDS whitelist: nếu stable_features[i].field không thuộc
        set → push xuống conditional + emit warning.

        Returns:
            (new_stable, new_conditional, new_optional, warnings)
        """
        from src.domain.models.telemetry import _STABLE_FEATURE_FIELDS

        warnings: list[str] = []
        new_stable: list[DetectionFeature] = []
        demoted: list[DetectionFeature] = []

        for feat in stable or []:
            if feat.field in _STABLE_FEATURE_FIELDS:
                new_stable.append(feat)
            else:
                # Push xuống conditional
                demoted.append(feat)
                warnings.append(
                    f"stable_field_demoted:{feat.field} → conditional "
                    f"(field not in _STABLE_FEATURE_FIELDS whitelist)"
                )

        new_conditional = list(conditional or []) + demoted
        return new_stable, new_conditional, list(optional or []), warnings

    @staticmethod
    def _clean_json(text: str) -> str:
        """Strip markdown fences / leading prose để json.loads parse được.
        """
        text = text.strip()

        # Step 1: fenced markdown
        fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if fenced:
            return fenced.group(1).strip()

        # Step 2: balanced-brace scanner (string-aware)
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
            # Balanced-brace không khép — JSON bị truncate. Trả về best-effort
            # text từ first '{' trở đi để json.loads raise rõ ràng.
            return text[first:].strip()

        return text[first: last + 1].strip()
