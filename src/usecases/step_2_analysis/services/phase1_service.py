"""Phase 1 AI Service - Behavior Analysis (FACTS ONLY). Tách riêng khỏi Phase 2 ATT&CK mapping để tránh bias do CVSS heuristic (vd CVE client-side MSHTML).

Major refactor (round-2):
- 5 fields CVSS-deterministic (exploit_vector, pre_auth, remote_exploitable,
  exploit_complexity, user_interaction_required) được fill bằng CVSS parser
  TRƯỚC khi gọi AI — AI không reason, không trả về các field này.
- Input payload thu gọn xuống 7 fields:
  cve_id, description, cvss_score, cvss_vector, cwe_ids (5 base)
    + poc_description, poc_request_info (2 PoC details từ nuclei crawl)
  Bỏ: cpes, references, published_at, modified_at, poc_references (URL list),
       threat_actors.
"""
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
# Short-form ontology file (110 primitive behaviors, no aliases / no capecs).
# Built by scripts/build_mandatory_behavior_ontology.py from the full ontology.
# Inject into system prompt at {mandatory_behaviors_block} so the LLM selects
# `mandatory_behaviors` from this closed vocabulary instead of inventing tokens.
_ONTOLOGY_FILE = Path(".cache/ontology/mandatory_behavior_ontology.json")
_EMPTY_ONTOLOGY_PLACEHOLDER = "(no behaviors available — return empty list)"


class AIPhase1Service:
    """Phase 1 AI service - Behavior Analysis only (khong map ATT&CK). Output schema: execution_surface, delivery_vector, mandatory_behaviors, evasive_indicators, exploit_requirements, reasoning, confidence."""

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
        # Load short-form ontology + render bullet block at init.
        # File is small (~15 KB) so re-reading per-CVE (orchestrator instantiates
        # this service per CVE) costs negligible I/O; intentional for simplicity.
        self._mandatory_behaviors_block = self._load_ontology_block()
        # Log model + base_url + ontology size để user thấy Phase 1 đang dùng gì.
        logger.info(
            "[Phase 1] model=%s base_url=%s ontology_block_lines=%d",
            self._MODEL,
            settings.get_phase1_base_url() or "(default - same as Phase 2)",
            self._mandatory_behaviors_block.count("\n") + 1
            if self._mandatory_behaviors_block
            else 0,
        )

    async def fetch_behavior(
        self,
        cve_id: str,
        description: str,
        cvss_score: float,
        cvss_vector: str,
        cwe_ids: list[str],
        poc_description: str | None = None,
        poc_request_info: dict | None = None,
    ) -> dict[str, Any]:
        """Phase 1 AI call - return behavior dict (no ATT&CK mapping).

        Input payload đã thu gọn: 5 base + 2 PoC details (không còn references,
        cpes, published_at, modified_at, threat_actors, poc_references URL list).
        PoC details populate từ nuclei crawl evidence:
          - poc_description: documentation text từ record type="documentation"
          - poc_request_info: dict {method, path, body} từ record type="network"
        """
        input_payload = {
            "cve_id": cve_id,
            "description": description or "N/A",
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector or "N/A",
            "cwe_ids": cwe_ids or [],
            "poc_description": poc_description or "",
            "poc_request_info": poc_request_info or {},
        }
        formatted_user = self.user_prompt_template.format(
            input_json=json.dumps(input_payload, ensure_ascii=False, indent=2),
        )

        # Resolve system prompt with the rendered ontology block injected at
        # {mandatory_behaviors_block}. Done per-call (not cached at init) so a
        # future build_ontology rebuild during a long-lived process picks up
        # without a restart. Cheap: pure str.format on a ~6-8K-token template.
        system_prompt_resolved = self.system_prompt_template.format(
            mandatory_behaviors_block=self._mandatory_behaviors_block,
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
                    system_prompt=system_prompt_resolved,
                    user_prompt=formatted_user,
                    model=self._MODEL,
                    override_api_key=phase1_keys[0],
                    override_base_url=phase1_base_url,
                )
            else:
                # Fallback: dung chung primary client (backward compat)
                logger.info("[Phase 1] Calling %s via primary client (no separate provider)", self._MODEL)
                response_text = await self.client.call_llm(
                    system_prompt=system_prompt_resolved,
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

    @staticmethod
    def _load_ontology_block() -> str:
        """Load short-form ontology JSON, render as bullet list for system prompt.

        Returns an empty placeholder if the file is missing or invalid so the
        service still functions (LLM will see explicit "return empty list"
        instruction and produce a degraded-but-valid response). Never raises.
        """
        try:
            data = json.loads(_ONTOLOGY_FILE.read_text(encoding="utf-8"))
        except FileNotFoundError:
            logger.warning(
                "[Phase 1] Ontology file not found at %s; using empty vocabulary",
                _ONTOLOGY_FILE,
            )
            return _EMPTY_ONTOLOGY_PLACEHOLDER
        except json.JSONDecodeError as e:
            logger.error(
                "[Phase 1] Invalid ontology JSON at %s: %s", _ONTOLOGY_FILE, e,
            )
            return _EMPTY_ONTOLOGY_PLACEHOLDER

        lines: list[str] = []
        for entry in data.get("entries", []):
            token = (entry.get("primitive") or "").strip()
            if not token:
                continue
            desc = (entry.get("description") or "").strip()
            lines.append(f"- `{token}`: {desc}" if desc else f"- `{token}`")
        return "\n".join(lines) if lines else _EMPTY_ONTOLOGY_PLACEHOLDER
