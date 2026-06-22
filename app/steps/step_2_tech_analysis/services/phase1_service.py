"""Phase 1 AI Service - Behavior Analysis (FACTS ONLY).

REFACTOR MOTIVATION:
AI cu (1-shot prompt) bi bias: doc CVSS AV:N + PR:N → tu dong chon T1190
(Exploit Public-Facing Application) cho MOI CVE, ke ca CVE client-side
nhu MSHTML (CVE-2021-40444). Nguyen nhan: AI bi ep vua phan tich behavior
vua map ATT&CK trong cung 1 lan suy nghi → output ATT&CK bi anh huong
boi CVSS heuristic.

GIAI PHAP: tach thanh 2 AI call:
  - Phase 1 (file nay): CHI phan tich FACTS - execution_surface,
    delivery_vector, user_interaction_required, entry_vector,
    execution_mechanism, mandatory_behaviors, ... KHONG co
    tactics/techniques/subtechniques → khong co co hoi bias.
  - Phase 2 (xem ai_service.fetch_attack_mapping): nhan Phase 1 output
    lam canonical anchor, su dung execution_surface de chon ATT&CK
    technique chinh xac.

Single Responsibility: goi LLM + parse JSON. Output la dict thuan
(Pydantic conversion lam o orchestrator.py).

MODEL OPTIMIZATION (Phase 1 vs Phase 2):
  Phase 1 = CLASSIFICATION task (chon execution_surface tu 5 options,
  delivery_vector tu 7 options, bool user_interaction_required).
  Reasoning vua du, khong can model 70B. Dung OpenRouter free model de
  tiet kiem cost:
    PHASE1_AI_MODEL=meta-llama/llama-3.3-70b-instruct:free
    PHASE1_AI_BASE_URL=https://openrouter.ai/api/v1
    PHASE1_AI_API_KEY=sk-or-...

  Phase 2 = REASONING task quan trong (map CVE → ATT&CK taxonomy).
  Giu model manh (Groq llama-3.3-70b).
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.shared.ai.core import AIServiceError, BaseAIClient

logger = logging.getLogger(__name__)


_PROMPTS_DIR = Path(__file__).parent.parent / "prompts"


class AIPhase1Service:
    """Phase 1 AI service - Behavior Analysis only (khong map ATT&CK).

    Two-phase refactor (see module docstring). This service implements
    Phase 1: extract canonical FACTS about CVE execution mechanism.
    Output schema includes 3 new fields:
      - execution_surface (client_side | server_side | local | multi_hop | unknown)
      - delivery_vector   (email_attachment | email_link | web_download |
                            network_protocol | physical | local_execution | unknown)
      - user_interaction_required (bool)

    Model selection (env-driven, no hardcode):
      - PHASE1_AI_MODEL  → primary model for behavior analysis (default: ANALYZE_AI_MODEL).
        RECOMMENDED: OpenRouter free model (e.g. llama-3.3-70b-instruct:free).
      - PHASE1_AI_BASE_URL → API base URL (default: AI_BASE_URL).
      - PHASE1_AI_API_KEY  → API key (default: AI_API_KEY).
      Falls back to legacy Groq llama-3.3-70b-versatile if nothing is set.
    """

    _SYSTEM_FILE = "analyze_behavior_phase1.system.txt"
    _USER_FILE = "analyze_behavior.user.txt"
    # Default model - same as Phase 2 (backward compat).
    # Override via env PHASE1_AI_MODEL to use OpenRouter free model.
    _DEFAULT_MODEL = "llama-3.3-70b-versatile"

    def __init__(self, base_client: BaseAIClient) -> None:
        self.client = base_client
        # Resolve Phase 1 model từ settings (PHASE1_AI_MODEL > ANALYZE_AI_MODEL).
        self._MODEL: str = settings.get_phase1_model() or self._DEFAULT_MODEL
        # Phase 1 system prompt does NOT reference _shared_mitre_rules.md
        # (no ATT&CK mapping in scope here).
        self.system_prompt_template = (
            _PROMPTS_DIR / self._SYSTEM_FILE
        ).read_text(encoding="utf-8")
        self.user_prompt_template = (
            _PROMPTS_DIR / self._USER_FILE
        ).read_text(encoding="utf-8")
        self._models_used: list[str] = []
        # Log model + base_url ở INFO level để user thấy Phase 1 đang dùng model nào
        # (vd Gemini thay vì Groq) trên console output.
        logger.info(
            "[Phase 1] model=%s base_url=%s",
            self._MODEL, settings.get_phase1_base_url() or "(default - same as Phase 2)",
        )

    def _record_model(self, model: str) -> None:
        if model and model not in self._models_used:
            self._models_used.append(model)

    def get_models_used(self) -> list[str]:
        return list(self._models_used)

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
        """Phase 1 AI call - return behavior dict (no ATT&CK mapping).

        Output dict shape (canonical Phase 1 schema):
          {
            "family": str | null,
            "vulnerability_type": str | null,
            "vulnerability_class": str | null,
            "exploit_vector": "remote" | "local" | "unknown" | null,
            "pre_auth": bool | null,
            "remote_exploitable": bool | null,
            "exploit_complexity": "low" | "medium" | "high" | null,
            "execution_surface": "client_side" | "server_side" | "local" |
                                 "multi_hop" | "unknown" | null,
            "delivery_vector": "email_attachment" | "email_link" |
                                "web_download" | "network_protocol" |
                                "physical" | "local_execution" | "unknown" | null,
            "user_interaction_required": bool | null,
            "attack_flow": {"entry_vector", "execution_mechanism",
                             "observable_side_effects"},
            "mandatory_behaviors": list[str],
            "evasive_indicators": list[str],
            "exploit_requirements": list[str],
            "cwe_metadata": {"cwe_ids", "cwe_names", "mapping_confidence"} | null,
            "confidence": float,
            "reasoning": list[str]
          }

        KHONG co: tactics, techniques, subtechniques, mapping_reasons,
        attack_confidence - day la Phase 2 concern.

        Raises:
            AIServiceError: neu AI fail (rate-limit, timeout, JSON parse fail)
        """
        poc_block = self._format_poc_block(poc_references or [])
        threat_actors_block = self._format_threat_actors_block(threat_actors or [])
        # Phase 1 KHONG can CAPEC hints (khong map ATT&CK)

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
            poc_block=poc_block,
            threat_actors_block=threat_actors_block,
            capec_hints_block="",  # Phase 1 ignores CAPEC hints
            phase1_block="",  # Phase 1 has no Phase 1 input (it IS Phase 1)
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
            self._record_model(self._MODEL)
            cleaned_text = self._clean_json(response_text)
            data = json.loads(cleaned_text)
            return data
        except (json.JSONDecodeError, AIServiceError) as e:
            logger.error("AIPhase1Service failed for %s: %s", cve_id, e)
            raise AIServiceError(f"Phase 1 Behavior Analysis failed: {e}") from e

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

    # ------------------------------------------------------------------
    # Optional prompt blocks (PoC refs, threat actors) - giong AIBehaviorService
    # ------------------------------------------------------------------
    _MAX_POC_REFS = 3
    _MAX_THREAT_ACTORS = 5

    @classmethod
    def _format_poc_block(cls, poc_references: list[str]) -> str:
        if not poc_references:
            return ""
        refs = poc_references[:cls._MAX_POC_REFS]
        lines = ["\nPublic PoC References (use as inspiration for exploit mechanism):"]
        for url in refs:
            lines.append(f"  - {url}")
        if len(poc_references) > cls._MAX_POC_REFS:
            lines.append(f"  ... ({len(poc_references) - cls._MAX_POC_REFS} more omitted)")
        return "\n".join(lines) + "\n"

    @classmethod
    def _format_threat_actors_block(cls, threat_actors: list[str]) -> str:
        if not threat_actors:
            return ""
        actors = threat_actors[:cls._MAX_THREAT_ACTORS]
        lines = ["\nThreat Actors observed in the wild (from OTX):"]
        for actor in actors:
            lines.append(f"  - {actor}")
        if len(threat_actors) > cls._MAX_THREAT_ACTORS:
            lines.append(f"  ... ({len(threat_actors) - cls._MAX_THREAT_ACTORS} more omitted)")
        return "\n".join(lines) + "\n"