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
    _SHARED_FILE = "_shared_mitre_rules.md"
    _USER_FILE = "analyze_behavior.user.txt"
    _DEFAULT_MODEL = "llama-3.3-70b-versatile"

    def __init__(self, base_client: BaseAIClient) -> None:
        self.client = base_client
        self._MODEL: str = settings.get_analyze_model() or self._DEFAULT_MODEL
        shared_rules_full = (_PROMPTS_DIR / self._SHARED_FILE).read_text(encoding="utf-8")
        shared_rules_phase2 = self._condense_shared_rules_for_phase2(shared_rules_full)
        phase2_template = (_PROMPTS_DIR / self._PHASE2_SYSTEM_FILE).read_text(encoding="utf-8")
        self._phase2_system_prompt = phase2_template.replace(
            "{{SHARED_MITRE_RULES}}", shared_rules_phase2
        )
        self.user_prompt_template = (_PROMPTS_DIR / self._USER_FILE).read_text(encoding="utf-8")
        logger.debug(
            "AIBehaviorService initialized (Phase 2): model=%s",
            self._MODEL,
        )

    async def fetch_attack_mapping(
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
        phase1_output: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Phase 2 AI call — return ATT&CK mapping dict only. Phase 1 output embed làm canonical anchor tránh AV:N→T1190 bias."""
        phase2_system = self._phase2_system_prompt

        description_block = self._build_phase2_description(
            phase1_output or {}, description or ""
        )
        input_payload = {
            "cve_id": cve_id,
            "description": description_block,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector or "N/A",
            "cwe_ids": cwe_ids or [],
            "published_at": published_at or "N/A",
            "modified_at": modified_at or "N/A",
            "poc_references": (poc_references or [])[: self._MAX_POC_REFS],
            "threat_actors": (threat_actors or [])[: self._MAX_THREAT_ACTORS],
        }
        formatted_user = self.user_prompt_template.format(
            input_json=json.dumps(input_payload, ensure_ascii=False, indent=2)
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
        """Strip markdown fences / leading prose để json.loads parse được.
        """
        fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if fenced:
            return fenced.group(1).strip()
        first = text.find("{")
        last = text.rfind("}")
        if first != -1 and last != -1 and last > first:
            return text[first : last + 1].strip()
        return text.strip()

    # Token caps cho prompt input (giữ cho orchestrator cap values).
    _MAX_POC_REFS = 3
    _MAX_THREAT_ACTORS = 5
    _MAX_DESCRIPTION_CHARS = 1200

    @staticmethod
    def _summarize_phase1(phase1_output: dict[str, Any]) -> str:
        """Phase 1 → canonical anchor block (focus Phase 2 vào ATT&CK mapping)."""
        if not phase1_output:
            return "n/a"

        vt = phase1_output.get("vulnerability_type") or "n/a"
        fam = phase1_output.get("family") or "n/a"
        surface = phase1_output.get("execution_surface") or "unknown"
        delivery = phase1_output.get("delivery_vector") or "unknown"
        ui_required = phase1_output.get("user_interaction_required")
        if isinstance(ui_required, bool):
            ui_str = "yes" if ui_required else "no"
        elif ui_required is None:
            ui_str = "unknown"
        else:
            ui_str = str(ui_required)

        af = phase1_output.get("attack_flow") or {}
        entry = af.get("entry_vector") or "n/a"
        exec_mech = af.get("execution_mechanism") or "n/a"
        effects = af.get("observable_side_effects") or []
        effects_str = ", ".join(effects) if effects else "n/a"

        mandatory = phase1_output.get("mandatory_behaviors") or []
        mandatory_str = ", ".join(mandatory) if mandatory else "n/a"

        return (
            f"[Phase 1 summary — CANONICAL FACTS, USE THESE TO DISAMBIGUATE ATT&CK]\n"
            f"(Note: AV:N + PR:N in CVSS vector does NOT imply server-side. "
            f"Use execution_surface / delivery_vector / user_interaction_required "
            f"instead of CVSS heuristic.)\n"
            f"  vulnerability_type:       {vt}\n"
            f"  family:                   {fam}\n"
            f"  execution_surface:        {surface}\n"
            f"  delivery_vector:          {delivery}\n"
            f"  user_interaction_required: {ui_str}\n"
            f"  mandatory_behaviors:      {mandatory_str}\n"
            f"  observable_side_effects:  {effects_str}\n"
            f"  entry_vector:             {entry}\n"
            f"  execution_mechanism:      {exec_mech}"
        )

    @staticmethod
    def _build_phase2_description(
        phase1_output: dict[str, Any] | None,
        nvd_description: str,
    ) -> str:
        """NVD (primary) + Phase 1 summary (anchor). NVD chứa product/keyword triggers (OGNL/Jinja2/eval) giúp chọn sub-technique đúng; Phase 1 tránh AV:N→T1190 bias."""
        nvd_truncated = (nvd_description or "N/A")[: AIBehaviorService._MAX_DESCRIPTION_CHARS]
        phase1_summary = AIBehaviorService._summarize_phase1(phase1_output or {})
        if not phase1_summary or phase1_summary.strip() == "n/a":
            return nvd_truncated
        return f"{nvd_truncated}\n\n--- PHASE 1 ANCHOR ---\n{phase1_summary}"

    @staticmethod
    def _condense_shared_rules_for_phase2(full_rules: str) -> str:
        """Trích phần shared rules CẦN THIẾT cho Phase 2: MEMORY CORRUPTION, EVASIVE INDICATORS ENFORCEMENT, SUBTECHNIQUE DECISION."""
        keep_sections = [
            "MEMORY CORRUPTION → execution-aware discriminator",
            "EVASIVE INDICATORS ENFORCEMENT",
            "SUBTECHNIQUE DECISION",
        ]
        lines = full_rules.split("\n")
        keep: list[str] = []
        in_keep_section = False
        section_indent = ""
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("- "):
                for sec in keep_sections:
                    if stripped.startswith(f"- {sec}"):
                        in_keep_section = True
                        section_indent = line[: len(line) - len(line.lstrip())]
                        keep.append(line)
                        break
                else:
                    in_keep_section = False
            elif in_keep_section:
                if line.startswith(section_indent + "  ") or not stripped:
                    keep.append(line)
                else:
                    in_keep_section = False
        return "\n".join(keep)
