"""AI Service cho Step 2 - Technical & ATT&CK Analyzer.

Chỉ làm 1 việc: gọi LLM + parse JSON thành dict thuần. KHÔNG tạo Pydantic,
KHÔNG có fallback logic (orchestrator lo phần đó).

Returns:
    dict (raw AI JSON đã clean) hoặc raises AIServiceError nếu fail.
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


class AIBehaviorService:
    """Service gọi AI để phân tích CVE behavior + ATT&CK mapping.

    Single Responsibility: gọi LLM + parse JSON. Output là dict thuần (Pydantic
    conversion làm ở orchestrator).

    Model selection (env-driven): ANALYZE_AI_MODEL cho analyze call,
    RETRY_AI_MODEL cho partial-fill retry. Cả 2 fallback về default nếu
    env unset → backward compat.
    """

    _SYSTEM_FILE = "analyze_behavior.system.txt"
    _PHASE2_SYSTEM_FILE = "analyze_attack_mapping.system.txt"
    _SHARED_FILE = "_shared_mitre_rules.md"
    _USER_FILE = "analyze_behavior.user.txt"
    # Default analyze model — Groq llama-3.3-70b-versatile, 6K TPM free tier.
    # Override via env ANALYZE_AI_MODEL.
    _DEFAULT_MODEL = "llama-3.3-70b-versatile"
    # Default retry model — Google Gemini 2.5 Flash, 1M TPM (tránh Groq 6K TPM
    # ceiling trên retry payloads lớn). Override via env RETRY_AI_MODEL.
    _DEFAULT_RETRY_MODEL = "gemini-2.5-flash"

    def __init__(self, base_client: BaseAIClient) -> None:
        self.client = base_client
        # Resolve model names from settings (env > legacy field > default).
        # Getter trả về None nếu env empty string → fallback default.
        self._MODEL: str = settings.get_analyze_model() or self._DEFAULT_MODEL
        self._RETRY_MODEL: str = settings.get_retry_model() or self._DEFAULT_RETRY_MODEL
        # Load shared MITRE rules 1 lần. Phase 1 (1-shot) dùng full rules.
        # Phase 2 dùng condensed rules (~30% size) để tránh vượt Groq 12K TPM
        # (vd CVE-2021-3156: 25 refs + 32 CPEs + full rules = 12K).
        shared_rules_full = (_PROMPTS_DIR / self._SHARED_FILE).read_text(encoding="utf-8")
        shared_rules_phase2 = self._condense_shared_rules_for_phase2(shared_rules_full)
        analyze_template = (_PROMPTS_DIR / self._SYSTEM_FILE).read_text(encoding="utf-8")
        # Replace placeholder tại construction time → call_llm nhận full prompt
        # (byte-identical với pre-split version).
        self.system_prompt_template = analyze_template.replace(
            "{{SHARED_MITRE_RULES}}", shared_rules_full
        )
        # Phase 2: riêng system prompt focused chỉ ATT&CK mapping.
        phase2_template = (_PROMPTS_DIR / self._PHASE2_SYSTEM_FILE).read_text(encoding="utf-8")
        self._phase2_system_prompt = phase2_template.replace(
            "{{SHARED_MITRE_RULES}}", shared_rules_phase2
        )
        self.user_prompt_template = (_PROMPTS_DIR / self._USER_FILE).read_text(encoding="utf-8")
        # Track cả analyze + retry models dùng trong run (instance-scoped, mỗi
        # CVE call fresh). Order-preserving + dedup: analyze luôn trước, retry
        # chỉ append nếu `record_retry_model()` được gọi.
        self._models_used: list[str] = []
        logger.debug(
            "AIBehaviorService initialized: analyze=%s retry=%s",
            self._MODEL, self._RETRY_MODEL,
        )

    def _record_model(self, model: str) -> None:
        """Append `model` to `_models_used` nếu chưa có."""
        if model and model not in self._models_used:
            self._models_used.append(model)

    def record_retry_model(self) -> None:
        """Mark retry model đã dùng. Call TRƯỚC retry call để hiển thị dù retry fail."""
        self._record_model(self._RETRY_MODEL)

    def get_models_used(self) -> list[str]:
        """Deduplicated + order-preserved list models đã dùng cho CVE này."""
        return list(self._models_used)

    async def fetch_raw_response(
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
        capec_hints_by_cwe: dict[str, list[dict]] | None = None,
        phase1_output: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Gọi AI + parse JSON. Return dict thuần.

        Args:
            poc_references: Optional PoC URLs (max 3 in prompt). Giúp AI narrow
                down exploit mechanism khi description vague (vd Log4Shell →
                PoC shows JNDI lookup chain).
            threat_actors: Optional threat actor names từ OTX.
            capec_hints_by_cwe: Optional dict {CWE-id: [CAPEC hint dicts]}.
                INSPIRATION ONLY (không phải ground truth).
            phase1_output: Optional Phase 1 behavior dict (two-phase refactor).
                Khi có, AI dùng `execution_surface` / `delivery_vector` /
                `user_interaction_required` làm canonical anchor tránh AV:N→T1190 bias.

        Raises:
            AIServiceError: nếu AI fail (rate-limit, timeout, JSON parse fail).
        """
        # Build optional prompt blocks. Empty string = block omitted (graceful fallback).
        poc_block = self._format_poc_block(poc_references or [])
        threat_actors_block = self._format_threat_actors_block(threat_actors or [])
        capec_hints_block = self._format_capec_hints_block(capec_hints_by_cwe or {})
        phase1_block = self._format_phase1_block(phase1_output or {})

        formatted_user = self.user_prompt_template.format(
            cve_id=cve_id,
            description=(description or "N/A")[: self._MAX_DESCRIPTION_CHARS],
            cvss_score=cvss_score,
            cvss_vector=cvss_vector or "N/A",
            cwe_ids=", ".join(cwe_ids) if cwe_ids else "None",
            cpes=", ".join(cpes[:self._MAX_CPES]) if cpes else "None",
            references=self._format_references(references),
            published_at=published_at or "N/A",
            modified_at=modified_at or "N/A",
            poc_block=poc_block,
            threat_actors_block=threat_actors_block,
            capec_hints_block=capec_hints_block,
            phase1_block=phase1_block,
        )

        try:
            response_text = await self.client.call_llm(
                system_prompt=self.system_prompt_template,
                user_prompt=formatted_user,
                model=self._MODEL,
            )
            # Record analyze model CHỈ sau khi dispatch thành công (call không raise).
            # Retry model được record riêng bởi orchestrator qua record_retry_model().
            self._record_model(self._MODEL)
            cleaned_text = self._clean_json(response_text)
            data = json.loads(cleaned_text)
            return data
        except (json.JSONDecodeError, AIServiceError) as e:
            logger.error("AIBehaviorService failed for %s: %s", cve_id, e)
            raise AIServiceError(f"Behavior Analysis failed: {e}") from e

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
        capec_hints_by_cwe: dict[str, list[dict]] | None = None,
        phase1_output: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Phase 2 AI call - return ATT&CK mapping dict only.

        Invoked AFTER Phase 1. Phase 1 output được embed làm canonical anchor
        tránh AV:N→T1190 bias. No behavior fields (Phase 1 lo phần đó).

        Output dict shape:
          {
            "tactics": list[str],
            "techniques": list[str],
            "subtechniques": list[str],
            "attack_confidence": float,
            "mapping_reasons": list[str]
          }

        Raises:
            AIServiceError: nếu AI fail
        """
        phase2_system = self._phase2_system_prompt

        poc_block = self._format_poc_block(poc_references or [])
        threat_actors_block = self._format_threat_actors_block(threat_actors or [])
        capec_hints_block = self._format_capec_hints_block(capec_hints_by_cwe or {})
        phase1_block = self._format_phase1_block(phase1_output or {})

        # Phase 2 cần CẢ NVD description (chứa keyword "OGNL"/"WebWork"/"Jinja2"
        # giúp LLM chọn sub-technique T1059.xxx đúng) LẪN Phase 1 summary (anchor
        # tránh AV:N→T1190 bias). Bỏ references/CPEs — chỉ cần cho Sigma ở Step 3.
        description_block = self._build_phase2_description(
            phase1_output or {}, description or ""
        )
        formatted_user = self.user_prompt_template.format(
            cve_id=cve_id,
            description=description_block,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector or "N/A",
            cwe_ids=", ".join(cwe_ids) if cwe_ids else "None",
            cpes="(omitted in Phase 2 - not needed for ATT&CK mapping)",
            references="(omitted in Phase 2 - not needed for ATT&CK mapping)",
            published_at=published_at or "N/A",
            modified_at=modified_at or "N/A",
            poc_block=poc_block,
            threat_actors_block=threat_actors_block,
            capec_hints_block=capec_hints_block,
            phase1_block=phase1_block,
        )

        try:
            response_text = await self.client.call_llm(
                system_prompt=phase2_system,
                user_prompt=formatted_user,
                model=self._MODEL,
            )
            self._record_model(self._MODEL)
            cleaned_text = self._clean_json(response_text)
            data = json.loads(cleaned_text)
            return data
        except (json.JSONDecodeError, AIServiceError) as e:
            logger.error("AIBehaviorService.fetch_attack_mapping failed for %s: %s", cve_id, e)
            raise AIServiceError(f"Phase 2 Attack Mapping failed: {e}") from e

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

    # Optional prompt blocks (PoC refs, threat actors, CAPEC hints).
    # Cap length để giữ user prompt < 4K tokens (Groq 6K TPM ceiling).
    _MAX_POC_REFS = 3
    _MAX_THREAT_ACTORS = 5
    _MAX_REFERENCES = 10
    _MAX_CPES = 10
    _MAX_DESCRIPTION_CHARS = 800

    @classmethod
    def _format_poc_block(cls, poc_references: list[str]) -> str:
        """Build 'Public PoC References' block. Empty khi không có PoC (block omitted)."""
        if not poc_references:
            return ""
        refs = poc_references[:cls._MAX_POC_REFS]
        lines = ["\nPublic PoC References (use as inspiration for exploit mechanism):"]
        for url in refs:
            lines.append(f"  - {url}")
        if len(poc_references) > cls._MAX_POC_REFS:
            lines.append(f"  ... ({len(poc_references) - cls._MAX_POC_REFS} more omitted)")
        lines.append("")
        return "\n".join(lines)

    @classmethod
    def _format_references(cls, references: list[str]) -> str:
        """Cap references list tránh vượt Groq TPM.

        CVE thực tế có thể 25+ URLs (vd CVE-2021-3156); cap 10 URLs đầu + ghi
        chú số còn lại. AI chỉ cần vài URLs để hiểu context.
        """
        if not references:
            return "None"
        capped = references[: cls._MAX_REFERENCES]
        body = "\n".join(capped)
        if len(references) > cls._MAX_REFERENCES:
            body += f"\n  ... ({len(references) - cls._MAX_REFERENCES} more omitted)"
        return body

    @classmethod
    def _format_threat_actors_block(cls, threat_actors: list[str]) -> str:
        """Build 'Threat Actors' block. Empty khi OTX không trả actor nào."""
        if not threat_actors:
            return ""
        actors = threat_actors[:cls._MAX_THREAT_ACTORS]
        lines = ["\nThreat Actors (observed by AlienVault OTX):"]
        for name in actors:
            lines.append(f"  - {name}")
        if len(threat_actors) > cls._MAX_THREAT_ACTORS:
            lines.append(f"  ... ({len(threat_actors) - cls._MAX_THREAT_ACTORS} more omitted)")
        lines.append("")
        return "\n".join(lines)

    @classmethod
    def _format_capec_hints_block(cls, capec_hints_by_cwe: dict[str, list[dict]]) -> str:
        """Build 'CAPEC hints' block. INSPIRATION ONLY (không phải ground truth)."""
        if not capec_hints_by_cwe:
            return ""
        lines = [
            "\nCAPEC hints (INSPIRATION, NOT requirements — use only if CVE signals support):"
        ]
        for cwe_id, hints in capec_hints_by_cwe.items():
            if not hints:
                continue
            lines.append(f"  {cwe_id}:")
            for h in hints:
                capec_id = h.get("capec_id", "?")
                name = h.get("name", "")
                likelihood = h.get("likelihood") or "?"
                related = h.get("related_techniques") or []
                related_str = ", ".join(related) if related else "no direct ATT&CK mapping"
                lines.append(
                    f"    - {capec_id} ({name}): likelihood={likelihood}, ATT&CK hints=[{related_str}]"
                )
        lines.append("")
        return "\n".join(lines)

    # Phase 1 anchor (two-phase refactor)

    @classmethod
    def _format_phase1_block(cls, phase1_output: dict[str, Any]) -> str:
        """Build 'Phase 1 canonical facts' block cho Phase 2 prompt.

        Phase 2 ANCHOR trên: execution_surface, delivery_vector,
        user_interaction_required, + entry_vector/execution_mechanism.

        Empty string khi phase1_output rỗng (single-shot mode backward compat).
        """
        if not phase1_output:
            return ""

        surface = phase1_output.get("execution_surface") or "unknown"
        delivery = phase1_output.get("delivery_vector") or "unknown"
        ui_required = phase1_output.get("user_interaction_required")
        if isinstance(ui_required, bool):
            ui_str = "yes" if ui_required else "no"
        elif ui_required is None:
            ui_str = "unknown"
        else:
            ui_str = str(ui_required)

        attack_flow = phase1_output.get("attack_flow") or {}
        entry = attack_flow.get("entry_vector") or "n/a"
        exec_mech = attack_flow.get("execution_mechanism") or "n/a"

        lines = [
            "\n# PHASE 1 OUTPUT (CANONICAL FACTS - USE THESE TO DISAMBIGUATE ATT&CK)",
            "(Note: AV:N + PR:N in CVSS vector does NOT imply server-side. Use these facts instead.)",
            f"  execution_surface:        {surface}",
            f"  delivery_vector:          {delivery}",
            f"  user_interaction_required: {ui_str}",
            f"  entry_vector (Phase 1):   {entry}",
            f"  execution_mechanism (Phase 1): {exec_mech}",
            "",
        ]
        return "\n".join(lines)

    @staticmethod
    def _summarize_phase1(phase1_output: dict[str, Any]) -> str:
        """Tóm tắt Phase 1 thành description ngắn cho Phase 2 user prompt.

        Gồm: vulnerability_type + family + entry_vector + execution_mechanism.
        Phase 2 chỉ cần ngắn gọn (focus vào ATT&CK mapping, không cần full).
        """
        if not phase1_output:
            return "n/a"
        vt = phase1_output.get("vulnerability_type") or "n/a"
        fam = phase1_output.get("family") or "n/a"
        af = phase1_output.get("attack_flow") or {}
        entry = af.get("entry_vector") or "n/a"
        exec_mech = af.get("execution_mechanism") or "n/a"
        return (
            f"[Phase 1 summary]\n"
            f"  vulnerability_type: {vt}\n"
            f"  family:             {fam}\n"
            f"  entry_vector:       {entry}\n"
            f"  execution_mechanism: {exec_mech}"
        )

    @staticmethod
    def _build_phase2_description(
        phase1_output: dict[str, Any] | None,
        nvd_description: str,
    ) -> str:
        """Build Phase 2 description: NVD (primary) + Phase 1 summary (anchor).

        Why BOTH (generalizable, không code-injection specific):
        - NVD description: chứa product/keyword triggers (vd "OGNL",
          "WebWork", "Jinja2", "eval") giúp LLM chọn sub-technique đúng
          (T1059.007 JS, T1059.006 Python). Thiếu keywords → LLM anchor
          vào T1190 generic, miss T1059.xxx.
        - Phase 1 summary: canonical facts tránh AV:N→T1190 bias.

        NVD rỗng/ngắn → return Phase 1 summary alone. Truncate NVD
        portion to _MAX_DESCRIPTION_CHARS.
        """
        nvd_truncated = (nvd_description or "N/A")[: AIBehaviorService._MAX_DESCRIPTION_CHARS]
        phase1_summary = AIBehaviorService._summarize_phase1(phase1_output or {})
        if not phase1_summary or phase1_summary.strip() == "n/a":
            return nvd_truncated
        return f"{nvd_truncated}\n\n--- PHASE 1 ANCHOR ---\n{phase1_summary}"

    @staticmethod
    def _condense_shared_rules_for_phase2(full_rules: str) -> str:
        """Trích phần shared rules CẦN THIẾT cho Phase 2 (ATT&CK mapping).

        Phase 2 đã có anchor rules + reference examples riêng trong
        analyze_attack_mapping.system.txt nên KHÔNG cần 5 soft principles,
        reference examples, CAPEC hints inspiration. GIỮ MEMORY CORRUPTION
        rule (cho CVE-2021-3156/2013-4365), EVASIVE INDICATORS ENFORCEMENT,
        SUBTECHNIQUE DECISION.
        """
        keep_sections = [
            "MEMORY CORRUPTION → T1203 + T1499.004",
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
