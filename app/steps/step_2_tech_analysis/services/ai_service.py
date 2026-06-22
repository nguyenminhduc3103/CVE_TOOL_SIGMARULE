"""AI Service cho Step 2 - Technical & ATT&CK Analyzer.

CHỈ làm 1 việc: gọi AI Groq/LLM + parse JSON response thành DICT thuần.

KHÔNG tạo Pydantic model ở đây. KHÔNG có fallback logic ở đây.
Tất cả Pydantic conversion + fallback sẽ làm ở orchestrator.py.

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

    Model selection (env-driven, no hardcode):
      - ANALYZE_AI_MODEL  → model for the primary analyze call.
      - RETRY_AI_MODEL    → model for the partial-fill retry call.
    Both fall back to legacy defaults if env vars are unset, so existing
    deployments keep working without changes.
    """

    _SYSTEM_FILE = "analyze_behavior.system.txt"
    _PHASE2_SYSTEM_FILE = "analyze_attack_mapping.system.txt"
    _SHARED_FILE = "_shared_mitre_rules.md"
    _USER_FILE = "analyze_behavior.user.txt"
    # Default analyze model — Groq llama-3.3-70b-versatile, 6K TPM free tier.
    # Override via env ANALYZE_AI_MODEL.
    _DEFAULT_MODEL = "llama-3.3-70b-versatile"
    # Default retry model — Google Gemini 2.5 Flash, 1M TPM (dodge Groq 6K TPM
    # ceiling on large retry payloads). Override via env RETRY_AI_MODEL.
    _DEFAULT_RETRY_MODEL = "gemini-2.5-flash"

    def __init__(self, base_client: BaseAIClient) -> None:
        self.client = base_client
        # Resolve model names from settings (env > legacy field > default).
        # Using getters so empty-string env values still fall through.
        self._MODEL: str = settings.get_analyze_model() or self._DEFAULT_MODEL
        self._RETRY_MODEL: str = settings.get_retry_model() or self._DEFAULT_RETRY_MODEL
        # Load shared MITRE rules once; both analyze + retry templates reference them.
        # Phase 1 (1-shot analyze) dùng full shared rules.
        # Phase 2 chỉ dùng anchor-based condensed rules (~30% size) để tránh
        # vượt Groq 12K TPM (vd CVE-2021-3156: 25 refs + 32 CPEs + full rules = 12K).
        shared_rules_full = (_PROMPTS_DIR / self._SHARED_FILE).read_text(encoding="utf-8")
        shared_rules_phase2 = self._condense_shared_rules_for_phase2(shared_rules_full)
        analyze_template = (
            _PROMPTS_DIR / self._SYSTEM_FILE
        ).read_text(encoding="utf-8")
        # Replace placeholder with shared rules content at construction time so
        # call_llm receives the full prompt (byte-identical to pre-split version).
        self.system_prompt_template = analyze_template.replace(
            "{{SHARED_MITRE_RULES}}", shared_rules_full
        )
        # Phase 2 (two-phase refactor): separate system prompt focused only
        # on ATT&CK mapping. Also embeds shared rules since ATT&CK IDs are
        # the focus of Phase 2.
        phase2_template = (
            _PROMPTS_DIR / self._PHASE2_SYSTEM_FILE
        ).read_text(encoding="utf-8")
        self._phase2_system_prompt = phase2_template.replace(
            "{{SHARED_MITRE_RULES}}", shared_rules_phase2
        )
        self.user_prompt_template = (
            _PROMPTS_DIR / self._USER_FILE
        ).read_text(encoding="utf-8")
        # Track BOTH analyze + retry models used in this run (instance-scoped
        # so each CVE call starts fresh). Order-preserving + deduplicated:
        # analyze model always first; retry model appended only if a retry
        # actually fired via `record_retry_model()`.
        self._models_used: list[str] = []
        logger.debug(
            "AIBehaviorService initialized: analyze=%s retry=%s",
            self._MODEL, self._RETRY_MODEL,
        )

    def _record_model(self, model: str) -> None:
        """Append `model` to `_models_used` if not already present."""
        if model and model not in self._models_used:
            self._models_used.append(model)

    def record_retry_model(self) -> None:
        """Mark that the retry model was used. Call BEFORE the retry call so
        it shows up even if the retry itself fails (e.g. rate-limit)."""
        self._record_model(self._RETRY_MODEL)

    def get_models_used(self) -> list[str]:
        """Return deduplicated, order-preserved list of models actually used
        for this CVE. analyze model first; retry model appended only if a
        retry was attempted.
        """
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
        """Gọi AI + parse JSON. Return dict thuần (không phải Pydantic).

        Args:
            ... (giữ nguyên 9 field gốc cho backward compat) ...
            poc_references: Optional list of public PoC URLs (max 3 in prompt).
                Helps AI narrow down exploit mechanism when description is
                vague (e.g. Log4Shell "untrusted deserialization" → PoC shows
                JNDI lookup chain).
            threat_actors: Optional list of threat actor names from OTX. Helps
                AI identify likely target/scale (e.g. APT29 vs script kiddie).
            capec_hints_by_cwe: Optional dict {CWE-id: [CAPEC hint dicts]}.
                INSPIRATION ONLY (not ground truth). Helps AI see common attack
                patterns for the CWE category. Empty dict / None = no hints.
            phase1_output: Optional Phase 1 behavior dict (NEW, two-phase refactor).
                When provided, AI uses `execution_surface` / `delivery_vector` /
                `user_interaction_required` from Phase 1 as canonical anchors to
                avoid the AV:N→T1190 bias. None → backward compat (single-shot mode).

        Raises:
            AIServiceError: nếu AI fail (rate-limit, timeout, JSON parse fail, etc.)
        """
        # Build 3 optional blocks for user prompt. Empty string = block omitted
        # from prompt entirely (graceful fallback when no data).
        poc_block = self._format_poc_block(poc_references or [])
        threat_actors_block = self._format_threat_actors_block(threat_actors or [])
        capec_hints_block = self._format_capec_hints_block(capec_hints_by_cwe or {})
        # NEW: Phase 1 anchor block (two-phase refactor)
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
            # Record analyze model ONLY after a successful dispatch (the call
            # itself didn't raise). Retry model is recorded separately by
            # the orchestrator via record_retry_model() before its call.
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

        Two-phase refactor: this method is invoked AFTER Phase 1 (behavior
        analysis). The Phase 1 output is embedded in the user prompt as
        canonical anchor to prevent the AV:N→T1190 bias that affected the
        single-shot prompt.

        Output dict shape (Phase 2 schema):
          {
            "tactics": list[str],
            "techniques": list[str],
            "subtechniques": list[str],
            "attack_confidence": float,
            "mapping_reasons": list[str]
          }
        No behavior fields (those come from Phase 1).

        Raises:
            AIServiceError: neu AI fail
        """
        # Phase 2 co rieng system prompt (analyze_attack_mapping.system.txt)
        # Load lazily trong __init__ roi cache
        phase2_system = self._phase2_system_prompt

        # Build prompt blocks. Phase 1 block LA BAT BUOC cho Phase 2
        # (no Phase 1 → fall back to single-shot behavior trong orchestrator).
        poc_block = self._format_poc_block(poc_references or [])
        threat_actors_block = self._format_threat_actors_block(threat_actors or [])
        capec_hints_block = self._format_capec_hints_block(capec_hints_by_cwe or {})
        phase1_block = self._format_phase1_block(phase1_output or {})

        # Phase 2 user prompt khac Phase 1 - can ca NVD description (chua
        # product/keyword triggers nhu "OGNL", "WebWork", "Jinja2" giup LLM
        # chon sub-technique T1059.xxx dung) LAN Phase 1 summary (anchor de
        # tranh AV:N→T1190 bias). KHONG can references/CPEs (chi can cho
        # Sigma rule generation o Step 3, KHONG can cho ATT&CK mapping).
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

    # ------------------------------------------------------------------
    # Optional prompt blocks (PoC refs, threat actors, CAPEC hints)
    # ------------------------------------------------------------------
    # Cap length để giữ user prompt < 4K tokens (Groq 6K TPM ceiling).
    _MAX_POC_REFS = 3
    _MAX_THREAT_ACTORS = 5
    _MAX_REFERENCES = 10
    _MAX_CPES = 10
    _MAX_DESCRIPTION_CHARS = 800

    @classmethod
    def _format_poc_block(cls, poc_references: list[str]) -> str:
        """Build the 'Public PoC References' block for the user prompt.

        Empty string when no PoCs (block omitted from prompt entirely).
        Caps at _MAX_POC_REFS to keep prompt size bounded.
        """
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
        """Cap references list để tránh vượt Groq TPM (12K tokens).

        CVE thực tế có thể có 25+ URLs (vd CVE-2021-3156 có 25 URLs);
        cap 10 URLs đầu + ghi chú số còn lại. Không ảnh hưởng chất lượng
        mapping vì AI chỉ cần vài URLs để hiểu context, không cần đọc hết.
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
        """Build the 'Threat Actors' block for the user prompt.

        Empty string when no actors observed (OTX returned nothing).
        """
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
        """Build the 'CAPEC hints' block for the user prompt.

        INSPIRATION ONLY (not ground truth). Empty string when no hints.
        """
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

    # ------------------------------------------------------------------
    # Phase 1 anchor (two-phase refactor)
    # ------------------------------------------------------------------
    @classmethod
    def _format_phase1_block(cls, phase1_output: dict[str, Any]) -> str:
        """Build the 'Phase 1 canonical facts' block for Phase 2 prompt.

        Phase 2 (ATT&CK mapping) ANCHORS on these fields:
          - execution_surface: WHERE code runs post-exploit
          - delivery_vector: HOW payload reaches victim
          - user_interaction_required: bool

        Plus entry_vector + execution_mechanism from Phase 1 attack_flow.

        Empty string when phase1_output is empty (Phase 2 invoked without
        Phase 1 - backward compat single-shot mode).
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
        """Tom tat Phase 1 thanh description ngan cho Phase 2 user prompt.

        Phase 2 user prompt can description ngan de AI hieu CVE nhung KHONG
        can full description (Phase 2 tap trung vao ATT&CK mapping). Tom
        tat gom: vulnerability_type + family + entry_vector + execution_mechanism.
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
        """Build Phase 2 description: NVD description (primary) + Phase 1 summary (anchor).

        Why BOTH (generalizable, not code-injection specific):
        - NVD description: contains product/keyword triggers (e.g. "OGNL",
          "WebWork", "Jinja2", "eval") that help LLM pick correct sub-technique
          (T1059.007 for JavaScript, T1059.006 for Python, etc.). Without these
          keywords the LLM anchors on generic T1190 and misses T1059.xxx.
        - Phase 1 summary: canonical facts (execution_surface, attack_flow) that
          prevent AV:N→T1190 bias and lock the LLM into the right context.

        If NVD description is empty/short, return Phase 1 summary alone.
        Truncate NVD portion to _MAX_DESCRIPTION_CHARS to avoid prompt bloat.
        """
        nvd_truncated = (nvd_description or "N/A")[: AIBehaviorService._MAX_DESCRIPTION_CHARS]
        phase1_summary = AIBehaviorService._summarize_phase1(phase1_output or {})
        if not phase1_summary or phase1_summary.strip() == "n/a":
            return nvd_truncated
        return f"{nvd_truncated}\n\n--- PHASE 1 ANCHOR ---\n{phase1_summary}"

    @staticmethod
    def _condense_shared_rules_for_phase2(full_rules: str) -> str:
        """Trích phần shared rules CẦN THIẾT cho Phase 2 (ATT&CK mapping).

        Phase 2 đã có anchor-based mapping rules trong analyze_attack_mapping.system.txt
        (sections ANCHOR-BASED TECHNIQUE SELECTION, INBOUND INTRUSION DISTINCTION).
        KHÔNG cần:
          - 5 soft principles (OS/SERVICE, PROTOCOL, TOOL, AUTH, NO-SIGNAL)
            → Phase 1 đã chọn execution_surface nên không cần principles.
          - Reference examples (CVE-2021-40444, CVE-2013-4365, CVE-2024-3094)
            → Phase 2 prompt đã có reference examples riêng.
          - CAPEC hints inspiration section.
        GIỮ:
          - MEMORY CORRUPTION rule (cho CVE-2021-3156, CVE-2013-4365)
          - EVASIVE INDICATORS ENFORCEMENT (cho completeness)
          - SUBTECHNIQUE DECISION (cho parent-only handling)
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
                # Section header line
                for sec in keep_sections:
                    if stripped.startswith(f"- {sec}"):
                        in_keep_section = True
                        section_indent = line[: len(line) - len(line.lstrip())]
                        keep.append(line)
                        break
                else:
                    in_keep_section = False
            elif in_keep_section:
                # Continuation line of the kept section
                if line.startswith(section_indent + "  ") or not stripped:
                    keep.append(line)
                else:
                    in_keep_section = False
        return "\n".join(keep)
