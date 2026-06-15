import json
import logging
import re
from pathlib import Path

from pydantic import ValidationError

from app.shared.models.attack import AttackFlow, AttackMapping, CWEMetadata, TechnicalAnalysis
from app.services.ai.base_client import AIServiceError, BaseAIClient
from app.shared.types.vulnerability_class import VulnerabilityClass


logger = logging.getLogger(__name__)


class AIBehaviorAnalyzer:
    """AI-powered CVE behavior + ATT&CK mapping analyzer (Bước 2 of the pipeline).

    Wraps `BaseAIClient.call_llm` with prompt assembly, JSON cleanup, and Pydantic
    parsing. On any failure raises `AIServiceError` so callers can fall back to
    the rule-based `analyze_behavior` + `map_attack` path.
    """

    _PROMPTS_DIR = Path(__file__).parent / "prompts"
    _SYSTEM_FILE = "analyze_behavior.system.txt"
    _USER_FILE = "analyze_behavior.user.txt"
    # Pick one. Comment/uncomment to switch.
    _MODEL = "llama-3.3-70b-versatile"  # full-fat 70B — best quality, but Groq free tier rate-limits TPD (100k)

    def __init__(self, base_client: BaseAIClient) -> None:
        self.client = base_client
        self.system_prompt_template = (self._PROMPTS_DIR / self._SYSTEM_FILE).read_text(
            encoding="utf-8"
        )
        self.user_prompt_template = (self._PROMPTS_DIR / self._USER_FILE).read_text(
            encoding="utf-8"
        )

    @staticmethod
    def _clean_json(text: str) -> str:
        """Strip markdown fences / leading prose so json.loads can parse the payload."""
        # Strip ```json ... ``` or ``` ... ``` blocks (greedy across newlines).
        fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if fenced:
            return fenced.group(1).strip()
        # Fallback: first {...} to last brace.
        first = text.find("{")
        last = text.rfind("}")
        if first != -1 and last != -1 and last > first:
            return text[first : last + 1].strip()
        return text.strip()

    def _coerce_vulnerability_class(self, raw: object) -> VulnerabilityClass | None:
        if raw is None:
            return None
        try:
            return VulnerabilityClass(str(raw).lower())
        except ValueError:
            logger.warning("Unknown vulnerability_class from AI: %r", raw)
            return VulnerabilityClass.UNKNOWN

    async def analyze(
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
    ) -> tuple[TechnicalAnalysis, AttackMapping]:
        cwe_ids_str = ", ".join(cwe_ids) if cwe_ids else "None"
        cpes_str = ", ".join(cpes) if cpes else "None"
        references_str = (
            "\n".join(references) if references else "None"
        )

        try:
            formatted_user = self.user_prompt_template.format(
                cve_id=cve_id,
                description=description or "N/A",
                cvss_score=cvss_score,
                cvss_vector=cvss_vector or "N/A",
                cwe_ids=cwe_ids_str,
                cpes=cpes_str,
                references=references_str,
                published_at=published_at or "N/A",
                modified_at=modified_at or "N/A",
            )
            # System prompt has no placeholders yet (schema is static), but .format()
            # would choke on any literal { in JSON-schema examples — so we keep it raw.
            system_prompt = self.system_prompt_template

            response_text = await self.client.call_llm(
                system_prompt=system_prompt,
                user_prompt=formatted_user,
                model=self._MODEL,
            )
            cleaned_text = self._clean_json(response_text)
            data = json.loads(cleaned_text)

            cwe_meta_raw = data.get("cwe_metadata")
            cwe_meta = None
            if isinstance(cwe_meta_raw, dict):
                cwe_meta = CWEMetadata(**cwe_meta_raw)

            attack_flow_raw = data.get("attack_flow")
            attack_flow = None
            if isinstance(attack_flow_raw, dict):
                attack_flow = AttackFlow(**attack_flow_raw)

            tech_analysis = TechnicalAnalysis(
                family=data.get("family"),
                signature=data.get("signature"),
                vulnerability_type=data.get("vulnerability_type"),
                vulnerability_class=self._coerce_vulnerability_class(
                    data.get("vulnerability_class")
                ),
                exploit_vector=data.get("exploit_vector"),
                pre_auth=data.get("pre_auth"),
                remote_exploitable=data.get("remote_exploitable"),
                exploit_complexity=data.get("exploit_complexity"),
                confidence=data.get("confidence"),
                likely_outcome=data.get("likely_outcome"),
                mandatory_behaviors=data.get("mandatory_behaviors") or None,
                evasive_indicators=data.get("evasive_indicators") or None,
                exploit_requirements=data.get("exploit_requirements") or None,
                cwe_metadata=cwe_meta,
                attack_flow=attack_flow,
                ai_used=True,
                ai_model=self._MODEL,
            )

            attack_mapping = AttackMapping(
                tactics=data.get("tactics") or None,
                techniques=data.get("techniques") or None,
                subtechniques=data.get("subtechniques") or None,
                confidence=data.get("attack_confidence") or data.get("confidence"),
                mapping_reasons=data.get("mapping_reasons") or None,
                ai_used=True,
                ai_model=self._MODEL,
            )
            return tech_analysis, attack_mapping

        except (json.JSONDecodeError, ValidationError, AIServiceError) as e:
            logger.error("AIBehaviorAnalyzer failed for %s: %s", cve_id, e)
            raise AIServiceError(f"Behavior Analysis failed: {e}") from e
