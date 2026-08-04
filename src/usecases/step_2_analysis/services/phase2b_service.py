"""Phase 2B Service - Chain Reasoning cho ATT&CK.

Nhận Phase 2A output (tactics, techniques, subtechniques) và CVE info,
trả về chain reasoning với step-by-step breakdown.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from config.settings import settings
from src.infrastructure.ai.core import AIServiceError, BaseAIClient

logger = logging.getLogger(__name__)

_PROMPTS_DIR = Path(__file__).parent.parent / "prompts"


class AIPhase2BService:
    """Service gọi AI Phase 2B — Chain Reasoning."""

    def __init__(self, base_client: BaseAIClient | None = None) -> None:
        if base_client is None:
            base_client = BaseAIClient(
                api_keys=settings.get_phase2_api_keys(),
                base_url=settings.get_phase2_base_url(),
            )
        self.client = base_client
        self._MODEL: str = settings.get_phase2_model()
        self._BASE_URL: str | None = settings.get_phase2_base_url()

        phase2b_template = (_PROMPTS_DIR / "analyze_behavior_phase2b.system.txt").read_text(encoding="utf-8")
        self._phase2b_system_prompt = phase2b_template
        self.user_prompt_template = (_PROMPTS_DIR / "analyze_behavior.user.txt").read_text(encoding="utf-8")

        logger.debug(
            "AIPhase2BService initialized: model=%s, base_url=%s",
            self._MODEL,
            self._BASE_URL,
        )

    async def reason_chain(
        self,
        step1_output: dict[str, Any],
        phase1_output: dict[str, Any],
        phase2a_output: dict[str, Any],
        cve_id: str,
    ) -> dict[str, Any]:
        """Phase 2B AI call — Chain reasoning."""
        s1 = step1_output or {}
        p1 = phase1_output or {}
        p2a = phase2a_output or {}

        input_payload = {
            "cve_id": cve_id,
            "description": s1.get("description") or "",
            "reasoning": p1.get("reasoning") or [],
            "poc_documentation": s1.get("poc_description") or "",
            "poc_evidence": s1.get("poc_request_info", {}).get("path") if isinstance(s1.get("poc_request_info"), dict) else "",
            "tactics": p2a.get("tactics") or [],
            "techniques": p2a.get("techniques") or [],
            "subtechniques": p2a.get("subtechniques") or [],
        }

        formatted_user = self.user_prompt_template.format(
            input_json=json.dumps(input_payload, ensure_ascii=False, indent=2),
        )

        try:
            logger.info("[Phase 2B] Calling AI with payload: %s", input_payload)
            response_text = await self.client.call_llm(
                system_prompt=self._phase2b_system_prompt,
                user_prompt=formatted_user,
                model=self._MODEL,
            )
            logger.info("[Phase 2B] Raw response: %s", response_text[:500])
            cleaned_text = self._clean_json(response_text)
            logger.info("[Phase 2B] Cleaned JSON: %s", cleaned_text[:500])
            data = json.loads(cleaned_text)
            logger.info("[Phase 2B] Parsed data: %s", data)

            # Ensure required fields
            if not data.get("is_attack_chain") and data.get("attack_chain"):
                data["is_attack_chain"] = True
            if not data.get("confidence"):
                data["confidence"] = "medium"

            # Generate mapping_reasons from attack_chain if not provided
            if not data.get("mapping_reasons") and data.get("attack_chain"):
                mapping_reasons = []
                for step in data["attack_chain"]:
                    tech = step.get("technique_id", "")
                    tac = step.get("tactic_id", "")
                    reasoning = step.get("reasoning", "")
                    if tech:
                        mapping_reasons.append(f"{tech} selected - {reasoning[:100]}" if reasoning else f"{tech} selected")
                data["mapping_reasons"] = mapping_reasons

            # Validate attack_chain techniques (if AI added new ones)
            from src.usecases.step_2_analysis.rule_based.attack_validator import validate_attack_mapping
            attack_chain = data.get("attack_chain") or []
            chain_techs = [step.get("technique_id") for step in attack_chain if step.get("technique_id")]
            chain_tactics = [step.get("tactic_id") for step in attack_chain if step.get("tactic_id")]

            invalid_chain = validate_attack_mapping(chain_tactics, chain_techs, [])
            if invalid_chain:
                logger.warning("[Phase 2B] Invalid TTPs in attack_chain: %s", invalid_chain)
                # Filter out invalid steps
                data["attack_chain"] = [
                    step for step in attack_chain
                    if step.get("technique_id") not in invalid_chain
                    and step.get("tactic_id") not in invalid_chain
                ]
                # Set confidence to low if had invalid
                data["confidence"] = "low"

            return data
        except (json.JSONDecodeError, AIServiceError) as e:
            logger.error("AIPhase2BService.reason_chain failed for %s: %s", cve_id, e)
            raise AIServiceError(f"Phase 2B Chain Reasoning failed: {e}") from e
        except Exception as e:
            logger.error("AIPhase2BService validation failed for %s: %s", cve_id, e)
            raise AIServiceError(f"Phase 2B validation failed: {e}") from e

    @staticmethod
    def _clean_json(text: str) -> str:
        """Strip markdown fences."""
        fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if fenced:
            return fenced.group(1).strip()
        first = text.find("{")
        last = text.rfind("}")
        if first != -1 and last != -1 and last > first:
            return text[first : last + 1].strip()
        return text.strip()
