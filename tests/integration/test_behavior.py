"""Integration test: AIBehaviorAnalyzer vs Groq (Log4Shell sample).

Run directly with:
 python -m tests.integration.test_behavior

This script bypasses pytest so you can see real LLM output in the terminal
without test-runner noise. It will short-circuit with a warning if
AI_ENABLED=false in .env.
"""

import asyncio
import logging
import sys

from app.core.config import settings
from app.models.core import CoreCVEData
from app.services.ai.base_client import BaseAIClient
from app.services.ai.behavior import AIBehaviorAnalyzer


def _print_config() -> bool:
	"""Log the AI config and return True if we should proceed."""
	logging.basicConfig(
		level=logging.INFO,
		format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
	)
	logger = logging.getLogger("integration.test_behavior")

	print("=" * 70)
	print("AI CONFIG (from app.core.config.settings)")
	print(f" AI Enabled : {settings.ai_enabled}")
	print(f" Base URL : {settings.ai_base_url}")
	api_key = settings.ai_api_key or ""
	masked = f"{api_key[:6]}...{api_key[-4:]}" if len(api_key) > 12 else "(empty)"
	print(f" API Key : {masked}")
	print("=" * 70)

	if not settings.ai_enabled:
		logger.warning(
			"AI is disabled (ai_enabled=False). Set AI_ENABLED=true in .env to run this test."
		)
		return False
	if not settings.ai_base_url:
		logger.warning("AI_BASE_URL is empty. Set it to a Groq / OpenAI / Ollama endpoint.")
		return False
	return True


async def _run() -> int:
	if not _print_config():
		return 0

	client = BaseAIClient()
	analyzer = AIBehaviorAnalyzer(client)

	# --- CoreCVEData sample (Log4Shell, CVE-2021-44228) -------------------
	# This mirrors what Bước 1 of the pipeline would produce from the NVD
	# enricher. Real orchestrator code would do:
	# core_data: CoreCVEData = await nvd_enricher.fetch("CVE-2021-44228")
	core_data = CoreCVEData(
		cve_id="CVE-2021-44228",
		description=(
			"Apache Log4j2 2.0-beta9 through 2.14.1 JNDI features used in "
			"configuration, log messages, and parameters do not protect "
			"against attacker-controlled LDAP and other JNDI related "
			"endpoints. An attacker who can control log messages or log "
			"message parameters can execute arbitrary code loaded from "
			"LDAP servers when message lookup substitution is enabled."
		),
		cvss_score=10.0,
		cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		severity="CRITICAL",
		cwe_ids=["CWE-917", "CWE-502"],
		cpes=["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"],
		references=[
			"https://logging.apache.org/log4j/2.x/security.html",
			"https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
		],
	)

	print(f"\n>>> Sending CVE {core_data.cve_id} to LLM (may take 5-15s)...\n")
	try:
		tech_analysis, attack_mapping = await analyzer.analyze(
			cve_id=core_data.cve_id,
			description=core_data.description or "",
			cvss_score=core_data.cvss_score or 0.0,
			cvss_vector=core_data.cvss_vector or "",
			cwe_ids=core_data.cwe_ids or [],
			cpes=core_data.cpes or [],
			references=core_data.references or [],
			published_at=(
				core_data.published_at.isoformat() if core_data.published_at else ""
			),
			modified_at=(
				core_data.modified_at.isoformat() if core_data.modified_at else ""
			),
		)
	except Exception as e:
		print("\n!!! TEST FAILED !!!")
		print(f"Exception type : {type(e).__name__}")
		print(f"Exception msg : {e}")
		return 1

	if not getattr(tech_analysis, "ai_used", False):
		print("\n!!! WARNING: tech_analysis.ai_used is False (unexpected).")

	print("\n" + "=" * 70)
	print("TechnicalAnalysis (parsed from LLM JSON)")
	print("=" * 70)
	print(tech_analysis.model_dump_json(indent=2, exclude_none=True))

	print("\n" + "=" * 70)
	print("AttackMapping (parsed from LLM JSON)")
	print("=" * 70)
	print(attack_mapping.model_dump_json(indent=2, exclude_none=True))

	techniques = attack_mapping.techniques or []
	if not techniques:
		print("\n!!! WARNING: AttackMapping.techniques is empty (model may have under-mapped).")

	print("\n>>> TEST PASSED")
	return 0


if __name__ == "__main__":
	sys.exit(asyncio.run(_run()))
