from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from time import perf_counter
from typing import Any

import httpx

from config.logging import get_logger
from src.domain.models.cve import CoreCVEData
from src.domain.models.coverage import CoverageAssessment
from src.domain.models.enriched import EnrichedCVEContext, EnrichmentMetadata
from src.domain.models.telemetry import TelemetryAssessment
from src.domain.models.triage import TriageContext
from src.infrastructure.providers.epss.provider import EPSSProvider
from src.infrastructure.providers.kev.provider import KEVProvider
from src.infrastructure.providers.nvd.provider import NVDProvider
from src.infrastructure.providers.otx.provider import OTXProvider
from src.infrastructure.providers.poc.provider import PoCProvider
from src.domain.services.capability import CapabilityChecker
from src.domain.services.priority_score import PriorityEngine
from src.usecases.step_1_triage.decision_engine import DecisionEngine
from src.usecases.step_1_triage.stages.analysis_stage import run_analysis_stage
from src.usecases.step_1_triage.stages.core_stage import run_core_stage
from src.usecases.step_1_triage.stages.coverage_stage import run_coverage_stage
from src.usecases.step_1_triage.stages.epss_stage import run_epss_stage
from src.usecases.step_1_triage.stages.exposure_stage import run_exposure_stage
from src.usecases.step_1_triage.stages.kev_stage import run_kev_stage
from src.usecases.step_1_triage.stages.poc_stage import run_poc_stage
from src.usecases.step_1_triage.stages.nuclei_crawl_stage import run_nuclei_crawl_stage
from src.usecases.step_1_triage.stages.telemetry_discovery_stage import run_telemetry_discovery_stage
from src.usecases.step_1_triage.stages.telemetry_assessment_stage import run_telemetry_assessment_stage
from src.usecases.step_1_triage.stages.telemetry_stage import run_telemetry_stage
from src.usecases.step_2_analysis.rule_based.attack_validator import validate_ttp_list


def _err_line(exc: BaseException) -> str:
    """Return the first line of str(exc), or the exception class name if empty.

    Some exceptions (e.g. ``httpx.ReadTimeout``) have an empty ``str()``,
    which would make ``str(exc).splitlines()[0]`` raise ``IndexError``.
    """
    text = str(exc)
    if not text:
        return type(exc).__name__
    return text.splitlines()[0]


class TriageOrchestrator:
    def __init__(self) -> None:
        self.nvd = NVDProvider()
        self.kev = KEVProvider()
        self.epss = EPSSProvider()
        self.otx = OTXProvider()
        self.poc = PoCProvider()
        self.priority_engine = PriorityEngine()
        self.decision_engine = DecisionEngine()
        self.capability_checker = CapabilityChecker()
        self.logger = get_logger(__name__)
        # Tracks which pipeline steps actually called an LLM and the model
        # used — surfaced via `enriched.metadata.ai_steps_used` /
        # `ai_total_cost_usd` so the test/CLI can report AI coverage.
        self._ai_steps_used: list[str] = []
        self._ai_total_cost_usd: float = 0.0

    async def orchestrate(self, cve_id: str) -> EnrichedCVEContext:
        pipeline_started = perf_counter()
        provider_status: dict[str, str] = {}
        provider_errors: dict[str, str] = {}
        provider_used: list[str] = []
        provider_durations: dict[str, int] = {}
        stage_partial = False

        provider_started = perf_counter()
        provider_tasks = {
            "nvd": self._run_provider("nvd", self.nvd, self.nvd.fetch, cve_id, provider_status, provider_errors, provider_durations),
            "kev": self._run_provider("kev", self.kev, self.kev.fetch, cve_id, provider_status, provider_errors, provider_durations),
            "epss": self._run_provider("epss", self.epss, self.epss.fetch, cve_id, provider_status, provider_errors, provider_durations),
            "otx": self._run_provider("otx", self.otx, self.otx.fetch, cve_id, provider_status, provider_errors, provider_durations),
            "poc": self._run_provider("poc", self.poc, self.poc.fetch, cve_id, provider_status, provider_errors, provider_durations),
        }
        nuclei_task = asyncio.create_task(run_nuclei_crawl_stage(cve_id))
        provider_results, nuclei_raw = await asyncio.gather(
            asyncio.gather(*provider_tasks.values(), return_exceptions=True),
            nuclei_task,
            return_exceptions=True,
        )
        # nuclei_raw should be a dict; collapse exception to empty payload
        if isinstance(nuclei_raw, BaseException):
            self.logger.warning(
                "[ORCHESTRATOR] nuclei_crawl_failed", cve_id=cve_id, error=_err_line(nuclei_raw)
            )
            nuclei_raw = {
                "status": "error",
                "cve_id": cve_id,
                "evidence": [],
                "references": [],
                "error": str(nuclei_raw)[:200],
            }
        # When wrapped, provider_results is the inner gather() list
        provider_results = provider_results if isinstance(provider_results, list) else []

        nvd_raw = kev_raw = epss_raw = poc_raw = None
        for name, result in zip(provider_tasks.keys(), provider_results):
            if isinstance(result, Exception):
                provider_status[name] = "failed"
                provider_errors[name] = _err_line(result)
                provider_durations.setdefault(name, int((perf_counter() - provider_started) * 1000))
            elif name == "nvd":
                nvd_raw = result
            elif name == "kev":
                kev_raw = result
            elif name == "epss":
                epss_raw = result
            elif name == "otx":
                otx_raw = result
            elif name == "poc":
                poc_raw = result

        provider_batch_duration_ms = int((perf_counter() - provider_started) * 1000)
        self.logger.info("[ORCHESTRATOR] provider_batch_completed", cve_id=cve_id, duration_ms=provider_batch_duration_ms)

        provider_used = [name for name, status in provider_status.items() if status == "success"]

        self.logger.info("[ORCHESTRATOR] Continuing with partial enrichment", cve_id=cve_id)

        nvd_core_raw, stage_failed = await self._run_stage(
            stage_name="core_stage",
            stage_fn=run_core_stage,
            cve_id=cve_id,
            payload=nvd_raw or {},
            fallback={},
        )
        stage_partial = stage_partial or stage_failed

        epss_stage_raw, stage_failed = await self._run_stage(
            stage_name="epss_stage",
            stage_fn=run_epss_stage,
            cve_id=cve_id,
            payload=epss_raw or {},
            fallback={},
        )
        stage_partial = stage_partial or stage_failed

        kev_stage_raw, stage_failed = await self._run_stage(
            stage_name="kev_stage",
            stage_fn=run_kev_stage,
            cve_id=cve_id,
            payload=kev_raw or {},
            fallback={},
        )
        stage_partial = stage_partial or stage_failed

        poc_stage_raw, stage_failed = await self._run_stage(
            stage_name="poc_stage",
            stage_fn=run_poc_stage,
            cve_id=cve_id,
            payload=poc_raw or {},
            fallback={"poc_references": None, "public_poc": False},
        )
        stage_partial = stage_partial or stage_failed

        # Build CoreCVEData from NVD raw (minimal mapping)
        core = self._build_core_context(cve_id, nvd_core_raw, otx_raw)

        # Merge nuclei YAML URL(s) into core.references so resolve_poc_context
        # carries them into triage.poc_references → PoCExtractorSource (Step 1.3).
        self._merge_references(core.references, nuclei_raw.get("references", []))

        exposure_raw, stage_failed = await self._run_stage(
            stage_name="exposure_stage",
            stage_fn=run_exposure_stage,
            cve_id=cve_id,
            payload=nvd_core_raw,
            fallback={"internet_exposure": None},
        )
        stage_partial = stage_partial or stage_failed

        internet_exposure = None
        if isinstance(exposure_raw, dict):
            internet_exposure = exposure_raw.get("internet_exposure")

        threat_actors = []
        if isinstance(otx_raw, dict):
            threat_actors = otx_raw.get("threat_actors") or []

        # Build TriageContext từ provider outputs
        in_kev_val = self._get_optional_bool(kev_stage_raw, "in_kev")
        
        # Gọi resolve_poc_context tập trung để trộn PoC từ cả references NVD và nomi-sec
        from src.shared.parsers.reference_parser import resolve_poc_context
        public_poc, poc_references = resolve_poc_context(core.references, poc_stage_raw)

        triage = TriageContext(
            in_kev=in_kev_val,
            kev_added_date=self._get_optional_datetime(kev_stage_raw, "kev_added_date"),
            ransomware_usage=self._get_optional_bool(kev_stage_raw, "known_ransomware_campaign_use") or False,
            observed_in_the_wild=in_kev_val or False,
            epss_score=self._get_optional_float(epss_stage_raw, "epss_score"),
            epss_percentile=self._get_optional_float(epss_stage_raw, "epss_percentile"),
            internet_exposure=internet_exposure,
            threat_actors=threat_actors,
            public_poc=public_poc,
            poc_references=poc_references or None,
        )

        # Enrich Core CWE IDs from KEV if NVD returned noinfo or empty
        if not core.cwe_ids or core.cwe_ids == ["NVD-CWE-noinfo"]:
            if isinstance(kev_stage_raw, dict) and kev_stage_raw.get("cwes"):
                core.cwe_ids = kev_stage_raw.get("cwes")

        # Priority & capability assessments
        priority, score = await self.priority_engine.assess(core, triage)
        triage.priority = priority
        triage.priority_score = score

        capability = await self.capability_checker.assess(core, triage)
        triage.capability_assessment = capability
        capability_classification = self.capability_checker.classify(core)

        # Đánh giá toàn bộ kết quả Triage theo 5 trường hợp cụ thể của ma trận ưu tiên để ra quyết định GO/NO-GO
        self.decision_engine.evaluate(core, triage, capability_classification)

        enriched = EnrichedCVEContext(
            core=core,
            triage=triage,
            provider_status=provider_status,
            provider_errors=provider_errors,
        )
        # Surface raw nuclei payload via object.__setattr__ to bypass Pydantic strict
        object.__setattr__(enriched, "nuclei_evidence", nuclei_raw)

        # ============================================================
        # Step 1.3: Telemetry Discovery (Two-Phase)
        # Phase A: Discover candidate sources
        # Phase B: Verify actual telemetry artifacts
        # ============================================================
        telemetry_discovery_result = await run_telemetry_discovery_stage(
            cve_id=cve_id,
            triage=triage,
            description=core.description,
            vendor=None,
        )
        enriched.telemetry_discovery = telemetry_discovery_result.discovery

        # ============================================================
        # Step 1.4: Telemetry Assessment (GATE)
        # Gate only PASSES if verified artifacts exist
        # ============================================================
        telemetry_assessment = await run_telemetry_assessment_stage(enriched.telemetry_discovery)
        enriched.telemetry_assessment = telemetry_assessment

        # GATE DECISION: If no verified artifacts, stop pipeline
        if telemetry_assessment.blocking:
            self.logger.warning(
                "[ORCHESTRATOR] telemetry_gate_blocked",
                cve_id=cve_id,
                verified_count=telemetry_assessment.verified_count,
                candidate_count=telemetry_assessment.candidate_count,
                decision=telemetry_assessment.decision.value,
            )
            # Override GO decision to NO-GO
            triage.decision = "NO-GO"
            triage.decision_reason = f"Telemetry gate blocked: {telemetry_assessment.reasoning}"
            triage.telemetry_blocked = True

            # Add metadata and return early (skip Step 2, 3, 4)
            metadata = EnrichmentMetadata(
                enriched_at=datetime.now(timezone.utc),
                enrichment_duration_ms=int((perf_counter() - pipeline_started) * 1000),
                providers_used=provider_used,
                partial_enrichment=True,
                provider_durations_ms=provider_durations or None,
            )
            enriched.metadata = metadata
            enriched.triage = triage
            return enriched

        # ============================================================
        # Continue to Step 2: Analysis Stage
        # ============================================================
        analysis_context, attack_context, stage_failed = await self._run_analysis_stage(enriched, capability_classification)
        stage_partial = stage_partial or stage_failed
        enriched.analysis = analysis_context
        enriched.attack = attack_context

        coverage_context, stage_failed = await self._run_enriched_stage(
            stage_name="coverage_stage",
            stage_fn=run_coverage_stage,
            context=enriched,
            capability=capability_classification,
            fallback=CoverageAssessment(),
        )
        stage_partial = stage_partial or stage_failed
        enriched.coverage = coverage_context

        telemetry_context, stage_failed = await self._run_enriched_stage(
            stage_name="telemetry_stage",
            stage_fn=run_telemetry_stage,
            context=enriched,
            capability=capability_classification,
            fallback=TelemetryAssessment(),
        )
        stage_partial = stage_partial or stage_failed
        enriched.telemetry = telemetry_context

        enrichment_duration_ms = int((perf_counter() - pipeline_started) * 1000)
        metadata = EnrichmentMetadata(
            enriched_at=datetime.now(timezone.utc),
            enrichment_duration_ms=enrichment_duration_ms,
            providers_used=provider_used,
            partial_enrichment=any(status != "success" for status in provider_status.values()) or stage_partial,
            provider_durations_ms=provider_durations or None,
            references_truncated=getattr(self.nvd.parser, "last_truncation", {}).get("references_truncated"),
            cpes_truncated=getattr(self.nvd.parser, "last_truncation", {}).get("cpes_truncated"),
            ai_steps_used=list(self._ai_steps_used),
            ai_total_cost_usd=self._ai_total_cost_usd or None,
        )

        enriched.metadata = metadata
        return enriched

    async def _run_stage(
        self,
        stage_name: str,
        stage_fn,
        cve_id: str,
        payload: dict[str, Any],
        fallback: dict[str, Any],
    ) -> tuple[dict[str, Any], bool]:
        try:
            result = await stage_fn(cve_id, payload)
            if isinstance(result, dict):
                return result, False
            return fallback, True
        except Exception as exc:
            self.logger.warning("[ORCHESTRATOR] stage_failed", stage=stage_name, cve_id=cve_id, error=_err_line(exc))
            return fallback, True

    async def _run_analysis_stage(self, context: EnrichedCVEContext, capability):
        from config.settings import settings
        from src.usecases.step_2_analysis.rule_based.attack_validator import filter_attack_mapping, normalize_family
        # NEW: import từ clean architecture folder
        from src.infrastructure.ai.core import AIServiceError, BaseAIClient
        from src.usecases.step_2_analysis.services.ai_service import AIBehaviorService
        from src.usecases.step_2_analysis import run_step2_tech_analysis

        # Phase 1: Try AI Behavior Analyzer first (nếu enabled).
        if getattr(settings, "ai_enabled", False):
            # Pre-bind locals so the warning logs below never raise UnboundLocalError
            # if `run_step2_tech_analysis` raises before the tuple unpack completes.
            tech_analysis = None
            attack_mapping = None
            coverage: dict = {"overall_coverage": 0.0, "verdict": "FAIL"}
            try:
                self.logger.info(
                    "[ORCHESTRATOR] analysis_stage_ai_attempt",
                    cve_id=context.core.cve_id,
                )
                client = BaseAIClient()
                ai_service = AIBehaviorService(client)

                tech_analysis, attack_mapping, coverage = await run_step2_tech_analysis(
                    ai_service=ai_service,
                    base_client=client,
                    cve_id=context.core.cve_id,
                    description=context.core.description or "",
                    cvss_score=context.core.cvss_score or 0.0,
                    cvss_vector=context.core.cvss_vector or "",
                    cwe_ids=context.core.cwe_ids or [],
                    cpes=context.core.cpes or [],
                    references=context.core.references or [],
                    published_at=(
                        context.core.published_at.isoformat()
                        if context.core.published_at
                        else ""
                    ),
                    modified_at=(
                        context.core.modified_at.isoformat()
                        if context.core.modified_at
                        else ""
                    ),
                    # Phase 6: pass PoC refs + threat actors from Step 1 triage
                    # context. AI uses these as INSPIRATION (not ground truth)
                    # to narrow down exploit mechanism for vague CVEs.
                    poc_references=getattr(context.triage, "poc_references", None) or [],
                    threat_actors=getattr(context.triage, "threat_actors", None) or [],
                    # Context signals from KEV / ransomware intel (advisory).
                    is_kev=bool(getattr(context.triage, "in_kev", False)),
                    ransomware_usage=bool(
                        getattr(context.triage, "ransomware_usage", False)
                    ),
                )

                # Nếu AI fail hoàn toàn → fall through
                if tech_analysis is None:
                    raise AIServiceError("AI returned None after retry")

                # Apply MITRE ATT&CK validator (safety net 2.3) cho AI output
                validation = validate_ttp_list(
                    attack_mapping.tactics,
                    attack_mapping.techniques,
                    attack_mapping.subtechniques,
                )
                attack_mapping.tactics = validation["valid_tactics"] or None
                attack_mapping.techniques = validation["valid_techniques"] or None
                attack_mapping.subtechniques = validation["valid_subtechniques"] or None
                attack_mapping.validation_warnings = validation["warnings"] or None
                attack_mapping.dropped_tactics = validation["invalid_tactics"] or None
                attack_mapping.dropped_techniques = validation["invalid_techniques"] or None
                attack_mapping.dropped_subtechniques = validation["invalid_subtechniques"] or None

                # Normalize family name về enum chuẩn (e.g. "Apache Log4j2" -> "jndi_injection")
                normalized_fam = normalize_family(tech_analysis.family)
                if normalized_fam:
                    tech_analysis.family = normalized_fam

                self.logger.info(
                    "[ORCHESTRATOR] analysis_stage_ai_success",
                    cve_id=context.core.cve_id,
                    coverage=coverage.get("overall_coverage", 0),
                    verdict=coverage.get("verdict", "?"),
                )
                # Record AI usage so the test/CLI can report it. Two-phase
                # flow exposes `ai_models_used` (list) covering both Phase 1
                # (e.g. OpenRouter) + Phase 2 (e.g. Groq). Legacy 1-shot flow
                # only has `ai_model` (single string). Aggregate both shapes.
                used_models: list[str] = []
                if tech_analysis.ai_models_used:
                    used_models.extend(tech_analysis.ai_models_used)
                if attack_mapping.ai_models_used:
                    used_models.extend(attack_mapping.ai_models_used)
                if not used_models:
                    fallback = tech_analysis.ai_model or attack_mapping.ai_model
                    if fallback:
                        used_models = [fallback]
                for m in used_models:
                    if m and m not in self._ai_steps_used:
                        self._ai_steps_used.append(m)
                return tech_analysis, attack_mapping, False
            except AIServiceError as exc:
                self.logger.warning(
                    "[ORCHESTRATOR] analysis_stage_ai_failed_fallback",
                    cve_id=context.core.cve_id,
error=_err_line(exc),
                )
                # Fall through to rule-based path bên dưới.
            except Exception as exc:
                self.logger.warning(
                    "[ORCHESTRATOR] analysis_stage_ai_unexpected_fallback",
                    cve_id=context.core.cve_id,
error=_err_line(exc),
                )
                # Fall through to rule-based path bên dưới.

        # Phase 2: Rule-based fallback.
        try:
            analysis_context, attack_context = await run_analysis_stage(context, capability)
            # Apply MITRE ATT&CK validator cho rule-based output
            validation = validate_ttp_list(
                attack_context.tactics if attack_context else None,
                attack_context.techniques if attack_context else None,
                attack_context.subtechniques if attack_context else None,
            )
            if attack_context and not validation["passed"]:
                self.logger.info(
                    "[ORCHESTRATOR] analysis_stage_validator_dropped",
                    cve_id=context.core.cve_id,
                    dropped_tactics=len(validation["invalid_tactics"]),
                    dropped_techniques=len(validation["invalid_techniques"]),
                )
            if attack_context:
                attack_context.tactics = validation["valid_tactics"] or None
                attack_context.techniques = validation["valid_techniques"] or None
                attack_context.subtechniques = validation["valid_subtechniques"] or None
                attack_context.validation_warnings = validation["warnings"] or None
                attack_context.dropped_tactics = validation["invalid_tactics"] or None
                attack_context.dropped_techniques = validation["invalid_techniques"] or None
                attack_context.dropped_subtechniques = validation["invalid_subtechniques"] or None
            return analysis_context, attack_context, False
        except Exception as exc:
            self.logger.warning("[ORCHESTRATOR] stage_failed", stage="analysis_stage", cve_id=context.core.cve_id, error=_err_line(exc))
            return None, None, True

    async def _run_enriched_stage(self, stage_name: str, stage_fn, context: EnrichedCVEContext, capability, fallback):
        try:
            result = await stage_fn(context, capability)
            return result, False
        except Exception as exc:
            self.logger.warning("[ORCHESTRATOR] stage_failed", stage=stage_name, cve_id=context.core.cve_id, error=_err_line(exc))
            return fallback, True

    async def _run_provider(
        self,
        provider_name: str,
        provider,
        fetcher,
        cve_id: str,
        provider_status: dict[str, str],
        provider_errors: dict[str, str],
        provider_durations: dict[str, int],
    ) -> Any | None:
        started = perf_counter()
        self.logger.info("[ORCHESTRATOR] provider_start", provider=provider_name, cve_id=cve_id)
        try:
            data = await fetcher(cve_id)
            duration_ms = int((perf_counter() - started) * 1000)
            provider_durations[provider_name] = duration_ms
            if data is None:
                provider_status[provider_name] = "failed"
                error_message = getattr(provider, "last_error_message", None) or "provider returned no data"
                provider_errors[provider_name] = error_message
                self.logger.warning("[ORCHESTRATOR] provider_failed", provider=provider_name, cve_id=cve_id, duration_ms=duration_ms, error=error_message)
                return None
            # Defensive: client layer trả empty dict {} (vd OTX bug cũ) cũng
            # được coi là failure thay vì success. Catch client-layer regressions
            # mà không cần đợi từng provider sửa từng behavior.
            if isinstance(data, dict) and not data:
                provider_status[provider_name] = "failed"
                error_message = getattr(provider, "last_error_message", None) or "provider returned empty data"
                provider_errors[provider_name] = error_message
                self.logger.warning("[ORCHESTRATOR] provider_failed", provider=provider_name, cve_id=cve_id, duration_ms=duration_ms, error=error_message)
                return None
            provider_status[provider_name] = "success"
            provider_errors.pop(provider_name, None)
            self.logger.info("[ORCHESTRATOR] provider_success", provider=provider_name, cve_id=cve_id, duration_ms=duration_ms)
            return data
        except (TimeoutError, httpx.TimeoutException) as exc:
            provider_status[provider_name] = "timeout"
            provider_errors[provider_name] = _err_line(exc)
            provider_durations[provider_name] = int((perf_counter() - started) * 1000)
            self.logger.warning("[ORCHESTRATOR] provider_failed", provider=provider_name, cve_id=cve_id, duration_ms=provider_durations[provider_name], error=provider_errors[provider_name])
        except Exception as exc:
            provider_status[provider_name] = "failed"
            provider_errors[provider_name] = _err_line(exc)
            provider_durations[provider_name] = int((perf_counter() - started) * 1000)
            self.logger.warning("[ORCHESTRATOR] provider_failed", provider=provider_name, cve_id=cve_id, duration_ms=provider_durations[provider_name], error=provider_errors[provider_name])
        return None

    @staticmethod
    def _merge_references(existing: list[Any], new_refs: list[Any]) -> None:
        """In-place dedup-merge: append new refs into existing, dedup by URL.

        Preserves full ref dict (URL + title/source/etc.) — never strips
        downstream-added keys. First occurrence wins on URL collision.
        """
        seen = {
            (r.get("url") if isinstance(r, dict) else r)
            for r in existing or []
        }
        for ref in new_refs or []:
            url = ref.get("url") if isinstance(ref, dict) else ref
            if isinstance(url, str) and url and url not in seen:
                seen.add(url)
                existing.append(ref)

    def _build_core_context(self, cve_id: str, nvd_raw: dict[str, Any] | None, otx_raw: dict[str, Any] | None = None) -> CoreCVEData:
        payload = nvd_raw or {}
        
        # 1. Trích xuất cơ bản từ NVD (nếu có)
        cve_id_val = payload.get("cve_id") or cve_id
        description = payload.get("description")
        cvss_score = payload.get("cvss_score")
        cvss_vector = payload.get("cvss_vector")
        severity = payload.get("severity")
        cwe_ids = payload.get("cwe_ids")
        references = payload.get("references")
        cpes = payload.get("cpes")
        affected_products = payload.get("affected_products")
        published_at = payload.get("published_at")
        modified_at = payload.get("modified_at")

        # 2. Dự phòng (Fallback) sang AlienVault OTX nếu NVD bị thiếu thông tin hoặc lỗi (e.g. description rỗng)
        otx_data = None
        if isinstance(otx_raw, dict):
            otx_data = otx_raw.get("raw")
            if not otx_data and "base_indicator" in otx_raw:
                otx_data = otx_raw

        if otx_data and isinstance(otx_data, dict):
            self.logger.info("[ORCHESTRATOR] Tiến hành kiểm tra và làm giàu dự phòng từ nguồn AlienVault OTX...", cve_id=cve_id)
            
            # Dự phòng Description
            if not description:
                description = otx_data.get("description") or (otx_data.get("base_indicator") or {}).get("description")
                if description:
                    self.logger.info("[ORCHESTRATOR] Fallback thành công: Đã lấy description từ OTX", cve_id=cve_id)
            
            # Dự phòng CVSS
            if not cvss_score:
                # Ưu tiên CVSSv3
                cvss_score = otx_data.get("cvssv3", {}).get("cvssV3", {}).get("baseScore")
                cvss_vector = otx_data.get("cvssv3", {}).get("cvssV3", {}).get("vectorString")
                severity = otx_data.get("cvssv3", {}).get("cvssV3", {}).get("baseSeverity")
                
                # Fallback sang CVSSv2
                if not cvss_score:
                    cvss_score_raw = otx_data.get("cvss", {}).get("Score")
                    try:
                        cvss_score = float(cvss_score_raw) if cvss_score_raw is not None else None
                    except (ValueError, TypeError):
                        cvss_score = None
                    cvss_vector = otx_data.get("cvss", {}).get("vectorString")
                
                # Tính severity từ score nếu vẫn thiếu
                if cvss_score and not severity:
                    try:
                        score_f = float(cvss_score)
                        if score_f >= 9.0:
                            severity = "CRITICAL"
                        elif score_f >= 7.0:
                            severity = "HIGH"
                        elif score_f >= 4.0:
                            severity = "MEDIUM"
                        elif score_f > 0:
                            severity = "LOW"
                    except Exception:
                        pass
                
                if cvss_score:
                    self.logger.info("[ORCHESTRATOR] Fallback thành công: Lấy CVSS từ OTX", score=cvss_score, vector=cvss_vector, severity=severity)

            # Dự phòng CWE
            if not cwe_ids or cwe_ids == ["NVD-CWE-noinfo"]:
                cwe_raw = otx_data.get("cwe")
                if cwe_raw:
                    cwe_clean = str(cwe_raw).strip()
                    if cwe_clean.startswith("CWE-"):
                        cwe_ids = [cwe_clean]
                        self.logger.info("[ORCHESTRATOR] Fallback thành công: Lấy CWE từ OTX", cwe_ids=cwe_ids)

            # Dự phòng References
            if not references:
                refs_list = otx_data.get("references") or []
                extracted_refs = []
                for ref in refs_list:
                    if isinstance(ref, dict) and ref.get("href"):
                        extracted_refs.append(ref.get("href"))
                    elif isinstance(ref, str):
                        extracted_refs.append(ref)
                if extracted_refs:
                    references = extracted_refs
                    self.logger.info("[ORCHESTRATOR] Fallback thành công: Lấy references từ OTX", count=len(references))

            # Dự phòng CPEs & affected_products
            if not cpes:
                products_list = otx_data.get("products") or []
                if products_list:
                    cpes = [str(p) for p in products_list if str(p).startswith("cpe:")]
                    if cpes and not affected_products:
                        try:
                            from src.shared.parsers.cpe_parser import parse_cpe
                            mapped_products = []
                            for cpe in cpes:
                                try:
                                    parsed = parse_cpe(cpe)
                                    tag = "[APP]"
                                    if parsed.part == "o":
                                        tag = "[OS]"
                                    elif parsed.part == "h":
                                        tag = "[HW]"
                                    label = f"{tag} {parsed.vendor.capitalize()} {parsed.product.capitalize()}"
                                    if parsed.version and parsed.version != "*":
                                        label += f" {parsed.version}"
                                    mapped_products.append(label)
                                except Exception:
                                    pass
                            if mapped_products:
                                affected_products = sorted(list(set(mapped_products)))
                        except Exception:
                            pass
                    self.logger.info("[ORCHESTRATOR] Fallback thành công: Lấy CPEs từ OTX", count=len(cpes))

            # Dự phòng Datetime
            from datetime import datetime
            if not published_at:
                date_created = otx_data.get("date_created")
                if date_created:
                    try:
                        published_at = datetime.fromisoformat(str(date_created).replace("Z", "+00:00"))
                    except Exception:
                        pass
            if not modified_at:
                date_modified = otx_data.get("date_modified")
                if date_modified:
                    try:
                        modified_at = datetime.fromisoformat(str(date_modified).replace("Z", "+00:00"))
                    except Exception:
                        pass

        return CoreCVEData(
            cve_id=cve_id_val,
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            severity=severity,
            cwe_ids=cwe_ids or None,
            references=references or None,
            cpes=cpes or None,
            affected_products=affected_products or None,
            published_at=published_at,
            modified_at=modified_at,
        )

    def _get_optional_float(self, payload: dict[str, Any] | None, key: str) -> float | None:
        if not payload:
            return None
        value = payload.get(key)
        try:
            return float(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    def _get_optional_bool(self, payload: dict[str, Any] | None, key: str) -> bool | None:
        if not payload:
            return None
        if key not in payload:
            return None
        value = payload.get(key)
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        normalized = str(value).strip().lower()
        if normalized in {"", "false", "no", "0", "none", "null", "unknown"}:
            return False
        return True

    def _get_optional_datetime(self, payload: dict[str, Any] | None, key: str):
        if not payload:
            return None
        return payload.get(key)
