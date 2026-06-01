from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from time import perf_counter
from typing import Any

import httpx

from app.core.logging import get_logger
from app.models.core import CoreCVEData
from app.models.coverage import CoverageAssessment
from app.models.enriched import EnrichedCVEContext, EnrichmentMetadata
from app.models.telemetry import TelemetryAssessment
from app.models.triage import TriageContext
from app.providers.epss.provider import EPSSProvider
from app.providers.kev.provider import KEVProvider
from app.providers.nvd.provider import NVDProvider
from app.triage.capability_checker import CapabilityChecker
from app.triage.priority_engine import PriorityEngine
from app.triage.stages.analysis_stage import run_analysis_stage
from app.triage.stages.core_stage import run_core_stage
from app.triage.stages.coverage_stage import run_coverage_stage
from app.triage.stages.epss_stage import run_epss_stage
from app.triage.stages.exposure_stage import run_exposure_stage
from app.triage.stages.kev_stage import run_kev_stage
from app.triage.stages.telemetry_stage import run_telemetry_stage


class TriageOrchestrator:
    def __init__(self) -> None:
        self.nvd = NVDProvider()
        self.kev = KEVProvider()
        self.epss = EPSSProvider()
        self.priority_engine = PriorityEngine()
        self.capability_checker = CapabilityChecker()
        self.logger = get_logger(__name__)

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
        }
        provider_results = await asyncio.gather(*provider_tasks.values(), return_exceptions=True)

        nvd_raw = kev_raw = epss_raw = None
        for name, result in zip(provider_tasks.keys(), provider_results):
            if isinstance(result, Exception):
                provider_status[name] = "failed"
                provider_errors[name] = str(result).splitlines()[0]
                provider_durations.setdefault(name, int((perf_counter() - provider_started) * 1000))
            elif name == "nvd":
                nvd_raw = result
            elif name == "kev":
                kev_raw = result
            elif name == "epss":
                epss_raw = result

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

        # Build CoreCVEData from NVD raw (minimal mapping)
        core = self._build_core_context(cve_id, nvd_core_raw)

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

        # Build TriageContext from provider outputs (skeleton-only)
        triage = TriageContext(
            in_kev=self._get_optional_bool(kev_stage_raw, "in_kev"),
            kev_added_date=self._get_optional_datetime(kev_stage_raw, "kev_added_date"),
            epss_score=self._get_optional_float(epss_stage_raw, "epss_score"),
            epss_percentile=self._get_optional_float(epss_stage_raw, "epss_percentile"),
            internet_exposure=internet_exposure,
        )

        # Priority & capability assessments (skeleton)
        priority, score = await self.priority_engine.assess(core, triage)
        triage.priority = priority
        triage.priority_score = score

        capability = await self.capability_checker.assess(core, triage)
        triage.capability_assessment = capability
        capability_classification = self.capability_checker.classify(core)

        enriched_seed = EnrichedCVEContext(
            core=core,
            triage=triage,
            provider_status=provider_status,
            provider_errors=provider_errors,
        )

        analysis_context, attack_context, stage_failed = await self._run_analysis_stage(enriched_seed, capability_classification)
        stage_partial = stage_partial or stage_failed
        enriched_seed.analysis = analysis_context
        enriched_seed.attack = attack_context

        coverage_context, stage_failed = await self._run_enriched_stage(
            stage_name="coverage_stage",
            stage_fn=run_coverage_stage,
            context=enriched_seed,
            capability=capability_classification,
            fallback=CoverageAssessment(),
        )
        stage_partial = stage_partial or stage_failed
        enriched_seed.coverage = coverage_context

        telemetry_context, stage_failed = await self._run_enriched_stage(
            stage_name="telemetry_stage",
            stage_fn=run_telemetry_stage,
            context=enriched_seed,
            capability=capability_classification,
            fallback=TelemetryAssessment(),
        )
        stage_partial = stage_partial or stage_failed
        enriched_seed.telemetry = telemetry_context

        enrichment_duration_ms = int((perf_counter() - pipeline_started) * 1000)
        metadata = EnrichmentMetadata(
            enriched_at=datetime.now(timezone.utc),
            enrichment_duration_ms=enrichment_duration_ms,
            providers_used=provider_used,
            partial_enrichment=any(status != "success" for status in provider_status.values()) or stage_partial,
            provider_durations_ms=provider_durations or None,
            references_truncated=getattr(self.nvd.parser, "last_truncation", {}).get("references_truncated"),
            cpes_truncated=getattr(self.nvd.parser, "last_truncation", {}).get("cpes_truncated"),
        )

        enriched = EnrichedCVEContext(
            core=core,
            triage=triage,
            analysis=enriched_seed.analysis,
            attack=enriched_seed.attack,
            coverage=enriched_seed.coverage,
            telemetry=enriched_seed.telemetry,
            provider_status=provider_status,
            provider_errors=provider_errors,
            metadata=metadata,
        )
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
            self.logger.warning("[ORCHESTRATOR] stage_failed", stage=stage_name, cve_id=cve_id, error=str(exc).splitlines()[0])
            return fallback, True

    async def _run_analysis_stage(self, context: EnrichedCVEContext, capability):
        try:
            analysis_context, attack_context = await run_analysis_stage(context, capability)
            return analysis_context, attack_context, False
        except Exception as exc:
            self.logger.warning("[ORCHESTRATOR] stage_failed", stage="analysis_stage", cve_id=context.core.cve_id, error=str(exc).splitlines()[0])
            return None, None, True

    async def _run_enriched_stage(self, stage_name: str, stage_fn, context: EnrichedCVEContext, capability, fallback):
        try:
            result = await stage_fn(context, capability)
            return result, False
        except Exception as exc:
            self.logger.warning("[ORCHESTRATOR] stage_failed", stage=stage_name, cve_id=context.core.cve_id, error=str(exc).splitlines()[0])
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
            provider_status[provider_name] = "success"
            provider_errors.pop(provider_name, None)
            self.logger.info("[ORCHESTRATOR] provider_success", provider=provider_name, cve_id=cve_id, duration_ms=duration_ms)
            return data
        except (TimeoutError, httpx.TimeoutException) as exc:
            provider_status[provider_name] = "timeout"
            provider_errors[provider_name] = str(exc).splitlines()[0]
            provider_durations[provider_name] = int((perf_counter() - started) * 1000)
            self.logger.warning("[ORCHESTRATOR] provider_failed", provider=provider_name, cve_id=cve_id, duration_ms=provider_durations[provider_name], error=provider_errors[provider_name])
        except Exception as exc:
            provider_status[provider_name] = "failed"
            provider_errors[provider_name] = str(exc).splitlines()[0]
            provider_durations[provider_name] = int((perf_counter() - started) * 1000)
            self.logger.warning("[ORCHESTRATOR] provider_failed", provider=provider_name, cve_id=cve_id, duration_ms=provider_durations[provider_name], error=provider_errors[provider_name])
        return None

    def _build_core_context(self, cve_id: str, nvd_raw: dict[str, Any] | None) -> CoreCVEData:
        payload = nvd_raw or {}
        return CoreCVEData(
            cve_id=payload.get("cve_id") or cve_id,
            description=payload.get("description"),
            cvss_score=payload.get("cvss_score"),
            cvss_vector=payload.get("cvss_vector"),
            severity=payload.get("severity"),
            cwe_ids=payload.get("cwe_ids") or None,
            references=payload.get("references") or None,
            cpes=payload.get("cpes") or None,
            published_at=payload.get("published_at"),
            modified_at=payload.get("modified_at"),
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
        if normalized in {"", "false", "no", "0", "none", "null"}:
            return False
        return True

    def _get_optional_datetime(self, payload: dict[str, Any] | None, key: str):
        if not payload:
            return None
        return payload.get(key)
