"""
PoC Extractor Source - Extract telemetry from PoC repositories.

Evidence Extraction (NO AI):
1. Phase A: List PoC repos as candidates
2. Phase B: Fetch README and extract VERBATIM evidence using EvidenceExtractor
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import httpx

from src.domain.models.telemetry_discovery import (
    CandidateSource,
    EvidenceType,
    LogContentType,
    SourceConfidence,
    TelemetryArtifact,
    TelemetryArtifactType,
    TelemetrySourceType,
    VerificationMethod,
    VerificationStatus,
)
from src.infrastructure.telemetry.discovery.evidence_extractor import EvidenceExtractor, extract_evidence
from src.infrastructure.telemetry.discovery.sources.base import TelemetrySourceBase
from src.infrastructure.clients.base import BaseHTTPClient
from config.logging import get_logger

if TYPE_CHECKING:
    from src.infrastructure.telemetry.discovery.service import DiscoveryContext

logger = get_logger(__name__)


# Patterns for detecting telemetry artifact types
ARTIFACT_TYPE_PATTERNS = {
    TelemetryArtifactType.APACHE_ACCESS_LOG: [
        r"GET\s+/", r"POST\s+/", r"HTTP/\d\.\d",
    ],
    TelemetryArtifactType.SYSLOG: [
        r"syslog", r"journald", r"<[0-9]{1,3}>",
    ],
    TelemetryArtifactType.WINDOWS_EVENT: [
        r"<EventID>", r"EventLog", r"Microsoft-Windows",
    ],
    TelemetryArtifactType.SYSMON: [
        r"Sysmon", r"<Sysmon>", r"ProcessCreate",
    ],
    TelemetryArtifactType.DNS_LOG: [
        r"dns", r"query.*com",
    ],
    TelemetryArtifactType.JSON_EVENT: [
        r"\{.*\"EventID\".*\}", r"\{.*\"event_type\".*\}",
    ],
}


class PoCExtractorSource(TelemetrySourceBase):
    """Extract telemetry from PoC repositories.

    Evidence Extraction (NO AI):
    - Phase A: List PoC repos as candidates
    - Phase B: Fetch README and extract VERBATIM evidence using EvidenceExtractor
    """

    name = "PoC Repository"
    source_type = TelemetrySourceType.POC_OUTPUT.value

    def __init__(self, timeout: float = 15.0) -> None:
        super().__init__()
        self._client = BaseHTTPClient(base_url="", timeout=timeout)
        self._extractor = EvidenceExtractor()

    async def discover(
        self,
        cve_id: str,
        context: DiscoveryContext,
    ) -> tuple[list[CandidateSource], list[TelemetryArtifact]]:
        """Two-phase discovery from PoC repositories."""
        candidates: list[CandidateSource] = []
        artifacts: list[TelemetryArtifact] = []

        poc_references = context.get("poc_references", [])
        if not poc_references:
            logger.debug("[PoC-Extractor] No PoC references in context", cve_id=cve_id)
            return candidates, artifacts

        logger.info("[PoC-Extractor] Checking PoC repos", cve_id=cve_id, count=len(poc_references))

        # Phase A: Add all PoC repos as candidates
        for poc_url in poc_references:
            candidate = CandidateSource(
                source_type=TelemetrySourceType.POC_OUTPUT,
                source_name="PoC-in-GitHub",
                source_url=poc_url,
                verification_status=VerificationStatus.PENDING,
                description=f"PoC repository for {cve_id}",
                reason="PoC repositories often contain log samples in README",
            )
            candidates.append(candidate)

        # Phase B: Verify each PoC for actual telemetry artifacts
        for poc_url in poc_references:
            artifact = await self._verify_poc(cve_id, poc_url)
            if artifact:
                artifacts.append(artifact)

        return candidates, artifacts

    async def _verify_poc(self, cve_id: str, poc_url: str) -> TelemetryArtifact | None:
        """Verify if PoC contains actual telemetry artifacts using EvidenceExtractor."""
        debug_stats = {"source": "PoC-Extractor", "url": poc_url}

        try:
            # Fetch README
            readme_content = await self._fetch_readme(poc_url)
            debug_stats["fetch_success"] = readme_content is not None
            debug_stats["fetch_length"] = len(readme_content) if readme_content else 0

            if not readme_content:
                logger.debug("[PoC-Extractor] DEBUG: No README fetched", **debug_stats)
                return None

            # Get debug stats BEFORE extraction
            stats_before = self._extractor.extract_debug_stats(readme_content)
            debug_stats["html_length"] = stats_before["content_length"]
            debug_stats["code_blocks_log"] = stats_before["code_blocks_log"]
            debug_stats["code_blocks_xml"] = stats_before["code_blocks_xml"]
            debug_stats["code_blocks_text"] = stats_before["code_blocks_text"]
            debug_stats["code_blocks_json"] = stats_before["code_blocks_json"]
            debug_stats["windows_xml_events"] = stats_before["windows_xml_events"]
            debug_stats["event_ids"] = stats_before["event_ids"]
            debug_stats["evtx_refs"] = stats_before["evtx_refs"]
            debug_stats["pcap_refs"] = stats_before["pcap_refs"]

            # Extract evidence using EvidenceExtractor (NO AI)
            extracted_evidence = self._extractor.extract(readme_content)
            debug_stats["extracted_count"] = len(extracted_evidence)

            logger.debug("[PoC-Extractor] DEBUG: Fetch/Extract stats", **debug_stats)

            if not extracted_evidence:
                return None

            # Get best evidence (highest confidence, most content)
            best_evidence = max(extracted_evidence, key=lambda e: (
                0 if e.confidence == "high" else 1 if e.confidence == "medium" else 2,
                -len(e.content)
            ))

            # Detect artifact type from content
            artifact_type = self._detect_artifact_type(readme_content, best_evidence)
            if not artifact_type:
                artifact_type = TelemetryArtifactType.JSON_EVENT

            # Determine verification method based on evidence type
            verification_method = self._get_verification_method(best_evidence.evidence_type)

            # Extract event IDs if any
            event_ids = self._extractor.extract_event_ids(best_evidence.content)
            primary_event_id = event_ids[0] if event_ids else None

            logger.info(
                "[PoC-Extractor] Found verified artifact",
                cve_id=cve_id,
                url=poc_url,
                artifact_type=artifact_type.value,
                evidence_type=best_evidence.evidence_type.value,
            )

            return TelemetryArtifact(
                artifact_type=artifact_type,
                source_name="PoC-in-GitHub",
                source_type=TelemetrySourceType.POC_OUTPUT,
                source_url=poc_url,
                evidence_type=best_evidence.evidence_type,
                evidence_content=best_evidence.content,
                verification_method=verification_method,
                event_id=primary_event_id,
                evidence_summary=self._generate_evidence_summary(artifact_type, best_evidence),
                verified=True,
                confidence=SourceConfidence.HIGH,
            )

        except Exception as exc:
            logger.warning(
                "[PoC-Extractor] Verification failed",
                cve_id=cve_id,
                url=poc_url,
                error=str(exc)[:100],
            )
            return None

    async def _fetch_readme(self, repo_url: str) -> str | None:
        """Fetch README.md from GitHub repository."""
        repo_url = self._normalize_github_url(repo_url)
        if not repo_url:
            return None

        for filename in ["README.md", "README", "readme.md", "Readme.md"]:
            try:
                raw_url = f"{repo_url}/{filename}"
                response = await self._client.get(raw_url)
                if response.status_code == 200:
                    return response.text
            except Exception:
                pass

        return None

    def _normalize_github_url(self, url: str) -> str | None:
        """Normalize GitHub URL to raw content URL."""
        match = re.search(r"github\.com/([^/]+)/([^/]+?)(?:\.git)?(?:/.*)?$", url, re.IGNORECASE)
        if match:
            user, repo = match.groups()
            repo = repo.rstrip("/").replace(".git", "")
            return f"https://raw.githubusercontent.com/{user}/{repo}/HEAD"
        return None

    def _detect_artifact_type(self, content: str, evidence) -> TelemetryArtifactType | None:
        """Detect which artifact type is present."""
        content_lower = content.lower()

        for artifact_type, patterns in ARTIFACT_TYPE_PATTERNS.items():
            matches = sum(1 for p in patterns if re.search(p, content_lower, re.IGNORECASE))
            if matches >= 1:
                return artifact_type

        # Check evidence content type
        ev_type = evidence.evidence_type.value if hasattr(evidence.evidence_type, 'value') else str(evidence.evidence_type)

        if ev_type == "xml":
            if "Sysmon" in content:
                return TelemetryArtifactType.SYSMON
            return TelemetryArtifactType.WINDOWS_EVENT
        elif ev_type == "raw_log":
            if "GET" in evidence.content or "POST" in evidence.content:
                return TelemetryArtifactType.APACHE_ACCESS_LOG

        return None

    def _get_verification_method(self, evidence_type: EvidenceType) -> VerificationMethod:
        """Map evidence type to verification method."""
        mapping = {
            EvidenceType.RAW_LOG: VerificationMethod.RAW_EVENT,
            EvidenceType.XML: VerificationMethod.RAW_EVENT,
            EvidenceType.EVTX: VerificationMethod.RAW_EVENT,
            EvidenceType.PCAP: VerificationMethod.RAW_EVENT,
            EvidenceType.MARKDOWN: VerificationMethod.VENDOR_LOG,
            EvidenceType.DOCUMENTATION: VerificationMethod.DOCUMENTATION,
        }
        return mapping.get(evidence_type, VerificationMethod.NOT_FOUND)

    def _generate_evidence_summary(self, artifact_type: TelemetryArtifactType, evidence) -> str:
        """Generate human-readable evidence summary."""
        type_name = artifact_type.value.replace("_", " ").title()
        ev_type = evidence.evidence_type.value.replace("_", " ")

        if evidence.source_section:
            return f"{type_name} ({ev_type}): {evidence.source_section}"

        return f"{type_name} ({ev_type})"

    async def close(self) -> None:
        await self._client.close()
