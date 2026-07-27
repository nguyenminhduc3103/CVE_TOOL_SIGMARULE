"""
Vendor Advisory Source - Extract telemetry from vendor security advisories.

Evidence Extraction (NO AI):
1. Phase A: List vendor advisories as candidates
2. Phase B: Fetch advisory content and extract VERBATIM evidence using EvidenceExtractor
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from src.domain.models.telemetry_discovery import (
    CandidateSource,
    EvidenceType,
    SourceConfidence,
    TelemetryArtifact,
    TelemetryArtifactType,
    TelemetrySourceType,
    VerificationMethod,
    VerificationStatus,
)
from src.infrastructure.telemetry.discovery.evidence_extractor import EvidenceExtractor
from src.infrastructure.telemetry.discovery.sources.base import TelemetrySourceBase
from src.infrastructure.clients.base import BaseHTTPClient
from config.logging import get_logger

if TYPE_CHECKING:
    from src.infrastructure.telemetry.discovery.service import DiscoveryContext

logger = get_logger(__name__)


# Vendor configurations - NO hardcoded artifact_type
VENDOR_CONFIGS = {
    "microsoft": {
        "name": "Microsoft MSRC",
        "advisory_url": "https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}",
        "reason": "Microsoft publishes security advisories with KB articles",
    },
    "apache": {
        "name": "Apache",
        "advisory_url": "https://httpd.apache.org/security/vulnerabilities.html",
        "reason": "Apache publishes vulnerability reports",
    },
    "vmware": {
        "name": "VMware",
        "advisory_url": "https://www.vmware.com/security/advisories/{cve_id}.html",
        "reason": "VMware publishes security advisories",
    },
    "cisco": {
        "name": "Cisco PSIRT",
        "advisory_url": "https://sec.cloudapps.cisco.com/security/center/psirt?cve={cve_id}",
        "reason": "Cisco publishes security advisories",
    },
}


class VendorAdvisorySource(TelemetrySourceBase):
    """Search vendor advisories for telemetry.

    Evidence Extraction (NO AI):
    - Phase A: List vendors as candidates
    - Phase B: Fetch advisory and extract VERBATIM evidence
    """

    name = "Vendor Advisory"
    source_type = TelemetrySourceType.VENDOR_ADVISORY.value

    def __init__(self, timeout: float = 15.0) -> None:
        super().__init__()
        self._client = BaseHTTPClient(base_url="", timeout=timeout)
        self._extractor = EvidenceExtractor()

    async def discover(
        self,
        cve_id: str,
        context: DiscoveryContext,
    ) -> tuple[list[CandidateSource], list[TelemetryArtifact]]:
        """Two-phase discovery from vendor advisories."""
        candidates: list[CandidateSource] = []
        artifacts: list[TelemetryArtifact] = []

        # Phase A: Add all known vendors as candidates
        for vendor_id, config in VENDOR_CONFIGS.items():
            advisory_url = config["advisory_url"].format(cve_id=cve_id)
            candidate = CandidateSource(
                source_type=TelemetrySourceType.VENDOR_ADVISORY,
                source_name=config["name"],
                source_url=advisory_url,
                verification_status=VerificationStatus.PENDING,
                description=f"Security advisory for {cve_id}",
                reason=config["reason"],
            )
            candidates.append(candidate)

        # Phase B: Extract evidence from applicable vendors
        applicable_vendors = self._detect_applicable_vendors(cve_id, context)
        for vendor_id in applicable_vendors:
            artifact = await self._extract_evidence(cve_id, vendor_id)
            if artifact:
                artifacts.append(artifact)

        return candidates, artifacts

    def _detect_applicable_vendors(self, cve_id: str, context: DiscoveryContext) -> list[str]:
        """Detect which vendors likely apply to this CVE."""
        applicable = []
        description = (context.description or "").lower()
        cve_lower = cve_id.lower()

        # Microsoft CVEs
        if "microsoft" in description or "windows" in description or "iis" in description:
            applicable.append("microsoft")

        # Apache CVEs
        if "apache" in description or "httpd" in description or "tomcat" in description:
            applicable.append("apache")

        # VMware CVEs
        if "vmware" in description or "esxi" in description or "vcenter" in description:
            applicable.append("vmware")

        # Cisco CVEs
        if "cisco" in description or "ios" in description:
            applicable.append("cisco")

        return applicable

    async def _extract_evidence(
        self,
        cve_id: str,
        vendor_id: str,
    ) -> TelemetryArtifact | None:
        """Extract VERBATIM evidence from vendor advisory.

        Flow:
        1. Fetch advisory content
        2. Run EvidenceExtractor on content
        3. If evidence found → return artifact with evidence_content
        4. If no evidence → return None (don't create fake artifact)
        """
        config = VENDOR_CONFIGS.get(vendor_id)
        if not config:
            return None

        debug_stats = {"source": f"Vendor-Advisory/{vendor_id}", "vendor": config["name"]}

        try:
            advisory_url = config["advisory_url"].format(cve_id=cve_id)
            response = await self._client.get(advisory_url)

            debug_stats["fetch_status"] = response.status_code
            debug_stats["fetch_length"] = len(response.text) if response.status_code == 200 else 0

            if response.status_code != 200:
                logger.debug("[Vendor-Advisory] DEBUG: Fetch failed", **debug_stats)
                return None

            content = response.text

            # Get debug stats BEFORE extraction
            stats_before = self._extractor.extract_debug_stats(content)
            debug_stats["html_length"] = stats_before["content_length"]
            debug_stats["code_blocks_log"] = stats_before["code_blocks_log"]
            debug_stats["code_blocks_xml"] = stats_before["code_blocks_xml"]
            debug_stats["code_blocks_text"] = stats_before["code_blocks_text"]
            debug_stats["code_blocks_json"] = stats_before["code_blocks_json"]
            debug_stats["windows_xml_events"] = stats_before["windows_xml_events"]
            debug_stats["event_ids"] = stats_before["event_ids"]

            # Run EvidenceExtractor on content (NO AI)
            extracted = self._extractor.extract(content)
            debug_stats["extracted_count"] = len(extracted)

            logger.debug("[Vendor-Advisory] DEBUG: Fetch/Extract stats", **debug_stats)

            if not extracted:
                return None

            # Get best evidence
            best = max(extracted, key=lambda e: (
                0 if e.confidence == "high" else 1 if e.confidence == "medium" else 2,
                -len(e.content)
            ))

            # Detect artifact type from content
            artifact_type = self._detect_artifact_type(content, best, vendor_id)

            # Map evidence type to verification method
            verification_method = self._get_verification_method(best.evidence_type)

            # Extract event IDs
            event_ids = self._extractor.extract_event_ids(best.content)
            primary_event_id = event_ids[0] if event_ids else None

            logger.info(
                "[Vendor-Advisory] Found evidence",
                cve_id=cve_id,
                vendor=config["name"],
                evidence_type=best.evidence_type.value,
                content_length=len(best.content),
            )

            return TelemetryArtifact(
                artifact_type=artifact_type,
                source_name=config["name"],
                source_type=TelemetrySourceType.VENDOR_ADVISORY,
                source_url=advisory_url,
                evidence_type=best.evidence_type,
                evidence_content=best.content,
                verification_method=verification_method,
                event_id=primary_event_id,
                evidence_summary=self._generate_summary(artifact_type, best),
                verified=True,
                confidence=SourceConfidence.HIGH if best.confidence == "high" else SourceConfidence.MEDIUM,
            )

        except Exception as exc:
            logger.warning(
                "[Vendor-Advisory] Extraction failed",
                cve_id=cve_id,
                vendor=vendor_id,
                error=str(exc)[:100],
            )
            return None

    def _detect_artifact_type(
        self,
        content: str,
        evidence,
        vendor_id: str,
    ) -> TelemetryArtifactType:
        """Detect artifact type from content and vendor."""
        content_lower = content.lower()

        # Check for specific telemetry indicators
        if "sysmon" in content_lower or "<sysmon>" in content_lower:
            return TelemetryArtifactType.SYSMON
        if "windows" in content_lower and ("event" in content_lower or "security" in content_lower):
            return TelemetryArtifactType.WINDOWS_EVENT
        if "apache" in content_lower or "nginx" in content_lower:
            return TelemetryArtifactType.APACHE_ACCESS_LOG
        if "zeek" in content_lower or "conn.log" in content_lower:
            return TelemetryArtifactType.ZEEK_CONN
        if "suricata" in content_lower:
            return TelemetryArtifactType.SURICATA_EVE
        if "dns" in content_lower:
            return TelemetryArtifactType.DNS_LOG
        if "pcap" in content_lower:
            return TelemetryArtifactType.PCAP

        # Vendor-specific defaults
        vendor_defaults = {
            "microsoft": TelemetryArtifactType.WINDOWS_EVENT,
            "apache": TelemetryArtifactType.APACHE_ACCESS_LOG,
            "vmware": TelemetryArtifactType.JSON_EVENT,
            "cisco": TelemetryArtifactType.SYSLOG,
        }

        # Check evidence content type
        ev_type = evidence.evidence_type.value if hasattr(evidence.evidence_type, 'value') else str(evidence.evidence_type)
        if ev_type == "xml":
            return TelemetryArtifactType.WINDOWS_EVENT

        return vendor_defaults.get(vendor_id, TelemetryArtifactType.APPLICATION_LOG)

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

    def _generate_summary(self, artifact_type: TelemetryArtifactType, evidence) -> str:
        """Generate human-readable summary."""
        type_name = artifact_type.value.replace("_", " ").title()
        ev_type = evidence.evidence_type.value.replace("_", " ")

        if evidence.source_section:
            return f"{type_name} ({ev_type}): {evidence.source_section}"
        return f"{type_name} ({ev_type})"

    async def close(self) -> None:
        await self._client.close()
