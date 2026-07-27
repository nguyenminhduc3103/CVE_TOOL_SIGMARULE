"""
Public Dataset Source - Check public security datasets.

Two-phase:
1. Phase A: List public datasets as candidates
2. Phase B: Verify if dataset actually contains samples for this CVE
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
from src.infrastructure.telemetry.discovery.sources.base import TelemetrySourceBase
from src.infrastructure.clients.base import BaseHTTPClient
from config.logging import get_logger

if TYPE_CHECKING:
    from src.infrastructure.telemetry.discovery.service import DiscoveryContext

logger = get_logger(__name__)


DATASET_CONFIGS = {
    "evtx_attack_samples": {
        "name": "EVTX-ATTACK-SAMPLES",
        "repo_url": "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES",
        "search_url": "https://api.github.com/search/code?q={cve_id}+repo:sbousseaden/EVTX-ATTACK-SAMPLES+extension:evtx",
        "artifact_type": TelemetryArtifactType.WINDOWS_EVENT,
        "description": "Windows Event logs (EVTX) for MITRE ATT&CK",
    },
    "splunk_bots": {
        "name": "Splunk BOTS",
        "repo_url": "https://github.com/splunk/botsv3",
        "search_url": None,  # No public search API
        "artifact_type": TelemetryArtifactType.JSON_EVENT,
        "description": "Boss of the SOC CTF dataset",
    },
    "security_onion": {
        "name": "Security Onion",
        "repo_url": "https://github.com/Security-Onion-Solutions/security-onion",
        "search_url": None,
        "artifact_type": TelemetryArtifactType.SURICATA_EVE,
        "description": "Security Onion validation scripts",
    },
    "malware_traffic": {
        "name": "Malware-Traffic-Analysis",
        "repo_url": "https://www.malware-traffic-analysis.net",
        "search_url": None,
        "artifact_type": TelemetryArtifactType.PCAP,
        "description": "PCAP and log samples",
    },
}


class PublicDatasetSource(TelemetrySourceBase):
    """Search public security datasets.

    Phase A: List datasets as candidates
    Phase B: Verify if dataset contains samples for this CVE
    """

    name = "Public Dataset"
    source_type = TelemetrySourceType.PUBLIC_DATASET.value

    def __init__(self, timeout: float = 15.0) -> None:
        super().__init__()
        self._client = BaseHTTPClient(base_url="", timeout=timeout)

    async def discover(
        self,
        cve_id: str,
        context: DiscoveryContext,
    ) -> tuple[list[CandidateSource], list[TelemetryArtifact]]:
        """Two-phase discovery from public datasets."""
        candidates: list[CandidateSource] = []
        artifacts: list[TelemetryArtifact] = []

        # Phase A: Add all datasets as candidates
        for dataset_id, config in DATASET_CONFIGS.items():
            candidate = CandidateSource(
                source_type=TelemetrySourceType.PUBLIC_DATASET,
                source_name=config["name"],
                source_url=config["repo_url"],
                verification_status=VerificationStatus.PENDING,
                description=config["description"],
                reason="Public datasets contain labeled security samples",
            )
            candidates.append(candidate)

        # Phase B: Verify EVTX-ATTACK-SAMPLES (has search API)
        evtx_artifact = await self._verify_evtx_samples(cve_id)
        if evtx_artifact:
            artifacts.append(evtx_artifact)

        return candidates, artifacts

    async def _verify_evtx_samples(self, cve_id: str) -> TelemetryArtifact | None:
        """Verify if EVTX-ATTACK-SAMPLES has samples for this CVE.

        Extracts actual evidence content from GitHub API results.
        """
        try:
            search_url = DATASET_CONFIGS["evtx_attack_samples"]["search_url"].format(cve_id=cve_id)
            response = await self._client.get(search_url)

            if response.status_code != 200:
                logger.debug("[Public-Dataset] GitHub search failed", cve_id=cve_id, status=response.status_code)
                return None

            data = response.json()
            total_count = data.get("total_count", 0)

            if total_count == 0:
                logger.debug("[Public-Dataset] No EVTX samples found", cve_id=cve_id)
                return None

            items = data.get("items", [])
            if not items:
                return None

            # Get the first matching file
            first_item = items[0]
            file_url = first_item.get("html_url")
            file_path = first_item.get("path", "")

            # Build download URL for EVTX file
            repo = "sbousseaden/EVTX-ATTACK-SAMPLES"
            download_url = f"https://github.com/{repo}/raw/master/{file_path}"

            # Try to fetch sample content (limited - EVTX is binary)
            sample_content = await self._fetch_evtx_sample(first_item)

            logger.info(
                "[Public-Dataset] Found EVTX samples",
                cve_id=cve_id,
                count=total_count,
                file=file_path,
            )

            return TelemetryArtifact(
                artifact_type=TelemetryArtifactType.WINDOWS_EVENT,
                source_name="EVTX-ATTACK-SAMPLES",
                source_type=TelemetrySourceType.PUBLIC_DATASET,
                source_url=file_url,
                download_url=download_url,
                evidence_type=EvidenceType.EVTX,
                evidence_content=sample_content,
                verification_method=VerificationMethod.RAW_EVENT,
                evidence_summary=f"EVTX file: {file_path} ({total_count} total matches)",
                verified=True,
                confidence=SourceConfidence.HIGH,
            )

        except Exception as exc:
            logger.warning(
                "[Public-Dataset] EVTX verification failed",
                cve_id=cve_id,
                error=str(exc)[:100],
            )
            return None

    async def _fetch_evtx_sample(self, item: dict) -> str | None:
        """Fetch sample content from EVTX file.

        EVTX files are binary XML containers. We can:
        1. Fetch via GitHub API (limited to 1MB)
        2. Return metadata reference
        """
        try:
            repo_url = item.get("repository", {}).get("url")
            if not repo_url:
                return None

            contents_url = f"{repo_url}/contents/{item.get('path')}"
            response = await self._client.get(contents_url)

            if response.status_code != 200:
                return None

            content_data = response.json()
            size = content_data.get("size", 0)

            # EVTX files are large binaries - return reference
            if size > 100 * 1024:  # > 100KB
                return (
                    f"[EVTX binary file: {size} bytes]\n"
                    f"[File: {item.get('path')}]\n"
                    f"[Download: {content_data.get('html_url')}]\n"
                    f"[Note: EVTX files require Windows Event Log parser to extract XML]"
                )

            # Small file - try to decode base64
            import base64

            if content_data.get("encoding") == "base64" and content_data.get("content"):
                decoded = base64.b64decode(content_data["content"])
                try:
                    # Try UTF-8 first
                    return decoded.decode("utf-8", errors="replace")
                except Exception:
                    # Binary - return hex preview
                    return f"[Binary EVTX - {size} bytes]\n[Preview: {decoded[:200].hex()}]"

            return None

        except Exception:
            return None

    async def close(self) -> None:
        await self._client.close()
