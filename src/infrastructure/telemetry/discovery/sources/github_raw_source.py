"""
GitHub Raw Source - Search GitHub for raw telemetry files.

Evidence Extraction (NO AI):
1. Phase A: List GitHub repositories as candidates
2. Phase B: Search GitHub API for .evtx, .pcap, .log files and download content
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import httpx

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
from config.logging import get_logger

if TYPE_CHECKING:
    from src.infrastructure.telemetry.discovery.service import DiscoveryContext

logger = get_logger(__name__)


# GitHub repositories known to contain telemetry files
GITHUB_TELEMETRY_REPOS = {
    "evtx_attack_samples": {
        "name": "EVTX-ATTACK-SAMPLES",
        "repo": "sbousseaden/EVTX-ATTACK-SAMPLES",
        "description": "MITRE ATT&CK attack evtx samples",
        "file_type": ".evtx",
        "artifact_type": TelemetryArtifactType.WINDOWS_EVENT,
    },
    "malware_traffic": {
        "name": "Malware-Traffic-Analysis",
        "repo": None,  # No dedicated repo, use gist search
        "description": "PCAP and log samples from malware analysis",
        "file_type": ".pcap",
        "artifact_type": TelemetryArtifactType.PCAP,
    },
}


# File extensions to search for
TELEMETRY_EXTENSIONS = {
    ".evtx": (TelemetryArtifactType.WINDOWS_EVENT, EvidenceType.EVTX),
    ".pcap": (TelemetryArtifactType.PCAP, EvidenceType.PCAP),
    ".log": (TelemetryArtifactType.APPLICATION_LOG, EvidenceType.RAW_LOG),
}


class GitHubRawSource(TelemetrySourceBase):
    """Search GitHub for raw telemetry files.

    Evidence Extraction (NO AI):
    - Phase A: List known telemetry repos as candidates
    - Phase B: Search GitHub API for files matching CVE + extension
    """

    name = "GitHub Raw"
    source_type = TelemetrySourceType.GITHUB.value

    def __init__(self, timeout: float = 15.0) -> None:
        super().__init__()
        self._client: httpx.AsyncClient | None = None
        self._timeout = timeout

    @property
    def enabled(self) -> bool:
        """Always enabled - GitHub search is useful for all CVEs."""
        return True

    async def discover(
        self,
        cve_id: str,
        context: DiscoveryContext,
    ) -> tuple[list[CandidateSource], list[TelemetryArtifact]]:
        """Two-phase discovery from GitHub."""
        candidates: list[CandidateSource] = []
        artifacts: list[TelemetryArtifact] = []

        # Phase A: Add known telemetry repos as candidates
        for repo_id, config in GITHUB_TELEMETRY_REPOS.items():
            candidate = CandidateSource(
                source_type=TelemetrySourceType.GITHUB,
                source_name=config["name"],
                source_url=f"https://github.com/{config['repo']}" if config["repo"] else None,
                verification_status=VerificationStatus.PENDING,
                description=config["description"],
                reason=f"Known repository containing {config['file_type']} telemetry files",
            )
            candidates.append(candidate)

        # Phase B: Search GitHub for files matching this CVE
        for ext, (artifact_type, evidence_type) in TELEMETRY_EXTENSIONS.items():
            artifact = await self._search_github(cve_id, ext, artifact_type, evidence_type)
            if artifact:
                artifacts.append(artifact)

        return candidates, artifacts

    async def _search_github(
        self,
        cve_id: str,
        extension: str,
        artifact_type: TelemetryArtifactType,
        evidence_type: EvidenceType,
    ) -> TelemetryArtifact | None:
        """Search GitHub API for telemetry files matching this CVE.

        Uses GitHub's code search API to find files with:
        - CVE ID in filename or path
        - Specific file extension (.evtx, .pcap, .log)
        """
        debug_stats = {"source": "GitHub-Raw", "extension": extension}

        try:
            # GitHub Code Search API
            # Note: Requires authentication for higher rate limits
            search_query = f"{cve_id}+extension:{extension}"
            search_url = f"https://api.github.com/search/code?q={search_query}&per_page=5"

            if not self._client:
                self._client = httpx.AsyncClient(timeout=self._timeout)

            headers = {
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "cve-ti-platform/1.0 (+https://github.com/cve-ti)",
            }

            response = await self._client.get(search_url, headers=headers)

            debug_stats["search_status"] = response.status_code
            debug_stats["search_url"] = search_url

            if response.status_code != 200:
                logger.debug("[GitHub-Raw] DEBUG: Search failed", **debug_stats)
                return None

            data = response.json()
            total_count = data.get("total_count", 0)
            items = data.get("items", [])

            debug_stats["total_count"] = total_count
            debug_stats["items_found"] = len(items)

            logger.debug("[GitHub-Raw] DEBUG: Search results", **debug_stats)

            if not items:
                return None

            # Get the first result
            first_item = items[0]
            file_url = first_item.get("html_url")
            repo_name = first_item.get("repository", {}).get("full_name", "unknown")
            file_path = first_item.get("path", "")
            file_size = first_item.get("size", 0)

            # Try to download raw content
            raw_content = await self._fetch_raw_content(first_item)
            debug_stats["content_fetched"] = raw_content is not None
            debug_stats["content_length"] = len(raw_content) if raw_content else 0
            debug_stats["file_size"] = file_size
            debug_stats["repo"] = repo_name
            debug_stats["file_path"] = file_path

            logger.debug("[GitHub-Raw] DEBUG: Content fetch", **debug_stats)

            # Build download URL (GitHub raw content URL)
            download_url = self._build_raw_url(repo_name, file_path)

            logger.info(
                "[GitHub-Raw] Found telemetry file",
                cve_id=cve_id,
                extension=extension,
                repo=repo_name,
                file=file_path,
            )

            return TelemetryArtifact(
                artifact_type=artifact_type,
                source_name=repo_name.split("/")[0] if "/" in repo_name else repo_name,
                source_type=TelemetrySourceType.GITHUB,
                source_url=file_url,
                download_url=download_url,
                evidence_type=evidence_type,
                evidence_content=raw_content,
                verification_method=VerificationMethod.RAW_EVENT,
                evidence_summary=f"{extension.upper()} file found: {file_path}",
                verified=True,
                confidence=SourceConfidence.HIGH,
            )

        except httpx.TimeoutException:
            logger.warning("[GitHub-Raw] Timeout", cve_id=cve_id, extension=extension)
            return None
        except Exception as exc:
            logger.warning(
                "[GitHub-Raw] Search failed",
                cve_id=cve_id,
                extension=extension,
                error=str(exc)[:100],
            )
            return None

    async def _fetch_raw_content(self, item: dict) -> str | None:
        """Fetch raw content of a file from GitHub.

        Note: GitHub has rate limits for raw content. For large files (>1MB),
        we only return a reference, not the full content.
        """
        try:
            # Use the GitHub contents API to get file content
            repo_url = item.get("repository", {}).get("url")
            if not repo_url:
                return None

            contents_url = f"{repo_url}/contents/{item.get('path')}"

            if not self._client:
                self._client = httpx.AsyncClient(timeout=self._timeout)

            headers = {
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "cve-ti-platform/1.0 (+https://github.com/cve-ti)",
            }

            response = await self._client.get(contents_url, headers=headers)

            if response.status_code != 200:
                return None

            content_data = response.json()

            # Check file size - skip if too large
            size = content_data.get("size", 0)
            if size > 1024 * 1024:  # 1MB limit
                return f"[File too large: {size} bytes - download at: {content_data.get('html_url')}]"

            # Decode base64 content
            import base64

            if content_data.get("encoding") == "base64" and content_data.get("content"):
                decoded = base64.b64decode(content_data["content"])
                # Try to decode as text, fallback to hex dump
                try:
                    return decoded.decode("utf-8", errors="replace")
                except Exception:
                    # Binary file - return hex preview
                    preview = decoded[:500].hex()
                    return f"[Binary file - hex preview: {preview}...]\n[Download at: {content_data.get('html_url')}]"

            return None

        except Exception as exc:
            logger.debug("[GitHub-Raw] Failed to fetch content", error=str(exc)[:100])
            return None

    def _build_raw_url(self, repo_name: str, file_path: str) -> str:
        """Build GitHub raw content URL."""
        return f"https://raw.githubusercontent.com/{repo_name}/HEAD/{file_path}"

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
