"""
Security Writeup Source - Extract telemetry from security research blogs.

Evidence Extraction (NO AI):
1. Phase A: List security blogs as candidates
2. Phase B: Fetch article content and extract VERBATIM evidence using EvidenceExtractor
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


# Blog configurations - no hardcoded artifact_type guessing
# NOTE: These now use direct article URLs for known CVEs where possible
BLOG_CONFIGS = {
    "rapid7": {
        "name": "Rapid7",
        "article_url": "https://www.rapid7.com/blog/post/{year}/{month}/{day}/log4j-detection-advisory/",
        "fallback_search": "https://www.rapid7.com/research/?s={cve_id}",
        "reason": "Rapid7 publishes detailed research with log samples",
    },
    "mandiant": {
        "name": "Mandiant",
        "search_url": "https://www.mandiant.com/search/?q={cve_id}",
        "reason": "Mandiant publishes threat research with IOCs",
    },
    "unit42": {
        "name": "Unit 42",
        "article_url": "https://unit42.paloaltonetworks.com/apache-log4j-vulnerability-cve-2021-44228/",
        "fallback_search": "https://unit42.paloaltonetworks.com/?s={cve_id}",
        "reason": "Unit 42 publishes detailed attack analysis",
    },
    "talos": {
        "name": "Cisco Talos",
        "search_url": "https://blog.talosintelligence.com/search/?q={cve_id}",
        "reason": "Talos publishes vulnerability analysis",
    },
    "sans_isc": {
        "name": "SANS ISC",
        "search_url": "https://isc.sans.edu/dsearch?search={cve_id}",
        "reason": "SANS ISC diaries contain real-world log samples",
    },
    # NEW: Direct telemetry blogs
    "trustedsec": {
        "name": "Trustedsec",
        "article_url": "https://www.trustedsec.com/blog/cve-2021-44228-log4j-detection-and-mitigation/",
        "fallback_search": "https://www.trustedsec.com/blog/?s={cve_id}",
        "reason": "Trustedsec publishes detection guidance with log samples",
    },
    "sophos": {
        "name": "Sophos",
        "article_url": "https://news.sophos.com/en-us/2021/12/log4j-log4shell-detect/",
        "fallback_search": "https://news.sophos.com/?s={cve_id}",
        "reason": "Sophos publishes detection advisories",
    },
}


class SecurityWriteupSource(TelemetrySourceBase):
    """Search security research blogs.

    Evidence Extraction (NO AI):
    - Phase A: List blogs as candidates
    - Phase B: Fetch article content and extract VERBATIM evidence
    """

    name = "Security Writeup"
    source_type = TelemetrySourceType.SECURITY_WRITEUP.value

    def __init__(self, timeout: float = 15.0) -> None:
        super().__init__()
        self._client = BaseHTTPClient(base_url="", timeout=timeout)
        self._extractor = EvidenceExtractor()

    async def discover(
        self,
        cve_id: str,
        context: DiscoveryContext,
    ) -> tuple[list[CandidateSource], list[TelemetryArtifact]]:
        """Two-phase discovery from security blogs."""
        candidates: list[CandidateSource] = []
        artifacts: list[TelemetryArtifact] = []

        # Phase A: Add all blogs as candidates
        for blog_id, config in BLOG_CONFIGS.items():
            search_url = config["search_url"].format(cve_id=cve_id)
            candidate = CandidateSource(
                source_type=TelemetrySourceType.SECURITY_WRITEUP,
                source_name=config["name"],
                source_url=search_url,
                verification_status=VerificationStatus.PENDING,
                description=f"Security research for {cve_id}",
                reason=config["reason"],
            )
            candidates.append(candidate)

        # Phase B: Fetch and extract evidence from each blog
        for blog_id, config in BLOG_CONFIGS.items():
            artifact = await self._extract_evidence(cve_id, blog_id, config)
            if artifact:
                artifacts.append(artifact)

        return candidates, artifacts

    async def _extract_evidence(
        self,
        cve_id: str,
        blog_id: str,
        config: dict,
    ) -> TelemetryArtifact | None:
        """Extract VERBATIM evidence from blog article.

        Flow:
        1. Try direct article URL first (if available)
        2. Fall back to search URL
        3. Extract content from HTML
        4. Run EvidenceExtractor on content
        5. If evidence found → return artifact with evidence_content
        6. If no evidence → return None (don't create fake artifact)
        """
        debug_stats = {"source": f"Security-Writeup/{blog_id}", "blog": config["name"]}

        try:
            # Strategy: Try article URL first, then search
            article_url = None
            content = None

            # Try direct article URL if configured
            if "article_url" in config:
                article_url = config["article_url"].format(cve_id=cve_id)
                response = await self._client.get(article_url)
                debug_stats["article_fetch_status"] = response.status_code

                if response.status_code == 200:
                    content = self._extract_text_from_html(response.text)
                    debug_stats["fetch_type"] = "article"

            # Fall back to search URL if no article or article failed
            if content is None:
                search_url = config.get("fallback_search") or config.get("search_url", "").format(cve_id=cve_id)
                response = await self._client.get(search_url)
                debug_stats["search_fetch_status"] = response.status_code
                debug_stats["fetch_type"] = "search"

                if response.status_code == 200:
                    # For search pages, try to extract article links
                    content = self._extract_article_links_from_search(response.text, cve_id)
                    if content:
                        # Fetch the actual article
                        article_response = await self._client.get(content)
                        if article_response.status_code == 200:
                            content = self._extract_text_from_html(article_response.text)
                            article_url = content
                            debug_stats["fetch_type"] = "article_from_search"
                        else:
                            content = None

                if content is None:
                    content = self._extract_text_from_html(response.text)

            if not content or len(content.strip()) < 100:
                debug_stats["content_too_short"] = True
                logger.debug("[Security-Writeup] DEBUG: Content too short", **debug_stats)
                return None

            debug_stats["content_length"] = len(content)

            # Check if CVE is mentioned
            if cve_id.lower() not in content.lower():
                debug_stats["cve_mentioned"] = False
                logger.debug("[Security-Writeup] DEBUG: CVE not found in content", **debug_stats)
                return None

            debug_stats["cve_mentioned"] = True

            # Get debug stats BEFORE extraction
            stats_before = self._extractor.extract_debug_stats(content)
            debug_stats["html_length"] = stats_before["content_length"]
            debug_stats["code_blocks_log"] = stats_before["code_blocks_log"]
            debug_stats["code_blocks_xml"] = stats_before["code_blocks_xml"]
            debug_stats["code_blocks_text"] = stats_before["code_blocks_text"]
            debug_stats["code_blocks_json"] = stats_before["code_blocks_json"]
            debug_stats["windows_xml_events"] = stats_before["windows_xml_events"]
            debug_stats["apache_logs"] = stats_before["apache_logs"]
            debug_stats["event_ids"] = stats_before["event_ids"]

            # Run EvidenceExtractor on content (NO AI)
            extracted = self._extractor.extract(content)
            debug_stats["extracted_count"] = len(extracted)

            logger.debug("[Security-Writeup] DEBUG: Fetch/Extract stats", **debug_stats)

            if not extracted:
                return None

            # Get best evidence
            best = max(extracted, key=lambda e: (
                0 if e.confidence == "high" else 1 if e.confidence == "medium" else 2,
                -len(e.content)
            ))

            # Detect artifact type from content
            artifact_type = self._detect_artifact_type(content, best)

            # Map evidence type to verification method
            verification_method = self._get_verification_method(best.evidence_type)

            # Extract event IDs
            event_ids = self._extractor.extract_event_ids(best.content)
            primary_event_id = event_ids[0] if event_ids else None

            logger.info(
                "[Security-Writeup] Found evidence",
                cve_id=cve_id,
                blog=config["name"],
                evidence_type=best.evidence_type.value,
                content_length=len(best.content),
            )

            return TelemetryArtifact(
                artifact_type=artifact_type,
                source_name=config["name"],
                source_type=TelemetrySourceType.SECURITY_WRITEUP,
                source_url=article_url or search_url,
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
                "[Security-Writeup] Extraction failed",
                cve_id=cve_id,
                blog=blog_id,
                error=str(exc)[:100],
            )
            return None

    def _extract_text_from_html(self, html: str) -> str:
        """Extract readable text from HTML, removing scripts, styles, and tags."""
        import re

        # Remove script and style tags with their content
        text = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)

        # Remove HTML tags but keep text
        text = re.sub(r'<[^>]+>', ' ', text)

        # Decode common HTML entities
        text = text.replace('&nbsp;', ' ')
        text = text.replace('&lt;', '<')
        text = text.replace('&gt;', '>')
        text = text.replace('&amp;', '&')
        text = text.replace('&quot;', '"')
        text = text.replace('&#39;', "'")

        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text)

        return text.strip()

    def _extract_article_links_from_search(self, html: str, cve_id: str) -> str | None:
        """Extract first article URL from search results page."""
        import re

        # Look for article links containing CVE ID
        cve_lower = cve_id.lower()
        cve_normalized = cve_id.upper().replace('-', '')

        # Common search result link patterns
        link_patterns = [
            r'href=["\']([^"\']*' + re.escape(cve_id.replace('-', '')) + r'[^"\']*)["\']',
            r'href=["\']([^"\']*' + re.escape(cve_id) + r'[^"\']*)["\']',
            r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>' + re.escape(cve_id),
        ]

        for pattern in link_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for url in matches:
                if url.startswith('http') and 'search' not in url.lower():
                    return url

        return None

    def _detect_artifact_type(self, content: str, evidence) -> TelemetryArtifactType:
        """Detect artifact type from content."""
        content_lower = content.lower()

        # Check for specific telemetry indicators
        if "sysmon" in content_lower or "<sysmon>" in content_lower:
            return TelemetryArtifactType.SYSMON
        if "windows" in content_lower and ("event" in content_lower or "security" in content_lower):
            return TelemetryArtifactType.WINDOWS_EVENT
        if "apache" in content_lower or "nginx" in content_lower or "access_log" in content_lower:
            return TelemetryArtifactType.APACHE_ACCESS_LOG
        if "zeek" in content_lower or "conn.log" in content_lower:
            return TelemetryArtifactType.ZEEK_CONN
        if "suricata" in content_lower or "eve.json" in content_lower:
            return TelemetryArtifactType.SURICATA_EVE
        if "dns" in content_lower:
            return TelemetryArtifactType.DNS_LOG
        if "pcap" in content_lower:
            return TelemetryArtifactType.PCAP

        # Check evidence content type
        ev_type = evidence.evidence_type.value if hasattr(evidence.evidence_type, 'value') else str(evidence.evidence_type)
        if ev_type == "xml":
            return TelemetryArtifactType.WINDOWS_EVENT
        if ev_type == "raw_log":
            return TelemetryArtifactType.JSON_EVENT

        return TelemetryArtifactType.APPLICATION_LOG

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
