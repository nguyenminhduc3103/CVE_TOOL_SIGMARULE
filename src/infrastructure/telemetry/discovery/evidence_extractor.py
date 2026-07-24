"""
Evidence Extractor - NO AI, parser/regex only.

Extracts VERBATIM telemetry evidence from content:
- Code blocks (```log ```, ```xml ```, ```text ```)
- File references (.log, .evtx, .pcap, .json)
- Section titles (Sample Log, Example, Detection, Telemetry, Observed Event)

Output is ALWAYS verbatim extracted content, never generated.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from src.domain.models.telemetry_discovery import EvidenceType


@dataclass
class ExtractedEvidence:
    """A piece of evidence extracted from content."""
    evidence_type: EvidenceType
    content: str
    source_section: str | None = None  # e.g., "Sample Log", "Detection Example"
    confidence: Literal["high", "medium", "low"] = "high"


class EvidenceExtractor:
    """Extract telemetry evidence from text using regex/parser only.

    NO AI - all extraction is done via pattern matching.
    Output is VERBATIM extracted content.
    """

    # Code block patterns (ordered by specificity - most specific first)
    CODE_BLOCK_PATTERNS = [
        # ```log ... ``` (with content between)
        (r'```log\s*\n(.*?)\n```', EvidenceType.RAW_LOG),
        # ```xml ... ``` (with content between)
        (r'```xml\s*\n(.*?)\n```', EvidenceType.XML),
        # ```text ... ``` (with content between)
        (r'```text\s*\n(.*?)\n```', EvidenceType.RAW_LOG),
        # ```json ... ``` (with content between)
        (r'```json\s*\n(.*?)\n```', EvidenceType.RAW_LOG),
    ]

    # Section headers that indicate telemetry
    SECTION_PATTERNS = [
        # Case-insensitive section headers
        r'(?:Sample\s+Log|Example\s+Log|Sample\s+Event|Detection\s+Example|Observed\s+Event|Telemetry\s+Sample)',
        r'(?:Event\s+Sample|Log\s+Example|Network\s+Event|DNS\s+Query)',
        r'(?:Sysmon\s+Event|Windows\s+Event|Access\s+Log|Error\s+Log)',
    ]

    # File reference patterns
    FILE_PATTERNS = [
        # EVTX file references
        (r'\b(\w+\.evtx)\b', EvidenceType.EVTX),
        # PCAP file references
        (r'\b(\w+\.pcap)\b', EvidenceType.PCAP),
        # Log file references
        (r'\b(\w+\.log)\b', EvidenceType.RAW_LOG),
        # JSON file references
        (r'\b(\w+\.json)\b', EvidenceType.RAW_LOG),
        # Zeek log references
        (r'\b(\w+\.(?:log|tsv|csv))\b', EvidenceType.RAW_LOG),
    ]

    # Apache/Nginx access log pattern
    APACHE_LOG_PATTERN = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+-\s+\S+\s+\[[\d\w:/]+\s+[+-]\d{4}\]\s+"[^"]+"\s+\d+\s+\d+'

    # Zeek connection log pattern (tab-separated)
    ZEEK_CONN_PATTERN = r'^\d+\.\d+\.\d+\.\d+\t\d+\t[\d.]+\t\d+\t(?:tcp|udp|icmp)'

    # Suricata eve.json pattern
    SURICATA_EVE_PATTERN = r'"event_type"\s*:\s*"(?:alert|flow|dns|http|smtp|tls|ssh|ftp)"'

    # Syslog pattern
    SYSLOG_PATTERN = r'^[A-Z][a-z]{2}\s+\d{1,2}\s+[\d:]+.*(?:kernel|systemd|sshd|CRON)'

    # Windows Event XML pattern
    WINDOWS_XML_PATTERN = r'<Event xmlns="[^"]+">.*?</Event>'

    # Event ID patterns in Windows events
    EVENT_ID_PATTERN = r'<EventID>(\d+)</EventID>'
    SYSMON_EVENT_PATTERN = r'(?:Sysmon\s+Event\s+ID?\s*:?\s*)(\d+)'

    def __init__(self, min_content_length: int = 10):
        """Initialize extractor.

        Args:
            min_content_length: Minimum length for extracted content to be valid
        """
        self.min_content_length = min_content_length

    def extract(self, content: str) -> list[ExtractedEvidence]:
        """Extract all evidence from content.

        Args:
            content: Raw text content to extract from (e.g., article, README)

        Returns:
            List of ExtractedEvidence objects with VERBATIM content
        """
        if not content or not content.strip():
            return []

        evidence_list = []

        # 1. Extract code blocks
        evidence_list.extend(self._extract_code_blocks(content))

        # 2. Extract section-based evidence
        evidence_list.extend(self._extract_sections(content))

        # 3. Extract file references
        evidence_list.extend(self._extract_file_refs(content))

        # Deduplicate and filter
        evidence_list = self._deduplicate(evidence_list)

        return evidence_list

    def _extract_code_blocks(self, content: str) -> list[ExtractedEvidence]:
        """Extract evidence from code blocks."""
        evidence_list = []

        for pattern, evidence_type in self.CODE_BLOCK_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                block_content = match.group(1).strip()
                if len(block_content) >= self.min_content_length:
                    # Determine section from surrounding context
                    section = self._get_section_context(content, match.start())

                    evidence_list.append(ExtractedEvidence(
                        evidence_type=evidence_type,
                        content=block_content,
                        source_section=section,
                    ))

        return evidence_list

    def _extract_sections(self, content: str) -> list[ExtractedEvidence]:
        """Extract evidence from sections with telemetry headers."""
        evidence_list = []

        for section_pattern in self.SECTION_PATTERNS:
            # Find section headers
            section_matches = list(re.finditer(section_pattern, content, re.IGNORECASE))

            for section_match in section_matches:
                section_start = section_match.end()
                section_name = section_match.group(0)

                # Extract content after the section header
                # Look for next section header or end of content
                remaining = content[section_start:section_start + 2000]  # Limit to 2000 chars

                # Find the actual content (skip blank lines)
                lines = remaining.split('\n')
                content_lines = []
                in_code_block = False

                for line in lines:
                    # Check for code block markers
                    if line.strip().startswith('```'):
                        in_code_block = not in_code_block
                        continue

                    if in_code_block:
                        content_lines.append(line)
                    elif line.strip() and not line.strip().startswith('#'):
                        # Check if this is another section header
                        if re.match(section_pattern, line, re.IGNORECASE):
                            break
                        content_lines.append(line)

                    # Stop if we hit another major section
                    if re.match(r'^#{1,3}\s+\w', line):
                        break

                section_content = '\n'.join(content_lines).strip()

                if len(section_content) >= self.min_content_length:
                    evidence_list.append(ExtractedEvidence(
                        evidence_type=EvidenceType.RAW_LOG,
                        content=section_content,
                        source_section=section_name,
                        confidence="medium",
                    ))

        return evidence_list

    def _extract_file_refs(self, content: str) -> list[ExtractedEvidence]:
        """Extract file references."""
        evidence_list = []

        for pattern, evidence_type in self.FILE_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                file_ref = match.group(1)
                section = self._get_section_context(content, match.start())

                # For file refs, we store the reference, not the content
                evidence_list.append(ExtractedEvidence(
                    evidence_type=evidence_type,
                    content=f"[File reference: {file_ref}]",
                    source_section=section,
                    confidence="low",
                ))

        return evidence_list

    def _get_section_context(self, content: str, position: int, window: int = 100) -> str | None:
        """Get the section header context around a position."""
        start = max(0, position - window)
        context = content[start:position]

        # Look for markdown headers
        header_match = re.search(r'(?:#{1,3}\s+[^\n]+)$', context, re.MULTILINE)
        if header_match:
            return header_match.group(0).strip()

        # Look for bold/italic headers
        bold_match = re.search(r'\*\*([^*]+)\*\*', context)
        if bold_match:
            return bold_match.group(1).strip()

        return None

    def _deduplicate(self, evidence_list: list[ExtractedEvidence]) -> list[ExtractedEvidence]:
        """Remove duplicate evidence based on content."""
        seen = set()
        unique = []

        for ev in evidence_list:
            # Use content hash for deduplication
            content_hash = hash(ev.content[:200])  # First 200 chars as key
            if content_hash not in seen:
                seen.add(content_hash)
                unique.append(ev)

        return unique

    def extract_event_ids(self, content: str) -> list[int]:
        """Extract Windows Event IDs from content."""
        event_ids = set()

        # From XML
        xml_matches = re.finditer(self.EVENT_ID_PATTERN, content)
        for match in xml_matches:
            try:
                event_ids.add(int(match.group(1)))
            except ValueError:
                pass

        # From text
        text_matches = re.finditer(self.SYSMON_EVENT_PATTERN, content, re.IGNORECASE)
        for match in text_matches:
            try:
                event_ids.add(int(match.group(1)))
            except ValueError:
                pass

        return sorted(list(event_ids))

    def get_evidence_summary(self, evidence_list: list[ExtractedEvidence]) -> str:
        """Generate a human-readable summary of evidence types found."""
        type_counts = {}
        for ev in evidence_list:
            type_name = ev.evidence_type.value
            type_counts[type_name] = type_counts.get(type_name, 0) + 1

        parts = []
        for ev_type, count in sorted(type_counts.items()):
            if count == 1:
                parts.append(ev_type)
            else:
                parts.append(f"{count}x {ev_type}")

        return ", ".join(parts) if parts else "No evidence found"

    def extract_debug_stats(self, content: str) -> dict:
        """Extract debug statistics from content WITHOUT doing full extraction.

        Returns stats to help debug why evidence wasn't found:
        - HTML length
        - Markdown length
        - Code block counts by type
        - Log pattern counts
        - File reference counts
        """
        import re

        stats = {
            "content_length": len(content) if content else 0,
            "html_length": 0,
            "markdown_length": 0,
            # Code block counts
            "code_blocks_log": 0,
            "code_blocks_xml": 0,
            "code_blocks_text": 0,
            "code_blocks_json": 0,
            "code_blocks_other": 0,
            # Pattern counts
            "apache_logs": 0,
            "zeek_logs": 0,
            "suricata_events": 0,
            "syslog_lines": 0,
            "windows_xml_events": 0,
            "event_ids": 0,
            # File references
            "evtx_refs": 0,
            "pcap_refs": 0,
            "log_refs": 0,
            "json_refs": 0,
            # Section headers
            "section_headers": 0,
        }

        if not content:
            return stats

        stats["html_length"] = len(content)

        # Count markdown sections (strip HTML tags)
        try:
            import re
            md_text = re.sub(r'<[^>]+>', ' ', content)
            stats["markdown_length"] = len(md_text.strip())
        except Exception:
            pass

        # Count code blocks by type
        log_blocks = re.findall(r'```log\s*\n(.*?)\n```', content, re.IGNORECASE | re.DOTALL)
        stats["code_blocks_log"] = len(log_blocks)

        xml_blocks = re.findall(r'```xml\s*\n(.*?)\n```', content, re.IGNORECASE | re.DOTALL)
        stats["code_blocks_xml"] = len(xml_blocks)

        text_blocks = re.findall(r'```text\s*\n(.*?)\n```', content, re.IGNORECASE | re.DOTALL)
        stats["code_blocks_text"] = len(text_blocks)

        json_blocks = re.findall(r'```json\s*\n(.*?)\n```', content, re.IGNORECASE | re.DOTALL)
        stats["code_blocks_json"] = len(json_blocks)

        # Count other code blocks
        other_blocks = re.findall(r'```(\w+)\s*\n', content)
        stats["code_blocks_other"] = len([b for b in other_blocks if b.lower() not in ('log', 'xml', 'text', 'json')])

        # Count log patterns
        stats["apache_logs"] = len(re.findall(self.APACHE_LOG_PATTERN, content))
        stats["zeek_logs"] = len(re.findall(self.ZEEK_CONN_PATTERN, content, re.MULTILINE))
        stats["suricata_events"] = len(re.findall(self.SURICATA_EVE_PATTERN, content))
        stats["syslog_lines"] = len(re.findall(self.SYSLOG_PATTERN, content, re.MULTILINE))
        stats["windows_xml_events"] = len(re.findall(self.WINDOWS_XML_PATTERN, content, re.DOTALL))

        # Count event IDs
        stats["event_ids"] = len(re.findall(self.EVENT_ID_PATTERN, content))

        # Count file references
        stats["evtx_refs"] = len(re.findall(r'\.evtx\b', content, re.IGNORECASE))
        stats["pcap_refs"] = len(re.findall(r'\.pcap\b', content, re.IGNORECASE))
        stats["log_refs"] = len(re.findall(r'\.log\b', content, re.IGNORECASE))
        stats["json_refs"] = len(re.findall(r'\.json\b', content, re.IGNORECASE))

        # Count section headers
        section_patterns = [
            r'Sample\s+Log', r'Example\s+Log', r'Sample\s+Event', r'Detection\s+Example',
            r'Observed\s+Event', r'Telemetry\s+Sample', r'Event\s+Sample', r'Log\s+Example',
        ]
        for pattern in section_patterns:
            stats["section_headers"] += len(re.findall(pattern, content, re.IGNORECASE))

        return stats


# Convenience function for quick extraction
def extract_evidence(content: str) -> list[ExtractedEvidence]:
    """Extract evidence from content using default extractor."""
    extractor = EvidenceExtractor()
    return extractor.extract(content)
