"""Unit tests for EvidenceExtractor."""
from __future__ import annotations

import pytest

from src.domain.models.telemetry_discovery import EvidenceType, TelemetryArtifactType
from src.infrastructure.telemetry.discovery.evidence_extractor import (
    EvidenceExtractor,
    ExtractedEvidence,
    extract_evidence,
)


class TestEvidenceExtractor:
    """Test EvidenceExtractor functionality."""

    def test_extract_xml_block(self):
        """Extract XML code block."""
        content = '''
## Detection Example

```xml
<Event>
  <EventID>1</EventID>
  <Image>cmd.exe</Image>
</Event>
```
'''
        extractor = EvidenceExtractor()
        evidence = extractor.extract(content)

        assert len(evidence) >= 1
        xml_evidence = [e for e in evidence if e.evidence_type == EvidenceType.XML]
        assert len(xml_evidence) >= 1
        assert "<EventID>1</EventID>" in xml_evidence[0].content

    def test_extract_log_block(self):
        """Extract log code block."""
        content = '''
## Sample Log

```log
192.168.1.1 - - [10/Dec/2021]
GET / HTTP/1.1
User-Agent: test
```
'''
        extractor = EvidenceExtractor()
        evidence = extractor.extract(content)

        assert len(evidence) >= 1
        log_evidence = [e for e in evidence if e.evidence_type == EvidenceType.RAW_LOG]
        assert len(log_evidence) >= 1
        assert "192.168.1.1" in log_evidence[0].content

    def test_extract_file_references(self):
        """Extract file references."""
        content = '''
## Event Samples

The following files contain sample events:
- process_creation.evtx
- network.evtx

And logs:
- connection.log
'''
        extractor = EvidenceExtractor()
        evidence = extractor.extract(content)

        evtx_refs = [e for e in evidence if e.evidence_type == EvidenceType.EVTX]
        assert len(evtx_refs) >= 1

    def test_extract_event_ids(self):
        """Extract Windows Event IDs."""
        content = '''
Sysmon Event ID 1: Process Creation
<EventID>3</EventID>
<EventID>4688</EventID>
'''
        extractor = EvidenceExtractor()
        event_ids = extractor.extract_event_ids(content)

        assert 1 in event_ids
        assert 3 in event_ids
        assert 4688 in event_ids

    def test_deduplication(self):
        """Duplicate content should be deduplicated."""
        content = '''
```log
192.168.1.1 - GET / HTTP/1.1
```

```log
192.168.1.1 - GET / HTTP/1.1
```
'''
        extractor = EvidenceExtractor()
        evidence = extractor.extract(content)

        # Should only have one unique evidence (duplicates removed)
        assert len(evidence) == 1
        # The content should be identical
        assert evidence[0].content == "192.168.1.1 - GET / HTTP/1.1"

    def test_min_content_length(self):
        """Short content should be filtered."""
        content = '''
```xml
<EventID>1</EventID>
```
'''
        extractor = EvidenceExtractor(min_content_length=50)
        evidence = extractor.extract(content)

        assert len(evidence) == 0

    def test_empty_content(self):
        """Empty content returns empty list."""
        extractor = EvidenceExtractor()
        evidence = extractor.extract("")
        assert evidence == []

        evidence = extractor.extract(None)
        assert evidence == []

    def test_get_evidence_summary(self):
        """Generate summary of evidence types."""
        extractor = EvidenceExtractor()
        evidence = [
            ExtractedEvidence(EvidenceType.XML, "<Event/>", confidence="high"),
            ExtractedEvidence(EvidenceType.RAW_LOG, "log line", confidence="high"),
            ExtractedEvidence(EvidenceType.XML, "<Event/>", confidence="high"),
        ]

        summary = extractor.get_evidence_summary(evidence)
        assert "xml" in summary
        assert "raw_log" in summary


class TestExtractedEvidence:
    """Test ExtractedEvidence dataclass."""

    def test_basic_creation(self):
        """Create basic evidence."""
        evidence = ExtractedEvidence(
            evidence_type=EvidenceType.XML,
            content="<Event/>",
        )
        assert evidence.evidence_type == EvidenceType.XML
        assert evidence.content == "<Event/>"
        assert evidence.source_section is None
        assert evidence.confidence == "high"

    def test_with_context(self):
        """Create evidence with section context."""
        evidence = ExtractedEvidence(
            evidence_type=EvidenceType.RAW_LOG,
            content="192.168.1.1 - -",
            source_section="Sample Log",
            confidence="medium",
        )
        assert evidence.source_section == "Sample Log"
        assert evidence.confidence == "medium"
