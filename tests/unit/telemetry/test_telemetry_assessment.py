"""Unit tests for Two-Phase Telemetry Discovery - Gate decision logic."""
from __future__ import annotations

import pytest

from src.domain.models.telemetry_discovery import (
    CandidateSource,
    EvidenceType,
    SourceConfidence,
    TelemetryArtifact,
    TelemetryArtifactType,
    TelemetryDiscovery,
    TelemetrySourceAssessment,
    TelemetrySourceType,
    VerificationMethod,
    VerificationStatus,
)


class TestTelemetryAssessmentGate:
    """Test gate decision logic for two-phase discovery."""

    def test_no_verified_artifacts_blocks(self):
        """0 verified artifacts → STOP_GATE (blocking=True).

        Even if there are candidates, gate should FAIL.
        """
        discovery = TelemetryDiscovery(cve_id="CVE-2021-44228")

        # Add candidates but NO verified artifacts
        discovery.add_candidate(CandidateSource(
            source_type=TelemetrySourceType.VENDOR_ADVISORY,
            source_name="Microsoft MSRC",
            verification_status=VerificationStatus.PENDING,
        ))
        discovery.add_candidate(CandidateSource(
            source_type=TelemetrySourceType.SECURITY_WRITEUP,
            source_name="Rapid7",
            verification_status=VerificationStatus.PENDING,
        ))

        assessment = TelemetrySourceAssessment.from_discovery(discovery)

        assert assessment.available is False
        assert assessment.verified_count == 0
        assert assessment.decision.value == "STOP_GATE"
        assert assessment.blocking is True
        assert assessment.candidate_count == 2  # Candidates exist
        assert assessment.confidence.value == "low"

    def test_single_verified_artifact_continues(self):
        """1 verified artifact WITH evidence → CONTINUE (not blocking)."""
        discovery = TelemetryDiscovery(cve_id="CVE-2021-44228")

        discovery.add_candidate(CandidateSource(
            source_type=TelemetrySourceType.POC_OUTPUT,
            source_name="PoC-in-GitHub",
        ))

        # CRITICAL: Artifact must have evidence_content to pass
        discovery.add_verified_artifact(TelemetryArtifact(
            artifact_type=TelemetryArtifactType.SYSMON,
            source_name="PoC-in-GitHub",
            source_type=TelemetrySourceType.POC_OUTPUT,
            verified=True,
            evidence_type=EvidenceType.XML,
            evidence_content="<Event><EventID>1</EventID></Event>",
            verification_method=VerificationMethod.RAW_EVENT,
            event_id=1,
            evidence_summary="Sysmon Event ID 1: Process Creation",
        ))

        assessment = TelemetrySourceAssessment.from_discovery(discovery)

        assert assessment.available is True
        assert assessment.verified_count == 1
        assert assessment.decision.value == "CONTINUE"
        assert assessment.blocking is False
        assert assessment.artifact_types == ["sysmon"]
        # Verify verified_evidence is populated
        assert len(assessment.verified_evidence) == 1
        assert assessment.verified_evidence[0]["source"] == "PoC-in-GitHub"
        assert assessment.verified_evidence[0]["event_id"] == 1
        assert assessment.verified_evidence[0]["verification"] == "raw_event"

    def test_three_verified_artifacts_high_confidence(self):
        """3+ verified artifacts WITH evidence → HIGH confidence."""
        discovery = TelemetryDiscovery(cve_id="CVE-2021-44228")

        # 3 verified artifacts - EACH MUST have evidence_content
        evidence_contents = [
            ("apache_access_log", EvidenceType.RAW_LOG, "192.168.1.1 - GET /"),
            ("sysmon", EvidenceType.XML, "<Event><EventID>1</EventID></Event>"),
            ("dns_log", EvidenceType.RAW_LOG, "query.example.com"),
        ]

        for artifact_type, ev_type, ev_content in evidence_contents:
            discovery.add_verified_artifact(TelemetryArtifact(
                artifact_type=TelemetryArtifactType[artifact_type.upper()],
                source_name="Various",
                source_type=TelemetrySourceType.PUBLIC_DATASET,
                verified=True,
                evidence_type=ev_type,
                evidence_content=ev_content,
            ))

        assessment = TelemetrySourceAssessment.from_discovery(discovery)

        assert assessment.verified_count == 3
        assert assessment.decision.value == "CONTINUE"
        assert assessment.confidence.value == "high"
        assert assessment.blocking is False

    def test_candidates_only_is_not_enough(self):
        """Having ONLY candidates (no verified artifacts) should FAIL gate."""
        discovery = TelemetryDiscovery(cve_id="CVE-2021-XXXX")

        # Add 5 candidates
        for i in range(5):
            discovery.add_candidate(CandidateSource(
                source_type=TelemetrySourceType.VENDOR_ADVISORY,
                source_name=f"Vendor-{i}",
                verification_status=VerificationStatus.PENDING,
            ))

        assessment = TelemetrySourceAssessment.from_discovery(discovery)

        # Should still FAIL because no verified artifacts
        assert assessment.verified_count == 0
        assert assessment.candidate_count == 5
        assert assessment.decision.value == "STOP_GATE"
        assert assessment.blocking is True
        assert "No verified telemetry artifacts" in assessment.reasoning


class TestTelemetryDiscovery:
    """Test TelemetryDiscovery helper methods."""

    def test_add_candidate(self):
        """Adding candidate sources."""
        discovery = TelemetryDiscovery(cve_id="CVE-2021-44228")

        discovery.add_candidate(CandidateSource(
            source_type=TelemetrySourceType.VENDOR_ADVISORY,
            source_name="Microsoft MSRC",
        ))

        assert len(discovery.candidate_sources) == 1
        assert discovery.candidate_sources[0].source_name == "Microsoft MSRC"

    def test_add_verified_artifact(self):
        """Adding verified artifacts with evidence."""
        discovery = TelemetryDiscovery(cve_id="CVE-2021-44228")

        # Artifact with evidence_content should be counted
        discovery.add_verified_artifact(TelemetryArtifact(
            artifact_type=TelemetryArtifactType.SYSMON,
            source_name="Rapid7",
            source_type=TelemetrySourceType.SECURITY_WRITEUP,
            verified=True,
            evidence_type=EvidenceType.XML,
            evidence_content="<Event><EventID>1</EventID></Event>",
        ))

        assert len(discovery.verified_artifacts) == 1
        assert discovery.get_verified_count() == 1  # With evidence_content = 1
        assert discovery.has_artifact_type(TelemetryArtifactType.SYSMON)

    def test_artifact_without_evidence_not_counted(self):
        """Artifact without evidence_content should NOT be counted."""
        discovery = TelemetryDiscovery(cve_id="CVE-2021-44228")

        # Artifact WITHOUT evidence_content should NOT count
        discovery.add_verified_artifact(TelemetryArtifact(
            artifact_type=TelemetryArtifactType.SYSMON,
            source_name="Rapid7",
            source_type=TelemetrySourceType.SECURITY_WRITEUP,
            verified=True,
            # No evidence_type or evidence_content
        ))

        assert len(discovery.verified_artifacts) == 1
        assert discovery.get_verified_count() == 0  # No evidence = 0
        assert discovery.has_artifact_type(TelemetryArtifactType.SYSMON)

    def test_get_artifact_types(self):
        """Get list of artifact types found."""
        discovery = TelemetryDiscovery(cve_id="CVE-2021-44228")

        discovery.add_verified_artifact(TelemetryArtifact(
            artifact_type=TelemetryArtifactType.SYSMON,
            source_name="Rapid7",
            source_type=TelemetrySourceType.SECURITY_WRITEUP,
        ))
        discovery.add_verified_artifact(TelemetryArtifact(
            artifact_type=TelemetryArtifactType.APACHE_ACCESS_LOG,
            source_name="Apache",
            source_type=TelemetrySourceType.VENDOR_ADVISORY,
        ))

        artifact_types = discovery.get_artifact_types()
        assert "sysmon" in artifact_types
        assert "apache_access_log" in artifact_types
        assert len(artifact_types) == 2


class TestTelemetryArtifact:
    """Test TelemetryArtifact functionality."""

    def test_to_sigma_logsource(self):
        """Convert artifact type to Sigma logsource."""
        artifact = TelemetryArtifact(
            artifact_type=TelemetryArtifactType.APACHE_ACCESS_LOG,
            source_name="Apache",
            source_type=TelemetrySourceType.VENDOR_ADVISORY,
        )

        assert artifact.to_sigma_logsource() == "apache_access_combined"

        artifact2 = TelemetryArtifact(
            artifact_type=TelemetryArtifactType.SYSMON,
            source_name="Rapid7",
            source_type=TelemetrySourceType.SECURITY_WRITEUP,
        )

        assert artifact2.to_sigma_logsource() == "sysmon"

    def test_verified_is_always_true(self):
        """Verified artifacts should always have verified=True."""
        artifact = TelemetryArtifact(
            artifact_type=TelemetryArtifactType.WINDOWS_EVENT,
            source_name="EVTX-ATTACK-SAMPLES",
            source_type=TelemetrySourceType.PUBLIC_DATASET,
        )

        assert artifact.verified is True
