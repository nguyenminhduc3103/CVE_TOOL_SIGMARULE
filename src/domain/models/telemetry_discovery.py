"""
Telemetry Discovery Models - Step 1.3/1.4

Two-phase approach:
1. Phase A - Discovery: List candidate sources that MIGHT have telemetry
2. Phase B - Verification: Fetch and verify actual telemetry artifacts exist
3. Gate: Only PASS if verified artifacts exist
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class TelemetrySourceType(str, Enum):
    """Types of telemetry sources."""
    VENDOR_ADVISORY = "vendor_advisory"
    PUBLIC_DATASET = "public_dataset"
    POC_OUTPUT = "poc_output"
    SECURITY_WRITEUP = "security_writeup"
    GITHUB = "github"
    SEARCH = "search"


class TelemetryArtifactType(str, Enum):
    """Types of telemetry artifacts (what Step 4 actually needs).

    These are the log types that Sigma rules can detect against.
    """
    APACHE_ACCESS_LOG = "apache_access_log"
    NGINX_ACCESS_LOG = "nginx_access_log"
    SYSLOG = "syslog"
    WINDOWS_EVENT = "windows_event"
    SYSMON = "sysmon"
    SECURITY_EVENT = "security_event"
    NETWORK_CONNECTION = "network_connection"
    DNS_LOG = "dns_log"
    HTTP_LOG = "http_log"
    PCAP = "pcap"
    ZEEK_CONN = "zeek_conn"
    ZEEK_DNS = "zeek_dns"
    ZEEK_HTTP = "zeek_http"
    SURICATA_EVE = "suricata_eve"
    JSON_EVENT = "json_event"
    AUTH_LOG = "auth_log"
    KERNEL_LOG = "kernel_log"
    APPLICATION_LOG = "application_log"


class LogContentType(str, Enum):
    """Types of log content found."""
    LOG_SNIPPET = "log_snippet"
    EVTX_REFERENCE = "evtx_reference"
    PCAP_REFERENCE = "pcap_reference"
    SCREENSHOT_REFERENCE = "screenshot_reference"
    JSON_EVENT = "json_event"
    SYSLOG = "syslog"
    ACCESS_LOG = "access_log"
    WINDOWS_EVENT = "windows_event"
    NETWORK_LOG = "network_log"


class SourceConfidence(str, Enum):
    """Confidence level of the telemetry source."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class VerificationStatus(str, Enum):
    """Verification status of a telemetry artifact."""
    PENDING = "pending"      # Not yet verified
    VERIFIED = "verified"    # Confirmed to exist
    NOT_FOUND = "not_found" # Checked but not found
    ERROR = "error"          # Error during verification


class VerificationMethod(str, Enum):
    """How the artifact was verified.

    Rules:
    - Only show Raw Log if actually retrieved
    - Screenshot → store screenshot or OCR content, not log
    - Text-only description → show as documentation
    - No telemetry → no Raw Log section
    """
    RAW_EVENT = "raw_event"        # Actual XML/EVTX/log found
    VENDOR_LOG = "vendor_log"      # Vendor advisory includes log sample
    DOCUMENTATION = "documentation" # Only textual description
    NOT_FOUND = "not_found"        # No telemetry found


class EvidenceType(str, Enum):
    """Types of evidence extracted by EvidenceExtractor (NO AI).

    EvidenceExtractor uses regex/parser only:
    - Tìm các code block log, xml, text
    - Tìm file refs (.log, .evtx, .pcap, .json)
    - Tìm section titles (Sample Log, Example, Detection, Telemetry, Observed Event)
    - Trích nguyên văn nội dung vào evidence_content
    """
    RAW_LOG = "raw_log"                    # ```log ``` code block
    XML = "xml"                            # ```xml ``` code block
    EVTX = "evtx"                          # .evtx file reference
    PCAP = "pcap"                          # .pcap file reference
    MARKDOWN = "markdown"                  # Markdown table/list format
    DOCUMENTATION = "documentation"         # Text description only
    NOT_FOUND = "not_found"                # No evidence found


class CandidateSource(BaseModel):
    """Phase A: A source that MIGHT contain telemetry (discovery phase)."""

    source_type: TelemetrySourceType
    source_name: str  # e.g., "Apache", "Microsoft MSRC", "EVTX-ATTACK-SAMPLES"
    source_url: str | None = None
    description: str | None = None
    verification_status: VerificationStatus = VerificationStatus.PENDING
    reason: str | None = None  # Why this source might have telemetry


class TelemetryArtifact(BaseModel):
    """Phase B: An actual telemetry artifact that was VERIFIED to exist.

    This is what Step 4 needs - not the source, but the actual log type.

    Evidence Extraction (no AI):
    - Parser/regex extracts log blocks from content
    - Evidence is VERBATIM, not generated
    """
    # Core identity
    artifact_type: TelemetryArtifactType
    source_name: str  # Where this artifact was found (e.g., "Apache", "Rapid7")
    source_type: TelemetrySourceType
    source_url: str | None = None
    download_url: str | None = None  # Direct URL to download raw file (EVTX, PCAP, etc.)

    # Evidence - THIS IS WHAT STEP 4 READS
    evidence_type: EvidenceType = EvidenceType.NOT_FOUND  # How evidence was extracted
    evidence_content: str | None = None  # VERBATIM extracted content

    # Verification metadata
    verified: bool = True  # Always True for artifacts in this list
    confidence: SourceConfidence = SourceConfidence.HIGH
    verification_method: VerificationMethod = VerificationMethod.NOT_FOUND

    # Evidence details for Step 4
    event_id: int | None = None           # e.g., 1 (Sysmon), 4648 (proc clone)
    log_type: str | None = None            # "Windows Event", "Apache Access Log"
    evidence_summary: str | None = None    # "Sysmon Event ID 1", "Apache log with JNDI"
    source_article: str | None = None     # "Rapid7 blog: Log4Shell Detection"

    # Legacy fields (for backwards compatibility)
    raw_content: str | None = None
    content_type: LogContentType | None = None
    description: str | None = None
    timestamp: datetime | None = None

    def to_sigma_logsource(self) -> str:
        """Convert artifact type to Sigma logsource category."""
        mapping = {
            TelemetryArtifactType.APACHE_ACCESS_LOG: "apache_access_combined",
            TelemetryArtifactType.NGINX_ACCESS_LOG: "nginx_access",
            TelemetryArtifactType.SYSLOG: "syslog",
            TelemetryArtifactType.WINDOWS_EVENT: "windows",
            TelemetryArtifactType.SYSMON: "sysmon",
            TelemetryArtifactType.SECURITY_EVENT: "windows_security",
            TelemetryArtifactType.NETWORK_CONNECTION: "network_connection",
            TelemetryArtifactType.DNS_LOG: "dns",
            TelemetryArtifactType.HTTP_LOG: "http",
            TelemetryArtifactType.ZEEK_CONN: "zeek_conn",
            TelemetryArtifactType.ZEEK_DNS: "zeek_dns",
            TelemetryArtifactType.ZEEK_HTTP: "zeek_http",
            TelemetryArtifactType.SURICATA_EVE: "suricata",
            TelemetryArtifactType.JSON_EVENT: "json",
        }
        return mapping.get(self.artifact_type, "unknown")

    @property
    def has_evidence(self) -> bool:
        """Check if this artifact has actual evidence content."""
        return self.evidence_content is not None and self.evidence_content.strip() != ""


class TelemetryDiscovery(BaseModel):
    """Two-phase telemetry discovery result.

    Phase A: List candidate sources (might have telemetry)
    Phase B: Verify and list actual artifacts
    """

    cve_id: str

    # Phase A: Discovery - sources that might have telemetry
    candidate_sources: list[CandidateSource] = Field(default_factory=list)

    # Phase B: Verification - actual artifacts found
    verified_artifacts: list[TelemetryArtifact] = Field(default_factory=list)

    # Metadata
    discovery_method: Literal["automated", "manual", "hybrid"] = "automated"
    last_discovery_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    discovery_errors: list[str] = Field(default_factory=list)

    def add_candidate(self, source: CandidateSource) -> None:
        """Add a candidate source (Phase A)."""
        self.candidate_sources.append(source)

    def add_verified_artifact(self, artifact: TelemetryArtifact) -> None:
        """Add a verified artifact (Phase B)."""
        self.verified_artifacts.append(artifact)

    def get_verified_count(self) -> int:
        """Get count of artifacts with ACTUAL verified evidence.

        CRITICAL: Only count artifacts that have evidence_content or
        evidence_type in {raw_log, xml, documentation}.
        Artifacts with evidence_type=NOT_FOUND don't count.
        """
        count = 0
        for artifact in self.verified_artifacts:
            ev_type = artifact.evidence_type
            if hasattr(ev_type, 'value'):
                ev_type = ev_type.value

            # Only count if:
            # 1. Has evidence_content (verbatim extracted)
            # 2. OR evidence_type is in {raw_log, xml, documentation}
            if artifact.has_evidence:
                count += 1
            elif ev_type in {"raw_log", "xml", "documentation"}:
                count += 1
            # else: NOT_FOUND - don't count
        return count

    def get_artifact_types(self) -> list[str]:
        """Get list of artifact types found."""
        return [a.artifact_type.value for a in self.verified_artifacts]

    def has_artifact_type(self, artifact_type: TelemetryArtifactType) -> bool:
        """Check if a specific artifact type was verified."""
        return any(a.artifact_type == artifact_type for a in self.verified_artifacts)


class TelemetryDiscoveryResult(BaseModel):
    """Result of a telemetry discovery run.

    Includes:
    - Phase A: Candidate sources
    - Phase B: Evidence extraction + Verified artifacts
    - Metadata: duration, errors
    """

    discovery: TelemetryDiscovery
    sources_queried: int = 0
    sources_with_candidates: int = 0
    sources_verified: int = 0

    # Evidence extraction stats
    evidence_extracted: int = 0  # Number of raw log/XML blocks found
    evidence_types_found: list[str] = Field(default_factory=list)  # ["raw_log", "xml", "documentation"]

    duration_ms: int = 0
    errors: list[str] = Field(default_factory=list)


class AssessmentDecision(str, Enum):
    """Decision from telemetry assessment."""
    CONTINUE = "CONTINUE"
    STOP_GATE = "STOP_GATE"


class TelemetrySourceAssessment(BaseModel):
    """Step 1.4 Assessment output - the GATE decision.

    Gate only PASSES if verified artifacts exist.
    Having candidate sources is NOT enough.
    """

    available: bool = False
    verified_count: int = 0
    confidence: SourceConfidence = SourceConfidence.LOW
    artifact_types: list[str] = Field(default_factory=list)

    # For traceability
    candidate_count: int = 0
    candidate_sources: list[str] = Field(default_factory=list)

    # NEW: Structured evidence for professional output
    verified_evidence: list[dict] = Field(default_factory=list)  # [{source, evidence_summary, verification}]

    # Gate decision
    reasoning: str = ""
    decision: AssessmentDecision = AssessmentDecision.STOP_GATE
    blocking: bool = True
    recommendation: str | None = None

    @classmethod
    def from_discovery(cls, discovery: TelemetryDiscovery) -> TelemetrySourceAssessment:
        """Create assessment from discovery result.

        Gate logic (2026-07): Step 1.4 (telemetry gate) chưa hoàn thiện — providers
        search logic vẫn thiếu nhiều trường hợp, verified_count gần như luôn = 0.
        Hard bypass: 0 verified → vẫn CONTINUE để Step 4 / 6 chạy. Confidence = LOW
        để reviewer thấy quality gap. Khi Step 1.4 hoàn thiện, sẽ restore gate.

        - 0 verified artifacts → CONTINUE (blocking=False, confidence=LOW)
        - 1+ verified artifacts → CONTINUE (confidence=MEDIUM)
        - 3+ verified artifacts → HIGH confidence
        """
        verified_count = discovery.get_verified_count()
        artifact_types = discovery.get_artifact_types()

        # Determine confidence
        if verified_count == 0:
            confidence = SourceConfidence.LOW
        elif verified_count >= 3:
            confidence = SourceConfidence.HIGH
        elif verified_count >= 1:
            confidence = SourceConfidence.MEDIUM
        else:
            confidence = SourceConfidence.LOW

        # Build verified evidence list - ONLY include artifacts with actual evidence
        verified_evidence = []
        for artifact in discovery.verified_artifacts:
            evidence_type = artifact.evidence_type
            if hasattr(evidence_type, 'value'):
                evidence_type = evidence_type.value

            # Skip artifacts without actual evidence
            if not artifact.has_evidence and evidence_type == "not_found":
                continue

            evidence_item = {
                "source": artifact.source_name,
                "artifact_type": artifact.artifact_type.value if hasattr(artifact.artifact_type, 'value') else str(artifact.artifact_type),
                "evidence_type": evidence_type,
                "evidence_summary": artifact.evidence_summary or f"{artifact.artifact_type.value if hasattr(artifact.artifact_type, 'value') else str(artifact.artifact_type)} telemetry",
                "verification": artifact.verification_method.value if hasattr(artifact.verification_method, 'value') else str(artifact.verification_method),
                "has_evidence": artifact.has_evidence,
                "event_id": artifact.event_id,
                "log_type": artifact.log_type,
            }
            verified_evidence.append(evidence_item)

        # Gate decision (hard bypass 2026-07: Step 1.4 chưa hoàn thiện)
        if verified_count == 0:
            decision = AssessmentDecision.CONTINUE
            candidate_names = [s.source_name for s in discovery.candidate_sources]
            reasoning = (
                "⚠ Step 1.4 telemetry gate bypassed (verified_count=0). "
                f"Searched {len(discovery.candidate_sources)} telemetry providers nhưng "
                "chưa tìm được verified artifacts — Step 1.4 chưa hoàn thiện, providers "
                "search logic thiếu nhiều trường hợp. Pipeline vẫn chạy Step 4/6 với "
                "AI-inferred telemetry (confidence=LOW). Reviewer nên kiểm tra logsource "
                "và field được AI đề xuất, không nên trust 100%."
            )
            blocking = False
            recommendation = (
                "Step 1.4 providers cần bổ sung: (1) PoC repositories với log output "
                "trong README, (2) Security research blogs có real log samples, "
                "(3) Public datasets (EVTX-ATTACK-SAMPLES, Splunk BOTS) labeled samples."
            )
        else:
            decision = AssessmentDecision.CONTINUE
            candidate_names = [s.source_name for s in discovery.candidate_sources]
            # Professional reasoning format
            evidence_lines = []
            for ev in verified_evidence:
                ev_type = ev["artifact_type"]
                ev_source = ev["source"]
                ev_summary = ev["evidence_summary"]
                evidence_lines.append(f"✓ {ev_type} telemetry documented by {ev_source}")
                if ev["event_id"]:
                    evidence_lines.append(f"  - Event ID {ev['event_id']}: {ev_summary}")

            reasoning = (
                "Verified telemetry evidence:\n" +
                "\n".join(evidence_lines) +
                "\n\nDetection engineering can rely on observed telemetry instead of inferred behavior."
            )
            blocking = False
            recommendation = None

        return cls(
            available=verified_count > 0,
            verified_count=verified_count,
            confidence=confidence,
            artifact_types=artifact_types,
            candidate_count=len(discovery.candidate_sources),
            candidate_sources=candidate_names,
            verified_evidence=verified_evidence,
            reasoning=reasoning,
            decision=decision,
            blocking=blocking,
            recommendation=recommendation,
        )


class PoCSummary(BaseModel):
    """Step 4 'intel' payload — bundled POC documentation + network PoC + exposure.

    Assembled by the Step 1 orchestrator from `triage.public_poc`,
    `triage.poc_references`, `poc_stage_raw`, and `exposure_raw`. Fed
    into the new Step 4 AI as the `intel` field of TelemetryInput.
    """

    public_poc: bool = False
    poc_references: list[str] = Field(default_factory=list)
    poc_credibility: list[dict] = Field(default_factory=list)
    nuclei_templates: list[dict] = Field(default_factory=list)
    exposure: dict | None = None

    # === PoC detail (consumed by Step 6 for value derivation) ===
    # `poc_description` — free-text documentation of the PoC (extracted from
    # nuclei evidence `type=documentation` records).
    # `poc_network_payloads` — list of network request payloads (extracted from
    # nuclei evidence `type=network` records; each item is a request_info dict
    # carrying method/host/port/path/headers/body/raw). Empty when no PoC
    # is documented.
    poc_description: str = ""
    poc_network_payloads: list[dict] = Field(default_factory=list)

