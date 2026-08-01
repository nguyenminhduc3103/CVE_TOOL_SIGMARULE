"""Unit tests for ATTCK RAG Service."""

import pytest
from unittest.mock import patch, MagicMock
import numpy as np

from src.infrastructure.rag.models import RetrievedTechnique, RAGQuery
from src.infrastructure.rag.attck_rag_service import ATTCKRAGService


class TestRetrievedTechnique:
    """Tests for RetrievedTechnique dataclass."""

    def test_retrieved_technique_creation(self):
        """Test creating a RetrievedTechnique object."""
        technique = RetrievedTechnique(
            t_code="T1190",
            name="Exploit Public-Facing Application",
            tactics=["TA0001"],
            confidence=0.91,
            match_reason="high semantic similarity",
            behavior_anchor="public_application_exploitation",
            description="The adversary is trying to exploit public-facing applications...",
        )

        assert technique.t_code == "T1190"
        assert technique.name == "Exploit Public-Facing Application"
        assert technique.tactics == ["TA0001"]
        assert technique.confidence == 0.91
        assert technique.behavior_anchor == "public_application_exploitation"

    def test_retrieved_technique_defaults(self):
        """Test RetrievedTechnique default values."""
        technique = RetrievedTechnique(
            t_code="T1059",
            name="Command and Scripting Interpreter",
        )

        assert technique.tactics == []
        assert technique.confidence == 0.0
        assert technique.match_reason == ""
        assert technique.behavior_anchor is None


class TestRAGQuery:
    """Tests for RAGQuery dataclass."""

    def test_rag_query_creation(self):
        """Test creating a RAGQuery object."""
        query = RAGQuery(
            cve_id="CVE-2021-44228",
            cve_description="Apache Log4j2 JNDI features...",
            mandatory_behaviors=["code_execution", "ldap_injection"],
            poc_evidence="${jndi:ldap://...}",
            top_k=5,
        )

        assert query.cve_id == "CVE-2021-44228"
        assert len(query.mandatory_behaviors) == 2
        assert query.top_k == 5

    def test_rag_query_defaults(self):
        """Test RAGQuery default values."""
        query = RAGQuery(
            cve_id="CVE-2021-44228",
            cve_description="Test description",
        )

        assert query.mandatory_behaviors == []
        assert query.poc_evidence is None
        assert query.top_k == 5
        assert query.confidence_threshold == 0.5


class TestATTCKRAGService:
    """Tests for ATTCKRAGService class."""

    @pytest.fixture
    def mock_ttp_data(self):
        """Mock TTP mapping data."""
        return {
            "T1190": {
                "name": "Exploit Public-Facing Application",
                "description": "Adversaries may exploit public-facing applications...",
                "tactics": ["TA0001"],
                "parent": None,
                "children": [],
            },
            "T1203": {
                "name": "Exploitation for Client Execution",
                "description": "Adversaries may exploit software...",
                "tactics": ["TA0002"],
                "parent": None,
                "children": [],
            },
            "T1071": {
                "name": "Application Layer Protocol",
                "description": "Adversaries may communicate using application layer protocols...",
                "tactics": ["TA0011"],
                "parent": None,
                "children": [],
            },
        }

    def test_build_query_text(self, mock_ttp_data):
        """Test query text building."""
        with patch.object(ATTCKRAGService, "_load_and_index"):
            service = ATTCKRAGService(lazy_load=True)

        query_text = service._build_query_text(
            cve_id="CVE-2021-44228",
            description="Apache Log4j2 JNDI features...",
            behaviors=["code_execution", "ldap_injection"],
            poc="${jndi:ldap://...}",
        )

        assert "CVE-2021-44228" in query_text
        assert "code_execution, ldap_injection" in query_text
        assert "Apache Log4j2 JNDI" in query_text
        assert "${jndi:ldap://...}" in query_text

    def test_build_query_text_without_behaviors(self, mock_ttp_data):
        """Test query text building without behaviors."""
        with patch.object(ATTCKRAGService, "_load_and_index"):
            service = ATTCKRAGService(lazy_load=True)

        query_text = service._build_query_text(
            cve_id="CVE-2021-44228",
            description="Apache Log4j2 JNDI features...",
            behaviors=[],
            poc=None,
        )

        assert "unknown" in query_text
        assert "N/A" in query_text

    def test_build_technique_text(self):
        """Test technique text building."""
        with patch.object(ATTCKRAGService, "_load_and_index"):
            service = ATTCKRAGService(lazy_load=True)

        text = service._build_technique_text(
            t_code="T1190",
            name="Exploit Public-Facing Application",
            description="Adversaries may exploit public-facing applications to gain initial access.",
            tactics=["TA0001"],
        )

        assert "T1190" in text
        assert "Exploit Public-Facing Application" in text
        assert "Adversaries may exploit" in text

    def test_build_technique_text_truncates_long_description(self):
        """Test that long descriptions are truncated."""
        with patch.object(ATTCKRAGService, "_load_and_index"):
            service = ATTCKRAGService(lazy_load=True)

        long_desc = "A" * 600  # > 500 chars
        text = service._build_technique_text(
            t_code="T1190",
            name="Test",
            description=long_desc,
            tactics=["TA0001"],
        )

        assert len(text) < len(long_desc) + 50  # Should be truncated

    def test_match_behavior_anchor_exact_match(self):
        """Test behavior anchor matching with exact match."""
        with patch.object(ATTCKRAGService, "_load_and_index"):
            service = ATTCKRAGService(lazy_load=True)

        result = service._match_behavior_anchor(
            behaviors=["ldap_injection"],
            technique_name="LDAP Injection",
            technique_desc="LDAP injection attacks...",
        )

        assert result == "ldap_injection"

    def test_match_behavior_anchor_partial_match(self):
        """Test behavior anchor matching with partial match."""
        with patch.object(ATTCKRAGService, "_load_and_index"):
            service = ATTCKRAGService(lazy_load=True)

        result = service._match_behavior_anchor(
            behaviors=["public_application_exploitation"],
            technique_name="Exploit Public-Facing Application",
            technique_desc="Attackers exploit public web applications...",
        )

        assert result == "public_application_exploitation"

    def test_match_behavior_anchor_no_match(self):
        """Test behavior anchor matching with no match."""
        with patch.object(ATTCKRAGService, "_load_and_index"):
            service = ATTCKRAGService(lazy_load=True)

        result = service._match_behavior_anchor(
            behaviors=["ransomware_behavior"],
            technique_name="Exploit Public-Facing Application",
            technique_desc="Web application exploitation...",
        )

        assert result is None

    def test_match_behavior_anchor_empty_behaviors(self):
        """Test behavior anchor matching with empty behaviors."""
        with patch.object(ATTCKRAGService, "_load_and_index"):
            service = ATTCKRAGService(lazy_load=True)

        result = service._match_behavior_anchor(
            behaviors=[],
            technique_name="LDAP Injection",
            technique_desc="LDAP injection attacks...",
        )

        assert result is None

    def test_build_match_reason(self):
        """Test match reason building."""
        with patch.object(ATTCKRAGService, "_load_and_index"):
            service = ATTCKRAGService(lazy_load=True)

        metadata = {
            "name": "Exploit Public-Facing Application",
            "description": "Web application exploitation...",
        }

        reason = service._build_match_reason(
            cve_description="Apache Log4j...",
            behaviors=["code_execution", "ldap_injection"],
            metadata=metadata,
            confidence=0.85,
        )

        assert "high semantic similarity" in reason or "moderate semantic similarity" in reason
        assert "code_execution" in reason or "ldap_injection" in reason

    def test_build_match_reason_high_confidence(self):
        """Test match reason with high confidence."""
        with patch.object(ATTCKRAGService, "_load_and_index"):
            service = ATTCKRAGService(lazy_load=True)

        reason = service._build_match_reason(
            cve_description="Test",
            behaviors=[],
            metadata={"name": "Test Technique"},
            confidence=0.92,
        )

        assert "high semantic similarity" in reason

    def test_build_match_reason_low_confidence(self):
        """Test match reason with low confidence."""
        with patch.object(ATTCKRAGService, "_load_and_index"):
            service = ATTCKRAGService(lazy_load=True)

        reason = service._build_match_reason(
            cve_description="Test",
            behaviors=[],
            metadata={"name": "Test Technique"},
            confidence=0.45,
        )

        assert "weak semantic similarity" in reason

    def test_is_loaded_property(self):
        """Test is_loaded property."""
        with patch.object(ATTCKRAGService, "_load_and_index"):
            service = ATTCKRAGService(lazy_load=True)

            assert service.is_loaded is False

    def test_technique_count_property(self):
        """Test technique_count property."""
        with patch.object(ATTCKRAGService, "_load_and_index"):
            service = ATTCKRAGService(lazy_load=True)

            assert service.technique_count == 0


class TestATTCKRAGServiceIntegration:
    """Integration tests for ATTCKRAGService (requires actual data)."""

    def test_retrieve_techniques_returns_list(self):
        """Test that retrieve_techniques returns a list."""
        # This test requires the actual TTP data file
        # Skip if file doesn't exist
        import os
        ttp_file = ".cache/ontology/ATT_CK_TTPs/TTPs_mapping.json"

        if not os.path.exists(ttp_file):
            pytest.skip(f"TTP file not found: {ttp_file}")

        service = ATTCKRAGService()

        results = service.retrieve_techniques(
            cve_id="CVE-2021-44228",
            cve_description="Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
            mandatory_behaviors=["code_execution", "ldap_injection", "public_application_exploitation"],
            poc_evidence="${jndi:ldap://...",
            top_k=3,
        )

        assert isinstance(results, list)
        assert len(results) <= 3

        for result in results:
            assert isinstance(result, RetrievedTechnique)
            assert result.t_code.startswith("T")
            assert result.name
            assert 0.0 <= result.confidence <= 1.0

    def test_retrieve_with_query(self):
        """Test retrieve_with_query method."""
        import os
        ttp_file = ".cache/ontology/ATT_CK_TTPs/TTPs_mapping.json"

        if not os.path.exists(ttp_file):
            pytest.skip(f"TTP file not found: {ttp_file}")

        service = ATTCKRAGService()

        query = RAGQuery(
            cve_id="CVE-2021-44228",
            cve_description="Apache Log4j2 JNDI features...",
            mandatory_behaviors=["ldap_injection"],
            poc_evidence="${jndi:ldap://...",
            top_k=3,
        )

        results = service.retrieve_with_query(query)

        assert isinstance(results, list)
        assert len(results) <= 3


class TestRAGServiceSingleton:
    """Tests for the singleton pattern."""

    def test_get_rag_service_returns_instance(self):
        """Test that get_rag_service returns an instance."""
        from src.infrastructure.rag.attck_rag_service import get_rag_service

        service = get_rag_service()
        assert isinstance(service, ATTCKRAGService)

    def test_get_rag_service_returns_same_instance(self):
        """Test that get_rag_service returns the same instance."""
        from src.infrastructure.rag.attck_rag_service import get_rag_service, _rag_service_instance

        # Reset singleton for test isolation
        import src.infrastructure.rag.attck_rag_service as rag_module
        rag_module._rag_service_instance = None

        service1 = get_rag_service()
        service2 = get_rag_service()

        assert service1 is service2
