"""Regression tests cho 2 bug fixes Step 1:

Bug #1: NVD 503 phải fallback sang MITRE cveawg mirror.
Bug #2: OTX fail phải mark provider_status="failed" (không "success").

Dùng asyncio.run() thay vì pytest.mark.asyncio để tránh dependency mới
(đồng bộ với pattern của test_step2_two_phase.py).
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import MagicMock

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import httpx
import pytest

from app.shared.clients.nvd_client import NVDHTTPClient
from app.shared.clients.otx_client import OTXFetchError, OTXHTTPClient


# ---------------------------------------------------------------------------
# Bug #1: NVD mirror fallback
# ---------------------------------------------------------------------------
class TestNVDMirrorFallback:
    """Khi NVD 503, phải tự động fallback sang MITRE cveawg."""

    def test_mitre_response_normalized_to_nvd_shape(self):
        """MITRE raw payload phải được normalize về NVD 2.0 envelope."""
        mitre_raw = {
            "cveMetadata": {
                "cveId": "CVE-2021-3156",
                "datePublished": "2021-01-26T00:00:00",
                "dateUpdated": "2021-04-06T00:00:00",
            },
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "Heap overflow in sudo"}],
                    "metrics": [{"cvssV3_1": {"baseScore": 7.8}}],
                    "problemTypes": [{"cweId": "CWE-122"}],
                    "references": [{"url": "https://example.com"}],
                    "affected": [{"vendor": "sudo"}],
                }
            },
        }
        normalized = NVDHTTPClient._normalize_mitre_to_nvd_shape(mitre_raw)
        assert "vulnerabilities" in normalized
        cve = normalized["vulnerabilities"][0]["cve"]
        assert cve["id"] == "CVE-2021-3156"
        assert cve["descriptions"][0]["value"] == "Heap overflow in sudo"
        assert cve["weaknesses"][0]["description"][0]["value"] == "CWE-122"
        assert cve["references"][0]["url"] == "https://example.com"
        assert cve["published"] == "2021-01-26T00:00:00"

    def test_mirror_method_directly_returns_normalized_data(self):
        """Test _fetch_from_mirror trực tiếp + adapter normalize."""
        async def scenario():
            from app.shared.clients.base import BaseHTTPClient
            from unittest.mock import AsyncMock, MagicMock

            nvd = NVDHTTPClient(timeout=5)

            # Mock BaseHTTPClient.get trả về MITRE shape
            mitre_raw = {
                "cveMetadata": {"cveId": "CVE-2021-3156"},
                "containers": {
                    "cna": {
                        "descriptions": [{"lang": "en", "value": "Heap overflow in sudo"}],
                    }
                },
            }
            fake_response = MagicMock()
            fake_response.status_code = 200
            fake_response.headers = {"content-type": "application/json"}
            fake_response.json = MagicMock(return_value=mitre_raw)
            fake_response.raise_for_status = MagicMock()

            original_get = BaseHTTPClient.get
            BaseHTTPClient.get = AsyncMock(return_value=fake_response)
            try:
                result = await nvd._fetch_from_mirror("CVE-2021-3156")
            finally:
                BaseHTTPClient.get = original_get

            # Adapter phải convert MITRE → NVD shape
            assert "vulnerabilities" in result
            assert result["vulnerabilities"][0]["cve"]["id"] == "CVE-2021-3156"
            assert result["vulnerabilities"][0]["cve"]["descriptions"][0]["value"] == "Heap overflow in sudo"

        asyncio.run(scenario())

    def test_mitre_mirror_constant_defined(self):
        """NVDHTTPClient phải có MITRE mirror URL constant."""
        assert hasattr(NVDHTTPClient, "MIRROR_URL")
        assert "cveawg.mitre.org" in NVDHTTPClient.MIRROR_URL or "mitre" in NVDHTTPClient.MIRROR_URL.lower()


# ---------------------------------------------------------------------------
# Bug #2: OTX failure detection
# ---------------------------------------------------------------------------
class TestOTXFailurePropagation:
    """Khi OTX network fail, phải raise (không return {}) → provider_status='failed'."""

    def test_otx_network_error_raises_otx_fetch_error(self):
        """Network exception phải raise OTXFetchError, không return {}."""
        async def scenario():
            otx = OTXHTTPClient(base_url="https://otx.alienvault.com", timeout=5)

            async def fake_get(url, **kwargs):
                raise httpx.ConnectError("Connection refused")

            otx.get = fake_get

            with pytest.raises(OTXFetchError):
                await otx.fetch_raw("CVE-2021-3156")

        asyncio.run(scenario())

    def test_otx_404_returns_empty_dict(self):
        """404 = CVE genuinely không có trên OTX → return {} (không raise)."""
        async def scenario():
            otx = OTXHTTPClient(base_url="https://otx.alienvault.com", timeout=5)

            response_404 = MagicMock()
            response_404.status_code = 404
            response_404.headers = {"content-type": "application/json"}

            async def fake_get(url, **kwargs):
                return response_404

            otx.get = fake_get

            result = await otx.fetch_raw("CVE-FAKE-NONE")
            assert result == {}

        asyncio.run(scenario())

    def test_otx_500_raises_otx_fetch_error(self):
        """HTTP 500 phải raise (qua raise_for_status)."""
        async def scenario():
            otx = OTXHTTPClient(base_url="https://otx.alienvault.com", timeout=5)

            response_500 = MagicMock()
            response_500.status_code = 500
            response_500.headers = {"content-type": "text/html"}
            response_500.text = "Internal Server Error"
            response_500.raise_for_status = MagicMock(
                side_effect=httpx.HTTPStatusError(
                    "500", request=MagicMock(), response=response_500
                )
            )

            async def fake_get(url, **kwargs):
                return response_500

            otx.get = fake_get

            with pytest.raises(OTXFetchError):
                await otx.fetch_raw("CVE-2021-3156")

        asyncio.run(scenario())


# ---------------------------------------------------------------------------
# Bug #2c: Orchestrator defensive empty-dict check
# ---------------------------------------------------------------------------
class TestOrchestratorProviderStatus:
    """Provider trả empty dict {} → provider_status='failed' (defensive depth)."""

    def test_empty_dict_provider_marked_failed(self):
        async def scenario():
            from app.steps.step_1_triage.orchestrator import TriageOrchestrator

            orch = TriageOrchestrator.__new__(TriageOrchestrator)
            orch.logger = MagicMock()

            fake_provider = MagicMock()
            fake_provider.last_error_message = "client returned empty"

            async def fake_fetch(_cve_id):
                return {}  # Empty dict (bug cũ của OTX)

            provider_status: dict = {}
            provider_errors: dict = {}
            provider_durations: dict = {}

            result = await orch._run_provider(
                "test_provider",
                fake_provider,
                fake_fetch,
                "CVE-2021-3156",
                provider_status,
                provider_errors,
                provider_durations,
            )

            assert result is None
            assert provider_status["test_provider"] == "failed"
            assert "empty" in provider_errors["test_provider"].lower()

        asyncio.run(scenario())

    def test_dict_with_keys_marked_success(self):
        """Dict có keys (kể cả value None) vẫn là success."""
        async def scenario():
            from app.steps.step_1_triage.orchestrator import TriageOrchestrator

            orch = TriageOrchestrator.__new__(TriageOrchestrator)
            orch.logger = MagicMock()

            fake_provider = MagicMock()
            fake_provider.last_error_message = None

            async def fake_fetch(_cve_id):
                return {"threat_actors": [], "raw": None}  # Valid shape

            provider_status: dict = {}
            provider_errors: dict = {}
            provider_durations: dict = {}

            result = await orch._run_provider(
                "test_provider",
                fake_provider,
                fake_fetch,
                "CVE-2021-3156",
                provider_status,
                provider_errors,
                provider_durations,
            )

            assert result is not None
            assert provider_status["test_provider"] == "success"

        asyncio.run(scenario())
