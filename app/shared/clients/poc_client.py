"""PoC HTTP client — fetches from nomi-sec/PoC-in-GitHub (raw GitHub JSON).

nomi-sec lưu mỗi CVE thành 1 file JSON:
  https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{YEAR}/{CVE-ID}.json
"""
from __future__ import annotations

import httpx

from app.shared.clients.base import BaseHTTPClient
from app.core.logging import get_logger

_BASE_RAW = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"

logger = get_logger(__name__)


class PoCHTTPClient(BaseHTTPClient):
    """HTTP client for nomi-sec/PoC-in-GitHub raw JSON files."""

    def __init__(self, timeout: float = 10.0) -> None:
        super().__init__(base_url="", timeout=timeout)

    def _extract_year(self, cve_id: str) -> str | None:
        """Extract year from CVE-YYYY-NNNNN format."""
        parts = cve_id.upper().split("-")
        if len(parts) >= 2 and parts[1].isdigit() and len(parts[1]) == 4:
            return parts[1]
        return None

    async def fetch_raw(self, cve_id: str) -> list[dict] | None:
        """
        Fetch PoC entries for a given CVE ID.

        Returns:
            List of raw entry dicts on success.
            None if CVE has no PoC (404) or on network/parse error.
        """
        year = self._extract_year(cve_id)
        if not year:
            logger.warning("[PoC] Invalid CVE format", cve_id=cve_id)
            return None

        url = f"{_BASE_RAW}/{year}/{cve_id.upper()}.json"
        logger.info("[PoC] Fetching", cve_id=cve_id, url=url)

        try:
            response = await self.get(
                url,
                headers={"User-Agent": "cve-ti-platform/1.0"},
                follow_redirects=True,
            )

            if response.status_code == 404:
                logger.info("[PoC] No PoC found (404)", cve_id=cve_id)
                return None

            response.raise_for_status()
            data = response.json()

            if isinstance(data, list):
                logger.info("[PoC] Raw entries fetched", cve_id=cve_id, count=len(data))
                return data
            return None

        except httpx.TimeoutException:
            logger.warning("[PoC] Request timeout", cve_id=cve_id)
            return None
        except httpx.HTTPStatusError as exc:
            logger.warning("[PoC] HTTP error", cve_id=cve_id, status=exc.response.status_code)
            return None
        except Exception as exc:
            logger.warning("[PoC] Unexpected error", cve_id=cve_id, error=str(exc).splitlines()[0])
            return None
