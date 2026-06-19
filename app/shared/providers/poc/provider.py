"""PoC provider — orchestrates client → parser → credibility filter."""
from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.shared.providers.base import BaseProvider
from app.shared.providers.poc.client import PoCClientWrapper
from app.shared.providers.poc.parser import PoCParser
from app.shared.providers.poc.credibility import PoCCredibilityFilter


class PoCProvider(BaseProvider):
    """
    Fetches and validates public PoC references from nomi-sec/PoC-in-GitHub.

    Pipeline:
        PoCClientWrapper    → thin proxy over shared PoCHTTPClient
        PoCParser           → extract + normalize fields (no business logic)
        PoCCredibilityFilter → filter by stars/forks/name/keywords/recency
    """

    def __init__(self) -> None:
        self.client = PoCClientWrapper()
        self.parser = PoCParser()
        self.credibility = PoCCredibilityFilter()
        self.logger = get_logger(__name__)
        self.last_error_message: str | None = None

    async def enrich(self, cve_id: str) -> dict:
        self.logger.info("[PoC] Fetching CVE", cve_id=cve_id)
        self.last_error_message = None

        # Step 1: Fetch raw entries from nomi-sec
        raw = await self.client.fetch_raw(cve_id)
        if raw is None:
            # 404 → CVE has no known PoC, not an error
            return {"poc_references": None, "public_poc": False}

        # Step 2: Parse → extract structured fields
        parsed_entries = self.parser.normalize(raw, cve_id)

        # Step 3: Filter → keep only credible repos
        credible_urls = self.credibility.filter(parsed_entries, cve_id)

        count = len(credible_urls)
        self.logger.info("[PoC] Success", cve_id=cve_id, credible_count=count)

        if not credible_urls:
            return {"poc_references": None, "public_poc": False}

        return {
            "poc_references": credible_urls,
            "public_poc": True,
        }

    async def fetch(self, cve_id: str) -> Any:
        return await self.enrich(cve_id)
