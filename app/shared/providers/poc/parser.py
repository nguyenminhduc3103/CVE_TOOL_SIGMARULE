"""PoC parser — pure data extraction from nomi-sec raw entries.

TODO boundaries (same as NVD parser):
- no HTTP logic here
- no business scoring / credibility logic here
- keep parsing deterministic and resilient to missing fields
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)


class PoCParser:
    """
    Normalize raw nomi-sec entry list into a list of structured dicts.

    Each output dict contains the fields downstream components need —
    both the html_url (for output) and metadata fields (for credibility
    filtering by PoCCredibilityFilter).
    """

    def normalize(self, raw_entries: list[dict[str, Any]], cve_id: str) -> list[dict[str, Any]]:
        """
        Extract relevant fields from each nomi-sec entry.

        Returns:
            List of structured entry dicts. Empty list if input is empty or invalid.
            Does NOT filter — returns all entries that have a valid html_url.
        """
        logger.info("[PoC] Parsing CVE data", cve_id=cve_id)

        if not isinstance(raw_entries, list):
            return []

        parsed: list[dict[str, Any]] = []
        for entry in raw_entries:
            if not isinstance(entry, dict):
                continue

            html_url = self._to_str(entry.get("html_url"))
            if not html_url:
                continue  # skip entries without a usable URL

            parsed.append({
                "html_url":          html_url,
                "full_name":         self._to_str(entry.get("full_name")),
                "name":              self._to_str(entry.get("name")),
                "description":       self._to_str(entry.get("description")),
                "stargazers_count":  self._to_int(entry.get("stargazers_count")),
                "forks_count":       self._to_int(entry.get("forks_count")),
                "updated_at":        self._to_datetime(entry.get("updated_at") or entry.get("pushed_at")),
                "created_at":        self._to_datetime(entry.get("created_at")),
            })

        logger.info("[PoC] Parsed entries", cve_id=cve_id, count=len(parsed))
        return parsed

    # ------------------------------------------------------------------
    # Private helpers — type coercion only, no business logic
    # ------------------------------------------------------------------

    def _to_str(self, value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    def _to_int(self, value: Any) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    def _to_datetime(self, value: Any) -> datetime | None:
        if not value:
            return None
        try:
            text = str(value).replace("Z", "+00:00")
            return datetime.fromisoformat(text)
        except (ValueError, AttributeError):
            return None
