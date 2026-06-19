from __future__ import annotations

from datetime import datetime
from typing import Any

from app.core.logging import get_logger


class KEVParser:
    def __init__(self) -> None:
        self.logger = get_logger(__name__)

    def normalize(self, raw: Any, cve_id: str) -> dict:
        """Normalize raw KEV feed into a deterministic internal dict.

        TODO boundaries:
        - no HTTP logic here
        - no business scoring here
        - gracefully handle missing feed entries and unexpected feed shape
        """
        self.logger.info("[KEV] Parsing CVE data")

        payload = raw if isinstance(raw, dict) else {}
        vulnerabilities = payload.get("vulnerabilities") or []
        match = self._find_match(vulnerabilities, cve_id)

        normalized = {
            "cve_id": cve_id,
            "in_kev": match is not None,
            "kev_added_date": self._parse_datetime(match.get("dateAdded")) if match else None,
            "due_date": self._parse_datetime(match.get("dueDate")) if match else None,
            "vendor_project": self._to_str(match.get("vendorProject")) if match else None,
            "product": self._to_str(match.get("product")) if match else None,
            "vulnerability_name": self._to_str(match.get("vulnerabilityName")) if match else None,
            "short_description": self._to_str(match.get("shortDescription")) if match else None,
            "required_action": self._to_str(match.get("requiredAction")) if match else None,
            "known_ransomware_campaign_use": self._to_bool(match.get("knownRansomwareCampaignUse")) if match else False,
            "cwes": self._to_list(match.get("cwes")) if match else [],
        }

        self.logger.info(
            "[KEV] Parsed KEV entry",
            cve_id=cve_id,
            in_kev=normalized["in_kev"],
            kev_added_date=normalized["kev_added_date"],
        )
        return normalized

    def _find_match(self, vulnerabilities: list[Any], cve_id: str) -> dict[str, Any] | None:
        for entry in vulnerabilities:
            if not isinstance(entry, dict):
                continue
            if str(entry.get("cveID") or entry.get("cveId") or "") == cve_id:
                return entry
        return None

    def _parse_datetime(self, value: Any) -> datetime | None:
        if not value:
            return None
        if isinstance(value, datetime):
            return value
        try:
            return datetime.fromisoformat(str(value))
        except ValueError:
            return None

    def _to_str(self, value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    def _to_bool(self, value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        normalized = str(value).strip().lower()
        if normalized in {"", "false", "no", "0", "none", "null", "unknown"}:
            return False
        return True

    def _to_list(self, value: Any) -> list[str]:
        if not value:
            return []
        if isinstance(value, list):
            return [str(item) for item in value if str(item).strip()]
        return [str(value)]
