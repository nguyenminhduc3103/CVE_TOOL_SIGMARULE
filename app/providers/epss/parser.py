from __future__ import annotations

from typing import Any

from app.core.logging import get_logger


class EPSSParser:
    def __init__(self) -> None:
        self.logger = get_logger(__name__)

    def normalize(self, raw: Any) -> dict:
        """Normalize raw EPSS response into a deterministic internal dict.

        TODO boundaries:
        - no HTTP logic here
        - no scoring logic here
        - keep missing-field handling graceful
        """
        self.logger.info("[EPSS] Parsing CVE data")

        payload = raw if isinstance(raw, dict) else {}
        data = payload.get("data") or []
        first = data[0] if data else {}

        normalized = {
            "cve_id": str(first.get("cve") or payload.get("cve") or payload.get("cve_id") or ""),
            "epss_score": self._to_float(first.get("epss") or payload.get("epss")),
            "epss_percentile": self._to_float(first.get("percentile") or payload.get("percentile")),
            "date": first.get("date") or payload.get("date"),
        }

        self.logger.info(
            "[EPSS] Parsed score",
            cve_id=normalized["cve_id"],
            epss_score=normalized["epss_score"],
            epss_percentile=normalized["epss_percentile"],
        )
        return normalized

    def _to_float(self, value: Any) -> float | None:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None
