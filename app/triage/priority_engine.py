from __future__ import annotations

from typing import Tuple

from app.models.core import CoreCVEData
from app.models.triage import TriageContext


class PriorityEngine:
    async def assess(self, core: CoreCVEData, triage: TriageContext) -> Tuple[str, int]:
        # Deterministic fallback scoring that tolerates missing providers.
        cvss_component = int((core.cvss_score or 0.0) * 10)
        epss_component = int((triage.epss_score or 0.0) * 100)
        kev_component = 15 if triage.in_kev is True else 0
        total = min(100, cvss_component + epss_component + kev_component)

        if total >= 90:
            return "critical", total
        if total >= 70:
            return "high", total
        if total >= 40:
            return "medium", total
        return "low", total
