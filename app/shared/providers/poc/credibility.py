"""PoC credibility filter — business logic for evaluating GitHub PoC repo quality.

Separation of concerns:
- PoCParser   → extracts and normalizes raw data (no decisions)
- PoCCredibilityFilter → decides which repos are trustworthy (no parsing)
"""
from __future__ import annotations

from datetime import datetime, timezone

from app.core.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Credibility thresholds — adjust here without touching parser or provider
# ---------------------------------------------------------------------------
_MIN_STARS: int = 3          # Minimum GitHub stars
_MIN_FORKS: int = 1          # Minimum GitHub forks
_MAX_AGE_DAYS: int = 1095    # Max days since last update (3 years)

# Keywords in repo description that signal it is an actual exploit/PoC
_EXPLOIT_KEYWORDS: frozenset[str] = frozenset({
    "exploit", "poc", "proof", "proof-of-concept", "rce", "bypass",
    "payload", "vulnerability", "cve", "attack", "demo",
})
# ---------------------------------------------------------------------------


class PoCCredibilityFilter:
    """
    Applies credibility criteria to parsed PoC entries.

    All 5 criteria must pass for a repo to be accepted:
      1. stargazers_count  >= _MIN_STARS
      2. forks_count       >= _MIN_FORKS
      3. full_name or name contains CVE-ID (case-insensitive)
      4. description contains at least 1 exploit/poc keyword
      5. updated_at is within the last _MAX_AGE_DAYS days
    """

    def filter(self, parsed_entries: list[dict], cve_id: str) -> list[str]:
        """
        Evaluate each parsed entry against credibility criteria.

        Args:
            parsed_entries: Output from PoCParser.normalize()
            cve_id:         The CVE being processed (used for name matching)

        Returns:
            List of credible html_url strings (may be empty).
        """
        credible_entries: list[dict] = []
        dropped = 0

        for entry in parsed_entries:
            passed, reason = self._evaluate(entry, cve_id)

            if passed:
                credible_entries.append(entry)
            else:
                dropped += 1

        # Sort by stars (descending) and keep only top 5
        credible_entries.sort(key=lambda x: x.get("stargazers_count", 0), reverse=True)
        top_5_entries = credible_entries[:5]
        
        credible_urls = [e["html_url"] for e in top_5_entries]

        if dropped or len(credible_entries) > 5:
            logger.info(
                "[PoC] Filter summary",
                cve_id=cve_id,
                total_accepted=len(credible_entries),
                kept_top_5=len(credible_urls),
                dropped=dropped,
            )

        return credible_urls

    # ------------------------------------------------------------------
    # Private — one method per criterion for easy maintenance
    # ------------------------------------------------------------------

    def _evaluate(self, entry: dict, cve_id: str) -> tuple[bool, str]:
        """Return (passed, reason). reason describes why entry was rejected."""

        # Criterion 1: Stars
        stars = entry.get("stargazers_count", 0)
        if stars < _MIN_STARS:
            return False, f"stars={stars} < {_MIN_STARS}"

        # Criterion 2: Forks
        forks = entry.get("forks_count", 0)
        if forks < _MIN_FORKS:
            return False, f"forks={forks} < {_MIN_FORKS}"

        # Criterion 3: CVE ID appears in repo name
        cve_lower = cve_id.lower()
        full_name = (entry.get("full_name") or "").lower()
        repo_name = (entry.get("name") or "").lower()
        if cve_lower not in full_name and cve_lower not in repo_name:
            return False, f"repo name '{full_name}' does not contain {cve_id}"

        # Criterion 4: Description mentions exploit/PoC context
        desc = (entry.get("description") or "").lower()
        if not any(kw in desc for kw in _EXPLOIT_KEYWORDS):
            return False, f"description '{desc[:60]}' has no exploit keywords"

        # Criterion 5: Repo must not be stale
        updated_at: datetime | None = entry.get("updated_at")
        if updated_at is not None:
            age_days = (datetime.now(timezone.utc) - updated_at).days
            if age_days > _MAX_AGE_DAYS:
                return False, f"repo not updated for {age_days} days > {_MAX_AGE_DAYS}"

        return True, "ok"
