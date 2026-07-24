"""GitHub Tree Client — fetches full repository file tree in a single API request.

Uses GitHub REST API:
GET https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1
"""
from __future__ import annotations

import httpx
from typing import Any
from urllib.parse import urlparse

from src.infrastructure.clients.base import BaseHTTPClient
from config.logging import get_logger

logger = get_logger(__name__)


class GitHubTreeHTTPClient(BaseHTTPClient):
    """HTTP client for GitHub Trees API and Raw file fetching."""

    def __init__(self, timeout: float = 15.0) -> None:
        super().__init__(base_url="https://api.github.com", timeout=timeout)

    def parse_repo_url(self, html_url: str) -> tuple[str, str] | None:
        """Extract (owner, repo) from https://github.com/owner/repo."""
        if not html_url or "github.com" not in html_url:
            return None
        parsed = urlparse(html_url)
        parts = [p for p in parsed.path.strip("/").split("/") if p]
        if len(parts) >= 2:
            return parts[0], parts[1].replace(".git", "")
        return None

    async def fetch_tree(self, owner: str, repo: str, branch: str = "main") -> list[dict[str, Any]]:
        """
        Fetch recursive git tree for a given owner/repo.

        Returns:
            List of tree item dicts containing 'path', 'type', 'size', 'url'.
        """
        url = f"/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
        logger.info("[GitHub Tree] Fetching tree", owner=owner, repo=repo, branch=branch)

        try:
            headers = {"User-Agent": "cve-ti-platform/1.0", "Accept": "application/vnd.github.v3+json"}
            response = await self.get(url, headers=headers, follow_redirects=True)

            if response.status_code == 404 and branch == "main":
                # Fallback to master if main branch 404s
                return await self.fetch_tree(owner, repo, branch="master")

            response.raise_for_status()
            data = response.json()
            return data.get("tree", [])

        except Exception as exc:
            logger.warning("[GitHub Tree] Error fetching tree", owner=owner, repo=repo, error=str(exc))
            return []

    async def fetch_raw_file(self, owner: str, repo: str, path: str, branch: str = "main") -> bytes | None:
        """Fetch raw content bytes of a file from raw.githubusercontent.com."""
        raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
        logger.info("[GitHub Raw] Fetching raw file", raw_url=raw_url)

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(raw_url, headers={"User-Agent": "cve-ti-platform/1.0"}, follow_redirects=True)
                if resp.status_code == 404 and branch == "main":
                    return await self.fetch_raw_file(owner, repo, path, branch="master")
                resp.raise_for_status()
                return resp.content
        except Exception as exc:
            logger.warning("[GitHub Raw] Error fetching raw file", raw_url=raw_url, error=str(exc))
            return None
