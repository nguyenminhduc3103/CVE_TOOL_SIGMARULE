"""Telemetry Repo Client — chuyên kết nối và cache dữ liệu từ OTRF Mordor & EVTX-ATTACK-SAMPLES.

Nguồn Telemetry Chuyên Biệt:
1. OTRF Mordor (OTRF/mordor)
2. EVTX-ATTACK-SAMPLES (sbousseaden/EVTX-ATTACK-SAMPLES)
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.infrastructure.clients.github_tree_client import GitHubTreeHTTPClient
from config.logging import get_logger

logger = get_logger(__name__)

CACHE_DIR = Path(".cache/telemetry_repos")


class TelemetryRepoHTTPClient:
    """HTTP client & Local Disk Caching cho các kho Telemetry mở."""

    TELEMETRY_REPOS = [
        {"owner": "sbousseaden", "repo": "EVTX-ATTACK-SAMPLES", "branch": "master", "score": 10.0},
        {"owner": "OTRF", "repo": "mordor", "branch": "master", "score": 10.0},
    ]

    def __init__(self) -> None:
        self.github_client = GitHubTreeHTTPClient()
        CACHE_DIR.mkdir(parents=True, exist_ok=True)

    async def fetch_matching_telemetry_files(
        self,
        keywords: list[str],
        technique_ids: list[str],
        max_files: int = 5
    ) -> list[dict[str, Any]]:
        """
        Tìm kiếm và tải các tệp Telemetry (.evtx, .json) khớp với (Technique ID + Keywords).

        Returns:
            Danh sách dict chứa: {
                "source": str,
                "file_path": str,
                "content_bytes": bytes,
                "score": float
            }
        """
        results: list[dict[str, Any]] = []
        kw_set = {k.lower() for k in keywords if k}
        tech_set = {t.upper() for t in technique_ids if t}

        for repo_info in self.TELEMETRY_REPOS:
            owner, repo, branch = repo_info["owner"], repo_info["repo"], repo_info["branch"]
            score = repo_info["score"]

            # Step 1: Fetch Tree (hoặc load cache)
            tree = await self._get_cached_tree(owner, repo, branch)
            if not tree:
                continue

            # Step 2: Lọc các tệp khớp với Hybrid Searching Criteria
            matched_items = self._filter_matching_items(tree, kw_set, tech_set)

            # Step 3: Tải nội dung các tệp khớp
            for item in matched_items[:max_files]:
                path = item.get("path", "")
                content = await self.github_client.fetch_raw_file(owner, repo, path, branch=branch)
                if content:
                    results.append({
                        "source": f"{owner}/{repo}",
                        "file_path": path,
                        "content_bytes": content,
                        "score": score
                    })

                if len(results) >= max_files:
                    break

        return results

    async def _get_cached_tree(self, owner: str, repo: str, branch: str) -> list[dict[str, Any]]:
        """Lấy cây thư mục repo từ cache đĩa địa phương hoặc gọi GitHub API."""
        cache_file = CACHE_DIR / f"{owner}__{repo}__tree.json"

        if cache_file.exists():
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass

        # Fetch fresh tree
        tree = await self.github_client.fetch_tree(owner, repo, branch=branch)
        if tree:
            try:
                with open(cache_file, "w", encoding="utf-8") as f:
                    json.dump(tree, f)
            except Exception as exc:
                logger.warning("[Telemetry Repo] Error writing cache", error=str(exc))

        return tree

    def _filter_matching_items(
        self,
        tree: list[dict[str, Any]],
        keywords: set[str],
        techniques: set[str]
    ) -> list[dict[str, Any]]:
        """Lọc các tệp trong tree dựa trên Hybrid Matching Rules."""
        matched: list[dict[str, Any]] = []

        for item in tree:
            path = (item.get("path") or "").lower()
            # Chỉ xét các tệp log/evtx/json/xml
            if not any(path.endswith(ext) for ext in [".evtx", ".json", ".xml", ".log"]):
                continue

            # Check matching
            tech_match = any(t.lower() in path for t in techniques)
            kw_match = any(k in path for k in keywords)

            # Ưu tiên 1: cả technique lẫn keyword khớp
            if tech_match and kw_match:
                matched.insert(0, item)
            # Ưu tiên 2: keyword khớp
            elif kw_match:
                matched.append(item)
            # Ưu tiên 3: technique khớp
            elif tech_match:
                matched.append(item)

        return matched
