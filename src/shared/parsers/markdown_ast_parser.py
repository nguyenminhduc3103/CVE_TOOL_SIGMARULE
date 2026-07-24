"""Markdown AST Parser — bóc tách các khối mã (Code Blocks) từ tài liệu Markdown.

Phân loại khối mã:
1. Executable / Exploit Commands (bash, powershell, python, curl, cmd, sh, ps1)
2. Sample Logs (json, xml, sysmon, log, evtx, text, yaml)
"""
from __future__ import annotations

import re
from typing import Any


COMMAND_LANGUAGES: set[str] = {
    "bash", "sh", "powershell", "ps1", "cmd", "python", "py", "curl", "zsh"
}

LOG_LANGUAGES: set[str] = {
    "json", "xml", "sysmon", "log", "evtx", "yaml", "yml"
}


class MarkdownASTParser:
    """Parser bóc tách code blocks từ markdown text."""

    _FENCED_CODE_PATTERN = re.compile(
        r"```(?P<lang>[a-zA-Z0-9_\-\+]*)\n(?P<code>.*?)```",
        re.DOTALL
    )

    def extract_code_blocks(self, markdown_text: str) -> list[dict[str, Any]]:
        """
        Trích xuất tất cả các khối mã trong markdown_text.

        Returns:
            List of dicts: [
                {
                    "lang": str,
                    "code": str,
                    "type": "command" | "log" | "unknown"
                }
            ]
        """
        if not markdown_text:
            return []

        blocks: list[dict[str, Any]] = []
        for match in self._FENCED_CODE_PATTERN.finditer(markdown_text):
            lang = (match.group("lang") or "").strip().lower()
            code = match.group("code").strip()

            if not code:
                continue

            block_type = self._classify_block(lang, code)
            blocks.append({
                "lang": lang or "text",
                "code": code,
                "type": block_type
            })

        return blocks

    def _classify_block(self, lang: str, code: str) -> str:
        """Phân loại khối mã là command, log, hay unknown."""
        if lang in COMMAND_LANGUAGES:
            return "command"
        if lang in LOG_LANGUAGES:
            return "log"

        # Heuristic check on content if lang is unspecified or 'text'
        code_lower = code.lower()

        # Log indicators
        if any(kw in code_lower for kw in ["eventid", "<event", '"event_id"', "sysmon", "commandline:", "parentimage:"]):
            return "log"

        # Command indicators
        if any(code.strip().startswith(prefix) for prefix in ["curl ", "python ", "powershell ", "cmd.exe", "./exploit", "nc "]):
            return "command"

        return "unknown"
