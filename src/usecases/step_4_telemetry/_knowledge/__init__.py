"""Knowledge Base — YAML data files cho telemetry domain, canonical telemetry, fields.

Tách khỏi code layer (`_resolver/`) và shared engines.
AI emit semantic → Resolver đọc KB → Map sang Canonical → Sigma.

Refactor 2026-07: chuyển từ hardcode whitelist sang knowledge-driven.
"""
from __future__ import annotations

from src.usecases.step_4_telemetry._knowledge import loader

__all__ = ["loader"]