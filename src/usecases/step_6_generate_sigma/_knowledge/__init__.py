"""Step 6 Detection Knowledge Base — YAML data files for detection knowledge.

Tách khỏi code layer (`services/`) và shared engines.
AI emit semantic intent → Intent Mapper đọc KB + Step 4 KB → Map sang logsource.

Refactor 2026-07: Detection KB chỉ chứa detection knowledge (families,
signatures, behaviors, correlation_hints, level_translation, completeness_thresholds).
Không duplicate Step 4 KB (taxonomy, canonical fields, logsource mapping).
"""
from __future__ import annotations

from src.usecases.step_6_generate_sigma._knowledge import loader

__all__ = ["loader"]