"""Step 6 Detection Knowledge Base — YAML data files for detection knowledge.

Only detection knowledge (families, signatures, behaviors, correlation_hints,
level_translation, completeness_thresholds); no Step 4 KB overlap.
"""
from __future__ import annotations

from src.usecases.step_6_generate_sigma._knowledge import loader

__all__ = ["loader"]