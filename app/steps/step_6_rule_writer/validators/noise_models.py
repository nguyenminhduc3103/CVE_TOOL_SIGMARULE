from typing import Literal

from pydantic import BaseModel


class NoiseEstimate(BaseModel):
    events_per_day: Literal["low", "medium", "high", "very_high"]
    estimated_count: Literal["<100", "100-1k", "1k-10k", ">10k"]
    complexity_class: Literal["low", "medium", "high"]
    noise_factors: list[str]
    likely_false_positives: list[str]
    recommended_filters: list[str]
    level_adjustment: str | None
    reasoning: str
    confidence: float
    ai_used: bool = False
