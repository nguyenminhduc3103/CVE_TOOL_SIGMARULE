"""Step 6 fallbacks — rule-based planner when AI is disabled or fails."""
from src.usecases.step_6_generate_sigma.fallbacks.rule_based_planner import (
    build_rule_based_plan,
)

__all__ = ["build_rule_based_plan"]