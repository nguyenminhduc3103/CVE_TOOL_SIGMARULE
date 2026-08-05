# Step 6 orchestrator alias — back-compat. Step6Orchestrator = SigmaRuleAI (legacy name kept).
from __future__ import annotations

from src.usecases.step_6_generate_sigma.services.sigma_rule_ai import SigmaRuleAI

Step6Orchestrator = SigmaRuleAI

__all__ = ["Step6Orchestrator", "SigmaRuleAI"]
