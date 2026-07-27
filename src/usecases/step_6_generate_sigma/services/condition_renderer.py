"""Condition Renderer — translate `DetectionLogic` into a Sigma condition string.

    operator="all"      → sel_a and sel_b
    operator="any"      → sel_a or sel_b
    operator="at_least" → N of sel_*

Builder NEVER silently weakens "all" to "any". If an operand index is out of range,
the renderer raises — caller decides whether to retry / fallback / not_ready.
"""
from __future__ import annotations

from pydantic import BaseModel

from src.usecases.step_6_generate_sigma.domain.detection_plan import DetectionLogic


class ConditionRenderResult(BaseModel):
    condition: str
    operator: str
    operand_names: list[str]
    human: str


def _operand_name(index: int, detections: list) -> str:
    if 0 <= index < len(detections):
        return f"sel_{index}"
    raise ValueError(
        f"logic operand index {index} out of range (plan has {len(detections)} intents)"
    )


def render_condition(
    logic: DetectionLogic,
    detections: list,
) -> ConditionRenderResult:
    """Render Sigma condition string from DetectionLogic.

    detection_count >= max(operands) is required (DetectionPlan already validates this).
    """
    operand_names = [_operand_name(idx, detections) for idx in logic.operands]

    if logic.operator == "all":
        condition = " and ".join(operand_names)
        human = "all of: " + " AND ".join(operand_names)
    elif logic.operator == "any":
        condition = " or ".join(operand_names)
        human = "any of: " + " OR ".join(operand_names)
    elif logic.operator == "at_least":
        n = logic.threshold if logic.threshold is not None else 1
        condition = f"{n} of {', '.join(operand_names)}"
        human = f"at least {n} of: " + ", ".join(operand_names)
    else:
        raise ValueError(f"unsupported operator: {logic.operator!r}")

    return ConditionRenderResult(
        condition=condition,
        operator=logic.operator,
        operand_names=operand_names,
        human=human,
    )


__all__ = ["ConditionRenderResult", "render_condition"]