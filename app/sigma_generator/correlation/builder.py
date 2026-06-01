from __future__ import annotations

from app.models.attack import AttackMapping, TechnicalAnalysis
from app.models.telemetry import TelemetryAssessment
from app.sigma_generator.correlation.correlation_models import CorrelationCondition
from app.sigma_generator.correlation.correlation_rules import BEHAVIOR_TO_SELECTION, FAMILY_CORRELATION_RULES
from app.sigma_generator.models.sigma_detection import SigmaDetection


class CorrelationBuilder:
    def build(
        self,
        analysis: TechnicalAnalysis | dict[str, object] | None,
        attack: AttackMapping | dict[str, object] | None,
        telemetry: TelemetryAssessment | dict[str, object] | None,
        detection: SigmaDetection,
    ) -> CorrelationCondition:
        if not self._correlation_required(telemetry):
            return CorrelationCondition(
                expression="1 of selection_*",
                confidence=0.0,
                reasoning="Telemetry does not require correlation; using independent indicators.",
                required_selections=list(detection.selections.keys()),
            )

        family = self._normalize(self._get(analysis, "family"))
        signature = self._normalize(self._get(analysis, "signature"))
        family_rule = self._resolve_family_rule(family, signature)
        available = list(detection.selections.keys())

        if family_rule is not None:
            required = [name for name in family_rule["required_selections"] if name in available]
            if required:
                expression = str(family_rule["expression"])
                reasoning = str(family_rule["reasoning"])
                return CorrelationCondition(
                    expression=expression,
                    confidence=0.02,
                    reasoning=reasoning,
                    required_selections=required,
                )

        behaviors = self._list(self._get(analysis, "mandatory_behaviors"))
        selections = [BEHAVIOR_TO_SELECTION[behavior] for behavior in behaviors if behavior in BEHAVIOR_TO_SELECTION]
        selections = [selection for selection in selections if selection in available]

        if not selections:
            return CorrelationCondition(
                expression="1 of selection_*",
                confidence=0.0,
                reasoning="No correlation rule matched; falling back to independent indicators.",
                required_selections=available,
            )

        if len(selections) == 1:
            expression = selections[0]
        elif len(selections) == 2:
            expression = f"{selections[0]} and {selections[1]}"
        elif len(selections) == 3:
            expression = f"{selections[0]} and ({selections[1]} or {selections[2]})"
        else:
            expression = " and ".join(selections)

        return CorrelationCondition(
            expression=expression,
            confidence=0.0,
            reasoning="Correlation derived from mandatory behavior chain.",
            required_selections=selections,
        )

    def _resolve_family_rule(self, family: str | None, signature: str | None) -> dict[str, object] | None:
        if signature and signature in FAMILY_CORRELATION_RULES:
            return FAMILY_CORRELATION_RULES[signature]
        if family and family in FAMILY_CORRELATION_RULES:
            return FAMILY_CORRELATION_RULES[family]
        return None

    def _correlation_required(self, telemetry: TelemetryAssessment | dict[str, object] | None) -> bool:
        value = self._get(telemetry, "correlation_required")
        if isinstance(value, bool):
            return value
        return str(value).lower() in {"1", "true", "yes"}

    def _get(self, value: object | None, key: str) -> object | None:
        if value is None:
            return None
        if isinstance(value, dict):
            return value.get(key)
        return getattr(value, key, None)

    def _list(self, value: object | None) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return [str(item) for item in value if item is not None]

    def _normalize(self, value: object | None) -> str | None:
        if value is None:
            return None
        text = str(value).strip().lower().replace(".", "_").replace("-", "_")
        return text or None