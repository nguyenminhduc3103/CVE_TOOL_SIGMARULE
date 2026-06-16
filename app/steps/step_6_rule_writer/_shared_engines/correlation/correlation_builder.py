from __future__ import annotations

from app.shared.models.attack import AttackMapping, TechnicalAnalysis
from app.shared.models.telemetry import TelemetryAssessment
from app.steps.step_6_rule_writer._shared_engines.correlation.correlation_models import CorrelationCondition, SigmaCorrelationBlock
from app.steps.step_6_rule_writer._shared_engines.correlation.correlation_rules import BEHAVIOR_TO_SELECTION, FAMILY_CORRELATION_RULES
from app.steps.step_6_rule_writer._shared_engines.models.sigma_detection import SigmaDetection


class CorrelationBuilder:
    def build(
        self,
        analysis: TechnicalAnalysis | dict[str, object] | None,
        attack: AttackMapping | dict[str, object] | None,
        telemetry: TelemetryAssessment | dict[str, object] | None,
        detection: SigmaDetection,
    ) -> CorrelationCondition:
        available = list(detection.selections.keys())

        # 1. Nếu không yêu cầu correlation, trả về mặc định
        if not self._correlation_required(telemetry):
            return CorrelationCondition(
                expression="1 of selection_*",
                is_cross_event=False,
                confidence=0.0,
                reasoning="Telemetry does not require correlation; using independent indicators.",
                required_selections=available,
            )

        family = self._normalize(self._get(analysis, "family"))
        signature = self._normalize(self._get(analysis, "signature"))
        
        # 2. Tra cứu luật trong FAMILY_CORRELATION_RULES
        family_rule = self._resolve_family_rule(family, signature)

        if family_rule is not None:
            required = [name for name in family_rule.get("required_selections", []) if name in available]
            if required:
                is_cross_event = bool(family_rule.get("is_cross_event", False))
                reasoning = str(family_rule.get("reasoning", ""))

                # NẾU LÀ ĐA SỰ KIỆN (CROSS-EVENT) -> Tạo Block Correlation chuẩn SigmaHQ
                if is_cross_event:
                    block = SigmaCorrelationBlock(
                        type=str(family_rule.get("correlation_type", "temporal_ordered")),
                        timespan=str(family_rule.get("timespan", "5m")),
                        rules=[]  # Sẽ được SigmaRuleGenerator điền tên các rule con vào sau
                    )
                    return CorrelationCondition(
                        is_cross_event=True,
                        correlation_block=block,
                        confidence=0.02,
                        reasoning=reasoning,
                        required_selections=required,
                    )
                # NẾU LÀ ĐƠN SỰ KIỆN (SINGLE-EVENT) -> Giữ nguyên expression cũ
                else:
                    expression = str(family_rule.get("expression", "1 of selection_*"))
                    return CorrelationCondition(
                        is_cross_event=False,
                        expression=expression,
                        confidence=0.02,
                        reasoning=reasoning,
                        required_selections=required,
                    )

        # 3. Fallback động (Dynamic Fallback) dựa trên behaviors nếu không có family rule
        behaviors = self._list(self._get(analysis, "mandatory_behaviors"))
        selections = [BEHAVIOR_TO_SELECTION[behavior] for behavior in behaviors if behavior in BEHAVIOR_TO_SELECTION]
        selections = [selection for selection in selections if selection in available]

        if not selections:
            return CorrelationCondition(
                expression="1 of selection_*",
                is_cross_event=False,
                confidence=0.0,
                reasoning="No correlation rule matched; falling back to independent indicators.",
                required_selections=available,
            )

        if len(selections) == 1:
            return CorrelationCondition(
                expression=selections[0],
                is_cross_event=False,
                confidence=0.0,
                reasoning="Single behavior detected; single-event expression.",
                required_selections=selections,
            )
        else:
            # Nếu có >= 2 hành vi động, tự động coi nó là chuỗi thời gian (temporal_ordered)
            block = SigmaCorrelationBlock(
                type="temporal_ordered",
                timespan="5m",
                rules=[]
            )
            return CorrelationCondition(
                is_cross_event=True,
                correlation_block=block,
                confidence=0.0,
                reasoning="Dynamic multi-behavior sequence detected; generating cross-event correlation.",
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