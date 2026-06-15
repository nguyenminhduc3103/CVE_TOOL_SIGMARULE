from __future__ import annotations

from app.shared.models.attack import AttackMapping, TechnicalAnalysis
from app.shared.models.telemetry import TelemetryAssessment
from app.steps.step_6_rule_writer._shared_engines.family_detection.registry import DetectionTemplateRegistry
from app.steps.step_6_rule_writer._shared_engines.models.sigma_detection import SigmaDetection


class FamilyDetectionBuilder:
    def __init__(self, registry: DetectionTemplateRegistry | None = None) -> None:
        self.registry = registry or DetectionTemplateRegistry()

    def build(
        self,
        analysis: TechnicalAnalysis | dict[str, object] | None,
        attack: AttackMapping | dict[str, object] | None,
        telemetry: TelemetryAssessment | dict[str, object] | None,
    ) -> SigmaDetection:
        family = self._normalize(self._get(analysis, "family"))
        signature = self._normalize(self._get(analysis, "signature"))
        template = self.registry.resolve(family, signature)
        detection = template.build_detection(analysis, attack, telemetry)

        if detection.selections:
            return detection

        generic_template = self.registry.resolve(None, None)
        if generic_template is template:
            return detection
        return generic_template.build_detection(analysis, attack, telemetry)

    def _get(self, value: object | None, key: str) -> object | None:
        if value is None:
            return None
        if isinstance(value, dict):
            return value.get(key)
        return getattr(value, key, None)

    def _normalize(self, value: object | None) -> str | None:
        if value is None:
            return None
        text = str(value).strip().lower().replace(".", "_").replace("-", "_")
        return text or None