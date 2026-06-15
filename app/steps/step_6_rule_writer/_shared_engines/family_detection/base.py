from __future__ import annotations

from abc import ABC, abstractmethod

from app.shared.models.attack import AttackMapping, TechnicalAnalysis
from app.shared.models.telemetry import TelemetryAssessment
from app.steps.step_6_rule_writer._shared_engines.models.sigma_detection import SigmaDetection


class DetectionTemplate(ABC):
    @abstractmethod
    def supports(self, family: str | None, signature: str | None) -> bool:
        raise NotImplementedError

    @abstractmethod
    def build_detection(
        self,
        analysis: TechnicalAnalysis | dict[str, object] | None,
        attack: AttackMapping | dict[str, object] | None,
        telemetry: TelemetryAssessment | dict[str, object] | None,
    ) -> SigmaDetection:
        raise NotImplementedError