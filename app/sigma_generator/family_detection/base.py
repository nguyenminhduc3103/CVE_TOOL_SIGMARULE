from __future__ import annotations

from abc import ABC, abstractmethod

from app.models.attack import AttackMapping, TechnicalAnalysis
from app.models.telemetry import TelemetryAssessment
from app.sigma_generator.models.sigma_detection import SigmaDetection


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