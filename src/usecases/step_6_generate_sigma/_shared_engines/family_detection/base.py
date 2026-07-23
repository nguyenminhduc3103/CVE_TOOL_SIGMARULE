from __future__ import annotations

from abc import ABC, abstractmethod

from src.domain.models.attack import AttackMapping, TechnicalAnalysis
from src.domain.models.telemetry import TelemetryAssessment
from src.usecases.step_6_generate_sigma._shared_engines.models.sigma_detection import SigmaDetection


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