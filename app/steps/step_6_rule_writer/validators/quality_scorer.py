from __future__ import annotations

from app.shared.models.coverage import CoverageAssessment
from app.shared.models.telemetry import TelemetryAssessment
from app.steps.step_6_rule_writer.validators.validation_models import (
    ComplexityClass,
    DeploymentReadiness,
    FalsePositiveRate,
    MaintenanceCost,
    QualityAssessment,
    SignalQuality,
)


class QualityScorer:
    """Lightweight rule scoring used by SigmaValidator.

    Returns a 0–100 score and an A–F grade based on a fixed penalty table.
    Keep this alongside `QualityAssessmentEngine` so the in-package
    `SigmaValidator` can keep using the simple penalty model.
    """

    def calculate(
        self,
        *,
        missing_metadata: bool = False,
        invalid_attack_tags: bool = False,
        invalid_condition: bool = False,
        generic_placeholders: bool = False,
        unknown_logsource: bool = False,
        missing_correlation_reasoning: bool = False,
    ) -> int:
        score = 100
        if missing_metadata:
            score -= 20
        if invalid_attack_tags:
            score -= 15
        if invalid_condition:
            score -= 20
        if generic_placeholders:
            score -= 10
        if unknown_logsource:
            score -= 5
        if missing_correlation_reasoning:
            score -= 5
        return max(score, 0)

    def grade(self, score: int) -> str:
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"


class QualityAssessmentEngine:
    def assess(self, sigma_rule, validation_result, telemetry: TelemetryAssessment | dict[str, object] | None, coverage: CoverageAssessment | dict[str, object] | None) -> QualityAssessment:
        signal_score = self._signal_score(sigma_rule, validation_result, telemetry)
        signal_quality = self._signal_quality(signal_score)
        false_positive_rate = self._false_positive_rate(sigma_rule, telemetry)
        complexity_class = self._complexity_class(sigma_rule)
        deployment_readiness = self._deployment_readiness(sigma_rule, validation_result, signal_quality)
        maintenance_cost = self._maintenance_cost(sigma_rule)
        quality_score = self._quality_score(validation_result, signal_score, false_positive_rate, complexity_class, deployment_readiness)
        reasoning = self._reasoning(signal_quality, false_positive_rate, complexity_class, deployment_readiness, maintenance_cost)

        return QualityAssessment(
            signal_quality=signal_quality,
            false_positive_rate=false_positive_rate,
            complexity_class=complexity_class,
            deployment_readiness=deployment_readiness,
            maintenance_cost=maintenance_cost,
            quality_score=quality_score,
            reasoning=reasoning,
        )

    def _signal_score(self, sigma_rule, validation_result, telemetry) -> int:
        score = 0
        if getattr(validation_result, "score", 0) >= 90:
            score += 30
        if bool(getattr(sigma_rule, "x_correlation_logic", False)):
            score += 20
        if self._is_family_specific(sigma_rule):
            score += 20
        if len(getattr(getattr(sigma_rule, "metadata", None), "tags", None) or []) >= 3:
            score += 15
        if self._telemetry_confidence(telemetry) >= 0.85:
            score += 15
        return score

    def _signal_quality(self, score: int) -> SignalQuality:
        if score >= 80:
            return SignalQuality.high
        if score >= 55:
            return SignalQuality.medium
        return SignalQuality.low

    def _false_positive_rate(self, sigma_rule, telemetry) -> FalsePositiveRate:
        family_specific = self._is_family_specific(sigma_rule)
        multiple_sources = len(self._telemetry_logsources(telemetry)) >= 2
        strong_correlation = bool(getattr(sigma_rule, "x_correlation_logic", False))
        detection = getattr(sigma_rule, "detection", None)
        selections = getattr(detection, "selections", None) or {}
        single_selection = len(selections) <= 1

        if family_specific and strong_correlation and multiple_sources and not single_selection:
            return FalsePositiveRate.low
        if family_specific or strong_correlation or multiple_sources:
            return FalsePositiveRate.medium
        return FalsePositiveRate.high

    def _complexity_class(self, sigma_rule) -> ComplexityClass:
        logsource_count = len([value for value in getattr(sigma_rule, "x_secondary_logsources", []) or []]) + 1
        selection_count = len((getattr(getattr(sigma_rule, "detection", None), "selections", None) or {}).keys())
        if logsource_count == 1 and selection_count <= 3:
            return ComplexityClass.low
        if selection_count <= 4:
            return ComplexityClass.medium
        return ComplexityClass.high

    def _deployment_readiness(self, sigma_rule, validation_result, signal_quality: SignalQuality) -> DeploymentReadiness:
        if getattr(validation_result, "score", 0) >= 90 and not getattr(validation_result, "errors", []):
            if signal_quality == SignalQuality.high:
                return DeploymentReadiness.production
            return DeploymentReadiness.test
        if getattr(validation_result, "score", 0) >= 70:
            return DeploymentReadiness.test
        return DeploymentReadiness.experimental

    def _maintenance_cost(self, sigma_rule) -> MaintenanceCost:
        if bool(getattr(sigma_rule, "x_correlation_logic", False)):
            return MaintenanceCost.medium
        if len((getattr(getattr(sigma_rule, "detection", None), "selections", None) or {}).keys()) <= 2:
            return MaintenanceCost.low
        return MaintenanceCost.high

    def _quality_score(self, validation_result, signal_score: int, false_positive_rate: FalsePositiveRate, complexity_class: ComplexityClass, deployment_readiness: DeploymentReadiness) -> int:
        validation_component = (getattr(validation_result, "score", 0) / 100) * 30
        signal_component = signal_score * 0.25
        fp_component = {FalsePositiveRate.low: 20, FalsePositiveRate.medium: 10, FalsePositiveRate.high: 0}[false_positive_rate]
        complexity_component = {ComplexityClass.low: 15, ComplexityClass.medium: 10, ComplexityClass.high: 5}[complexity_class]
        readiness_component = {DeploymentReadiness.production: 10, DeploymentReadiness.test: 6, DeploymentReadiness.experimental: 2}[deployment_readiness]
        return max(0, min(100, int(round(validation_component + signal_component + fp_component + complexity_component + readiness_component))))

    def _reasoning(self, signal_quality, false_positive_rate, complexity_class, deployment_readiness, maintenance_cost) -> str:
        return (
            f"signal_quality={signal_quality.value}; "
            f"false_positive_rate={false_positive_rate.value}; "
            f"complexity_class={complexity_class.value}; "
            f"deployment_readiness={deployment_readiness.value}; "
            f"maintenance_cost={maintenance_cost.value}"
        )

    def _is_family_specific(self, sigma_rule) -> bool:
        return (getattr(sigma_rule, "x_family", None) not in (None, "generic")) or (getattr(sigma_rule, "x_signature", None) not in (None, "generic"))

    def _telemetry_confidence(self, telemetry) -> float:
        value = self._get(telemetry, "telemetry_confidence")
        try:
            return float(value) if value is not None else 0.0
        except (TypeError, ValueError):
            return 0.0

    def _telemetry_logsources(self, telemetry) -> list[str]:
        return [str(item) for item in self._get(telemetry, "candidate_logsources") or []]

    def _get(self, value: object | None, key: str) -> object | None:
        if value is None:
            return None
        if isinstance(value, dict):
            return value.get(key)
        return getattr(value, key, None)