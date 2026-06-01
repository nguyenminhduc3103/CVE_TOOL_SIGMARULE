from __future__ import annotations


class QualityScorer:
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