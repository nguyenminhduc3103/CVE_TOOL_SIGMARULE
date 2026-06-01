from __future__ import annotations

from abc import ABC, abstractmethod

from app.coverage.sigma_searcher import SigmaRule


class RuleSimilarityEngine(ABC):
    @abstractmethod
    def score(
        self,
        rule: SigmaRule,
        cve_id: str,
        description: str,
        techniques: list[str],
        behaviors: list[str],
        logsource_categories: list[str],
    ) -> dict[str, float]:
        raise NotImplementedError


class SimpleRuleSimilarityEngine(RuleSimilarityEngine):
    def score(
        self,
        rule: SigmaRule,
        cve_id: str,
        description: str,
        techniques: list[str],
        behaviors: list[str],
        logsource_categories: list[str],
    ) -> dict[str, float]:
        attack_overlap = self._overlap_score(set(techniques), set(rule.attack_techniques))
        candidate_logsources = {value for value in [rule.logsource_category] if value}
        logsource_overlap = self._overlap_score(set(logsource_categories), candidate_logsources)
        behavior_overlap = self._overlap_score(set(behaviors), set(rule.behavior_markers))
        title_similarity = self._title_similarity(description, rule.title_tokens)

        cve_tag = cve_id.lower().replace("cve-", "cve.").replace("-", ".")
        cve_overlap = 1.0 if cve_tag in {tag.lower() for tag in rule.tags} else 0.0

        coverage_score = (
            (0.35 * attack_overlap)
            + (0.2 * logsource_overlap)
            + (0.25 * behavior_overlap)
            + (0.15 * cve_overlap)
            + (0.05 * title_similarity)
        )

        return {
            "attack_overlap": round(attack_overlap, 3),
            "logsource_overlap": round(logsource_overlap, 3),
            "behavior_overlap": round(behavior_overlap, 3),
            "cve_overlap": round(cve_overlap, 3),
            "title_similarity": round(title_similarity, 3),
            "coverage_score": round(coverage_score, 3),
        }

    def _overlap_score(self, lhs: set[str], rhs: set[str]) -> float:
        if not lhs or not rhs:
            return 0.0
        overlap = len(lhs.intersection(rhs))
        total = len(lhs.union(rhs))
        if total == 0:
            return 0.0
        return overlap / total

    def _title_similarity(self, description: str, title_tokens: tuple[str, ...]) -> float:
        if not description or not title_tokens:
            return 0.0
        desc_tokens = {token for token in description.lower().replace("-", " ").split() if token}
        title_set = set(title_tokens)
        return self._overlap_score(desc_tokens, title_set)

