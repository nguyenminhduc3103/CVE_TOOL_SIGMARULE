from __future__ import annotations

from app.steps.step_3_coverage.decision_engine import decide_coverage
from app.steps.step_3_coverage.sigma_searcher import FilesystemRuleInventory, InMemoryRuleInventory, RuleInventory, SigmaRepositoryIndexer
from app.steps.step_3_coverage.similarity_engine import SimpleRuleSimilarityEngine
from app.shared.models.coverage import CoverageAssessment
from app.shared.models.enriched import EnrichedCVEContext
from app.steps.step_1_triage.capability_checker import CapabilityClassification


def _derive_logsources(mandatory_behaviors: list[str] | None) -> list[str]:
    behavior_to_logsource = {
        "process_execution": "process_creation",
        "process_creation": "process_creation",
        "shell_spawn": "process_creation",
        "file_write": "file_event",
        "registry_modification": "registry_event",
        "image_load": "image_load",
        "network_connection": "network_connection",
        "network_callback": "network_connection",
        "http_request": "webserver",
        "web_request": "webserver",
        "webshell": "webserver",
        "webshell_drop": "webserver",
        "database_query": "webserver",
        "privilege_escalation": "process_creation",
    }

    logsources: list[str] = []
    for behavior in mandatory_behaviors or []:
        mapped = behavior_to_logsource.get(behavior)
        if mapped and mapped not in logsources:
            logsources.append(mapped)
    return logsources


def _derive_keywords(context: EnrichedCVEContext) -> list[str]:
    description = (context.core.description or "").lower()
    keywords: list[str] = []
    for token in ("jndi", "powershell", "cmd.exe", "webshell", "upload", "ssrf", "deserialization", "spooler", "printer", "driver", "traversal"):
        if token in description:
            keywords.append(token)
    return keywords


def _inventory() -> RuleInventory:
    return FilesystemRuleInventory()


async def run_coverage_stage(
    context: EnrichedCVEContext,
    capability: CapabilityClassification | None = None,
    inventory: RuleInventory | None = None,
) -> CoverageAssessment:
    if capability and capability.value.startswith("out_of_scope"):
        return CoverageAssessment(
            decision="NEW",
            matched_rule_ids=None,
            matched_titles=None,
            matched_rule_titles=None,
            coverage_score=0.0,
            coverage_reasoning=[f"Coverage skipped for {capability.value}"],
            overlap_score=0.0,
            relationship_type="new",
            reasoning=f"Coverage skipped for {capability.value}",
            decision_reason=f"Coverage skipped for {capability.value}",
            overlap_breakdown={
                "attack_overlap_score": 0.0,
                "logsource_overlap_score": 0.0,
                "behavior_overlap_score": 0.0,
            },
            skipped=True,
        )

    techniques = context.attack.techniques if context.attack else []
    behaviors = context.analysis.mandatory_behaviors if context.analysis else []
    logsources = _derive_logsources(behaviors)
    repository = inventory or _inventory()
    indexer = SigmaRepositoryIndexer(repository)
    rules = indexer.load()
    if not rules:
        rules = SigmaRepositoryIndexer(InMemoryRuleInventory()).load()

    similarity_engine = SimpleRuleSimilarityEngine()

    scored: list[tuple[str, str, dict[str, float]]] = []
    for rule in rules:
        dimensions = similarity_engine.score(
            rule=rule,
            cve_id=context.core.cve_id,
            description=context.core.description or "",
            techniques=techniques or [],
            behaviors=behaviors or [],
            logsource_categories=logsources,
        )
        if dimensions["coverage_score"] <= 0:
            continue
        scored.append((rule.rule_id, rule.title, dimensions))

    scored.sort(key=lambda item: item[2]["coverage_score"], reverse=True)

    if scored:
        best_dimensions = scored[0][2]
    else:
        best_dimensions = {
            "attack_overlap": 0.0,
            "logsource_overlap": 0.0,
            "behavior_overlap": 0.0,
            "cve_overlap": 0.0,
            "title_similarity": 0.0,
            "coverage_score": 0.0,
        }

    decision, decision_reason = decide_coverage(
        coverage_score=best_dimensions["coverage_score"],
        attack_overlap=best_dimensions["attack_overlap"],
        logsource_overlap=best_dimensions["logsource_overlap"],
        behavior_overlap=best_dimensions["behavior_overlap"],
        cve_overlap=best_dimensions["cve_overlap"],
    )

    matched_rule_ids = [rule_id for rule_id, _, _ in scored[:5]]
    matched_titles = [title for _, title, _ in scored[:5]]
    similarity_reasoning = [
        (
            f"{rule_id} score={dims['coverage_score']:.3f} "
            f"attack={dims['attack_overlap']:.3f} logsource={dims['logsource_overlap']:.3f} "
            f"behavior={dims['behavior_overlap']:.3f} cve={dims['cve_overlap']:.3f} title={dims['title_similarity']:.3f}"
        )
        for rule_id, _, dims in scored[:5]
    ]
    coverage_reasoning = [decision_reason] + similarity_reasoning
    overlap_breakdown = {
        "attack_overlap_score": best_dimensions["attack_overlap"],
        "logsource_overlap_score": best_dimensions["logsource_overlap"],
        "behavior_overlap_score": best_dimensions["behavior_overlap"],
    }

    return CoverageAssessment(
        decision=decision,
        matched_rule_ids=matched_rule_ids or None,
        matched_titles=matched_titles or None,
        matched_rule_titles=matched_titles or None,
        coverage_score=best_dimensions["coverage_score"],
        coverage_reasoning=coverage_reasoning,
        similarity_reasoning=similarity_reasoning or None,
        related_rules=matched_rule_ids or None,
        related_attack_rules=matched_rule_ids or None,
        overlap_score=best_dimensions["coverage_score"],
        relationship_type=decision.lower(),
        reasoning=decision_reason,
        overlap_breakdown=overlap_breakdown,
        decision_reason=decision_reason,
    )
