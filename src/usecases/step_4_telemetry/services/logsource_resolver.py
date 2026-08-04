# Logsource resolver — pure data-driven code. No AI, no hardcoded category names.
#
# Pipeline:
#   candidate_features + target_environment
#       │
#       ├──> extract_categories(...)           # stable ∪ conditional, dedup, ordered
#       │
#       └──> resolve(knowledge, target_env, categories)
#                  │
#                  └──> list[SigmaLogsource]
#
# The resolver is split into two pieces so the core stays ~20 lines and
# is trivially testable. The AI service loads `knowledge` once and
# injects it; `resolve` itself never touches I/O.
from __future__ import annotations

from src.usecases.step_4_telemetry._knowledge.sigma_category_statistics import (
    SigmaCategoryStatistics,
    SigmaFieldStats,
)
from src.usecases.step_4_telemetry.models.sigma_logsource import SigmaLogsource
from src.usecases.step_4_telemetry.models.telemetry_plan import (
    CandidateFeatures,
    TargetEnvironment,
)


def extract_categories(candidate_features: CandidateFeatures) -> list[str]:
    """Flatten `stable ∪ conditional` into an ordered, deduped list.

    `optional` is intentionally excluded from logsource selection — it's
    a supplementary indicator tier, not a primary detection surface.

    Order: stable first (in input order), then conditional (skipping any
    telemetry_concept already seen). First occurrence wins.
    """
    out: list[str] = []
    seen: set[str] = set()
    for tier in (candidate_features.stable, candidate_features.conditional):
        for feature in tier:
            concept = feature.telemetry_concept
            if concept in seen:
                continue
            seen.add(concept)
            out.append(concept)
    return out


def resolve(
    knowledge: SigmaCategoryStatistics,
    target_env: TargetEnvironment,
    categories: list[str],
) -> list[SigmaLogsource]:
    """Pure function. Maps `categories` × `target_env.platforms` to SigmaLogsources.

    Each emitted `SigmaLogsource` carries `allowed_fields` drawn from
    `info.fields` for the matched category — i.e. the SigmaHQ field
    names a rule for that category can match, plus the operators seen
    in the corpus. Operators order is preserved from source.

    Per category:
      - if `knowledge.get(c).platforms` is empty (or category unknown),
        emit a single `{product: None, category}` entry with that
        category's fields;
      - else, iterate `target_env.platforms` in input order and emit one
        `{product: platform, category}` per platform in the category's
        platform list, each carrying the same category fields.

    Dedup by `(product|None, category)` using insertion-ordered dict
    (Python 3.7+). Output preserves (category-order, then platform-order).

    The resolver contains ZERO hardcoded category names. It does not know
    what `webserver`, `process_creation`, or `network_connection` mean —
    it only reads `info.platforms` / `info.fields` and reacts to the
    empty-list signal.
    """
    out: list[SigmaLogsource] = []
    seen: dict[tuple[str | None, str], None] = {}

    for category in categories:
        info = knowledge.get(category)
        platforms = info.platforms if info is not None else []
        fields = info.fields if info is not None else {}

        if not platforms:
            key = (None, category)
            if key not in seen:
                seen[key] = None
                out.append(_make(None, category, fields))
            continue

        for platform in target_env.platforms:
            if platform in platforms:
                key = (platform, category)
                if key not in seen:
                    seen[key] = None
                    out.append(_make(platform, category, fields))

    return out


def _make(
    product: str | None,
    category: str,
    fields: dict[str, SigmaFieldStats],
) -> SigmaLogsource:
    """Build a SigmaLogsource and project `fields` → `allowed_fields`.

    Drops the empty-string field name (a real entry in the source JSON
    under `application.fields`) — it's a SigmaHQ corpus artifact, not a
    real field name, and produces noise in the render.
    """
    allowed = {
        name: list(stats.operators)
        for name, stats in fields.items()
        if name  # filter empty-string keys
    }
    return SigmaLogsource(
        product=product,
        category=category,
        allowed_fields=allowed,
    )