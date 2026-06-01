from __future__ import annotations


RELATIONSHIP_BY_SCORE: tuple[tuple[float, str], ...] = (
    (0.75, "supersede"),
    (0.45, "extend"),
    (0.2, "related"),
    (0.0, "new"),
)


def build_relationship(overlap_score: float) -> str:
    for threshold, relationship in RELATIONSHIP_BY_SCORE:
        if overlap_score >= threshold:
            return relationship
    return "new"
