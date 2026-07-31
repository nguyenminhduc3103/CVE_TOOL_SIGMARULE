"""Tool 4 — Build the short-form mandatory-behavior ontology used by Phase 1 prompt.

Pipeline:
    .cache/ontology/primitive_behavior_ontology.json  (Tool 3 output)
        |
        |  Strip `aliases` and `capecs` arrays — keep only `primitive` + `description`.
        v
    .cache/ontology/mandatory_behavior_ontology.json

Output schema:
    {
      "source": ".../primitive_behavior_ontology.json",
      "count": <int>,
      "entries": [
        {"primitive": "authorization_bypass", "description": "Access a protected resource without proper authorization."},
        ...
      ]
    }

Why short-form:
    Phase 1 prompt injects this list verbatim into the system prompt so the LLM
    selects `mandatory_behaviors` from a closed vocabulary. Aliases + capecs cost
    ~40-60 tokens per entry on top of primitive+description — dropping them cuts
    the prompt by ~30-40% without hurting recall (the LLM does not need aliases to
    match semantics; capecs are a reference cross-link that is irrelevant when
    generating analysis, only for post-hoc validation).

Idempotent: re-running with an unchanged source overwrites the output with the
same content. Safe to run from CI after re-running Tool 3.

Run:
    python scripts/build_mandatory_behavior_ontology.py
    python scripts/build_mandatory_behavior_ontology.py --source PATH --output PATH
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

logger = logging.getLogger("build_mandatory_behavior_ontology")

DEFAULT_SOURCE = Path(".cache/ontology/primitive_behavior_ontology.json")
DEFAULT_OUTPUT = Path(".cache/ontology/mandatory_behavior_ontology.json")


def build(source: Path, output: Path) -> int:
    """Read source ontology, drop aliases+capecs, write short-form.

    Returns 0 on success, 1 if source has no primitives (caller signals error
    back to the OS via exit code).
    """
    if not source.exists():
        logger.error("Source ontology not found at %s", source)
        return 1
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        logger.error("Invalid JSON in source ontology %s: %s", source, e)
        return 1

    primitives = data.get("primitives", [])
    if not primitives:
        logger.error("No primitives found in source ontology %s", source)
        return 1

    entries: list[dict] = []
    skipped = 0
    for p in primitives:
        token = (p.get("primitive") or "").strip()
        if not token:
            skipped += 1
            continue
        entries.append(
            {
                "primitive": token,
                "description": (p.get("description") or "").strip(),
            }
        )

    payload = {
        "source": str(source).replace("\\", "/"),
        "count": len(entries),
        "skipped_empty_primitive": skipped,
        "entries": entries,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    logger.info(
        "Wrote %d short-form entries (skipped %d empty) to %s",
        len(entries), skipped, output,
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build short-form mandatory-behavior ontology for Phase 1 prompt.",
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=DEFAULT_SOURCE,
        help=f"Source primitive-behavior ontology (default: {DEFAULT_SOURCE})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Output short-form ontology (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    )
    return build(args.source, args.output)


if __name__ == "__main__":
    sys.exit(main())
