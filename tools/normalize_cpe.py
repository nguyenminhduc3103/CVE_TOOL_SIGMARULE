# CPE List Normalizer - tools/normalize_cpe.py
# Normalize product labels into deterministic CPE buckets

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from pathlib import Path

from pydantic import BaseModel, Field


# Repo bootstrap
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

logger = logging.getLogger(__name__)


# Constants
# CPE part tag -> output bucket
TAG_TO_BUCKET: dict[str, str] = {
    "[APP]": "applications",
    "[OS]": "operating_systems",
    "[HW]": "hardware",
}

# Match [APP] xxx, [OS] xxx, [HW] xxx
_TAG_PATTERN = re.compile(r"^\s*(\[(APP|OS|HW)\])\s*(.+?)\s*$")


# Schema
class NormalizedCPE(BaseModel):
    """Normalized product list grouped by CPE part"""
    
    applications: list[str] = Field(
        default_factory=list,
        description="Software / applications (CPE part=a)",
    )
    operating_systems: list[str] = Field(
        default_factory=list,
        description="Operating systems (CPE part=o)",
    )
    hardware: list[str] = Field(
        default_factory=list,
        description="Hardware devices (CPE part=h)",
    )


# Pure normalizer
def normalize_products(labels: list[str]) -> NormalizedCPE:
    """
    Normalize CPE labels by grouping, deduplicating, and sorting
    
    Groups by [APP]/[OS]/[HW], deduplicates, sorts output, ignores malformed
    """
    
    if not isinstance(labels, list):
        raise TypeError("labels must be a list[str]")
    
    buckets: dict[str, set[str]] = {
        "applications": set(),
        "operating_systems": set(),
        "hardware": set(),
    }
    
    for raw in labels:
        if not isinstance(raw, str):
            logger.debug("Skip non-string item: %r", raw)
            continue
        
        raw = raw.strip()
        match = _TAG_PATTERN.match(raw)
        if match is None:
            logger.debug("Skip malformed label: %s", raw)
            continue
        
        tag = match.group(1)
        body = match.group(3).strip()
        bucket = TAG_TO_BUCKET[tag]
        buckets[bucket].add(body)
    
    return NormalizedCPE(
        applications=sorted(buckets["applications"]),
        operating_systems=sorted(buckets["operating_systems"]),
        hardware=sorted(buckets["hardware"]),
    )


# CLI
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-i", "--input",
        help="JSON file containing a list of tagged product labels",
    )
    parser.add_argument(
        "-o", "--output",
        help="Write normalized JSON to file",
    )
    parser.add_argument(
        "--pretty",
        dest="pretty",
        action="store_true",
        default=True,
        help="Pretty JSON output (default)",
    )
    parser.add_argument(
        "--compact",
        dest="pretty",
        action="store_false",
        help="Compact JSON output",
    )
    return parser


# Main
def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    
    if args.input:
        raw = Path(args.input).read_text(encoding="utf-8")
    else:
        raw = sys.stdin.read()
    
    try:
        labels = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"[normalize_cpe] invalid JSON input: {exc}", file=sys.stderr)
        return 2
    
    if not isinstance(labels, list):
        print("[normalize_cpe] input must be a JSON list", file=sys.stderr)
        return 2
    
    normalized = normalize_products(labels)
    payload = json.dumps(
        normalized.model_dump(),
        ensure_ascii=False,
        indent=2 if args.pretty else None,
    )
    
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(payload + "\n", encoding="utf-8")
        print(f"[normalize_cpe] wrote {out_path}", file=sys.stderr)
    else:
        print(payload)
    
    return 0


# Entrypoint
if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)