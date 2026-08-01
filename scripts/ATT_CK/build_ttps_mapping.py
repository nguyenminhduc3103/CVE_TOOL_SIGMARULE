"""Build TTPs mapping từ MITRE ATT&CK JSON sang format hierarchical.

Output format:
{
  "T1003": {
    "name": "OS Credential Dumping",
    "tactic_id": "TA0006",
    "phase": "Credential Access",
    "children": {
      "T1003.001": {"name": "LSASS Memory"},
      "T1003.002": {"name": "Security Account Manager"}
    }
  }
}
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parents[2]
INPUT_FILE = ROOT_DIR / ".cache" / "mitre_attack" / "ATT_CK_TTPs" / "ATT_CK.json"
OUTPUT_FILE = ROOT_DIR / ".cache" / "ontology" / "ATT_CK_TTPs" / "TTPs_mapping.json"


def build_ttps_mapping(
    input_path: Path = INPUT_FILE,
    output_path: Path = OUTPUT_FILE,
) -> dict[str, dict[str, Any]]:
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    logger.info("Loading ATT_CK JSON from %s...", input_path)
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    techniques = data.get("techniques", [])
    mapping: dict[str, dict[str, Any]] = {}

    # Build lookup for tactic info
    tactic_lookup: dict[str, str] = {}
    for t in techniques:
        for tac in t.get("tactics", []):
            if isinstance(tac, dict):
                tid = tac.get("id", "")
                tname = tac.get("name", "")
                if tid:
                    tactic_lookup[tid] = tname

    for t in techniques:
        tech_id = t.get("id", "")
        if not tech_id:
            continue

        is_subtechnique = t.get("is_subtechnique", False)
        if is_subtechnique:
            continue  # Skip subtechniques, they'll be added as children

        # Get primary tactic
        tactics = t.get("tactics", [])
        primary_tactic = tactics[0] if tactics else {}
        if isinstance(primary_tactic, dict):
            tactic_id = primary_tactic.get("id", "")
            tactic_name = primary_tactic.get("name", "")
        else:
            tactic_id = str(primary_tactic)
            tactic_name = tactic_lookup.get(tactic_id, "")

        # Build children (subtechniques)
        children: dict[str, dict[str, str]] = {}
        for child_id in t.get("subtechniques", []):
            # Find child technique info
            for sub_t in techniques:
                if sub_t.get("id") == child_id:
                    children[child_id] = {
                        "name": sub_t.get("name", "")
                    }
                    break

        mapping[tech_id] = {
            "name": t.get("name", ""),
            "tactic_id": tactic_id,
            "phase": tactic_name,
            "children": children,
        }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    logger.info("Writing %d technique mappings to %s...", len(mapping), output_path)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(mapping, f, indent=2, ensure_ascii=False)

    file_size_kb = output_path.stat().st_size / 1024
    logger.info("Successfully generated TTPs_mapping.json (%.2f KB).", file_size_kb)
    return mapping


if __name__ == "__main__":
    build_ttps_mapping()
