from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parents[2]
INPUT_FILE = ROOT_DIR / ".cache" / "mitre_attack" / "ATT_CK_TTPs" / "ATT_CK.json"
FALLBACK_INPUT_FILE = ROOT_DIR / ".cache" / "mitre_attack" / "ATT_CK.json"
OUTPUT_FILE = ROOT_DIR / ".cache" / "ontology" / "ATT_CK_TTPs" / "TTPs_mapping.json"


def build_ttps_mapping(
    input_path: Path = INPUT_FILE,
    output_path: Path = OUTPUT_FILE,
) -> dict[str, dict[str, Any]]:
    target_input = input_path if input_path.exists() else FALLBACK_INPUT_FILE
    if not target_input.exists():
        raise FileNotFoundError(f"Neither {input_path} nor {FALLBACK_INPUT_FILE} exists.")

    logger.info("Loading standardized ATT_CK JSON from %s...", target_input)
    with open(target_input, "r", encoding="utf-8") as f:
        data = json.load(f)

    techniques = data.get("techniques", [])
    mapping: dict[str, dict[str, Any]] = {}

    for t in techniques:
        tech_id = t.get("id")
        if not tech_id:
            continue

        # Extract tactic IDs (e.g. ["TA0001", "TA0002"])
        tactics_list = []
        for tac in t.get("tactics", []):
            if isinstance(tac, dict) and tac.get("id"):
                tactics_list.append(tac["id"])
            elif isinstance(tac, str):
                tactics_list.append(tac)

        mapping[tech_id] = {
            "name": t.get("name", ""),
            "description": t.get("description", ""), # <--- DÒNG MỚI ĐƯỢC THÊM
            "tactics": tactics_list,
            "parent": t.get("parent"),
            "children": t.get("subtechniques", []),
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
