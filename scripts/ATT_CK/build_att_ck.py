"""Script to parse and standardize MITRE ATT&CK STIX bundle into canonical ATT_CK.json.

Input: .cache/mitre_attack/enterprise-attack.json
Output: .cache/mitre_attack/ATT_CK.json
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parents[2]
INPUT_FILE = ROOT_DIR / ".cache" / "mitre_attack" / "enterprise-attack.json"
OUTPUT_FILE = ROOT_DIR / ".cache" / "mitre_attack" / "ATT_CK_TTPs" / "ATT_CK.json"

EXPLICIT_DC_TO_DS: dict[str, str] = {
    "Response Content": "Network Traffic",
    "Response Metadata": "Network Traffic",
    "Malware Content": "Malware Repository",
    "Malware Metadata": "Malware Repository",
    "Network Connection Creation": "Network Traffic",
    "Active DNS": "Network Traffic",
    "Passive DNS": "Network Traffic",
    "Host Status": "Sensor Health",
    "Social Media": "Persona",
    "OS API Execution": "Process",
    "Domain Registration": "Domain Name",
}


def build_att_ck_json(input_path: Path = INPUT_FILE, output_path: Path = OUTPUT_FILE) -> dict[str, Any]:
    logger.info("Loading STIX bundle from %s...", input_path)
    with open(input_path, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    objects = bundle.get("objects", [])
    id_map = {o["id"]: o for o in objects}

    # 1. Parse tactics (x-mitre-tactic)
    tactic_map: dict[str, dict[str, str]] = {}
    for o in objects:
        if o.get("type") == "x-mitre-tactic" and not o.get("x_mitre_deprecated"):
            shortname = o.get("x_mitre_shortname")
            tactic_name = o.get("name")
            tactic_id = None
            for ext in o.get("external_references", []):
                if ext.get("source_name") == "mitre-attack":
                    tactic_id = ext.get("external_id")
                    break
            if shortname and tactic_id:
                tactic_map[shortname] = {"id": tactic_id, "name": tactic_name}

    logger.info("Loaded %d tactics.", len(tactic_map))

    # 2. Build Data Source & Data Component mapping
    ds_objs = [o for o in objects if o.get("type") == "x-mitre-data-source"]
    ds_names = sorted([ds["name"] for ds in ds_objs], key=len, reverse=True)

    def get_data_source_for_dc(dc_name: str) -> str | None:
        if dc_name in EXPLICIT_DC_TO_DS:
            return EXPLICIT_DC_TO_DS[dc_name]
        for ds in ds_names:
            if dc_name.startswith(ds) or ds.lower() in dc_name.lower():
                return ds
        return None

    # 3. Trace detection strategies -> analytics -> data components -> techniques
    det_rels = [
        o for o in objects
        if o.get("type") == "relationship" and o.get("relationship_type") == "detects"
    ]
    tech_to_dcs: dict[str, set[str]] = {}
    for r in det_rels:
        tech_stix_id = r.get("target_ref")
        det_strat = id_map.get(r.get("source_ref"))
        if not det_strat or det_strat.get("x_mitre_deprecated") or det_strat.get("revoked"):
            continue
        for a_ref in det_strat.get("x_mitre_analytic_refs", []):
            analytic = id_map.get(a_ref)
            if not analytic or analytic.get("x_mitre_deprecated"):
                continue
            for lsr in analytic.get("x_mitre_log_source_references", []):
                dc_ref = lsr.get("x_mitre_data_component_ref")
                dc_obj = id_map.get(dc_ref)
                if dc_obj and not dc_obj.get("x_mitre_deprecated") and not dc_obj.get("revoked"):
                    tech_to_dcs.setdefault(tech_stix_id, set()).add(dc_obj["name"])

    # 4. Parse techniques (attack-pattern)
    ap_objs = [
        o for o in objects
        if o.get("type") == "attack-pattern"
        and not o.get("x_mitre_deprecated")
        and not o.get("revoked")
    ]

    techniques_raw: list[dict[str, Any]] = []
    parent_subtechs: dict[str, list[str]] = {}

    for ap in ap_objs:
        ext_id = None
        for ext in ap.get("external_references", []):
            if ext.get("source_name") == "mitre-attack" and ext.get("external_id", "").startswith("T"):
                ext_id = ext.get("external_id")
                break
        if not ext_id:
            continue

        is_subtech = bool(ap.get("x_mitre_is_subtechnique", False))
        parent_id = ext_id.split(".")[0] if is_subtech and "." in ext_id else None

        if is_subtech and parent_id:
            parent_subtechs.setdefault(parent_id, []).append(ext_id)

        # Map kill chain phases to tactics
        tactics = []
        seen_tactic_ids = set()
        for kcp in ap.get("kill_chain_phases", []):
            if kcp.get("kill_chain_name") == "mitre-attack":
                phase = kcp.get("phase_name")
                if phase in tactic_map:
                    tac_info = tactic_map[phase]
                    if tac_info["id"] not in seen_tactic_ids:
                        seen_tactic_ids.add(tac_info["id"])
                        tactics.append(tac_info)

        # Data components & data sources
        dc_set = tech_to_dcs.get(ap["id"], set())
        dcs = sorted(list(dc_set))
        ds_set = set()
        for dc_name in dcs:
            ds_name = get_data_source_for_dc(dc_name)
            if ds_name:
                ds_set.add(ds_name)
        dss = sorted(list(ds_set))

        techniques_raw.append({
            "id": ext_id,
            "name": ap.get("name", ""),
            "description": ap.get("description", ""),
            "platforms": ap.get("x_mitre_platforms", []),
            "is_subtechnique": is_subtech,
            "parent": parent_id,
            "subtechniques": [],
            "tactics": tactics,
            "data_sources": dss,
            "data_components": dcs,
        })

    # Populate subtechniques array for parent techniques
    for t in techniques_raw:
        if not t["is_subtechnique"]:
            t["subtechniques"] = sorted(parent_subtechs.get(t["id"], []))

    # Sort techniques by ID naturally (T1001, T1001.001, T1002...)
    def tech_sort_key(item: dict[str, Any]) -> tuple[int, int]:
        tech_id = item["id"]
        parts = tech_id.lstrip("T").split(".")
        main_num = int(parts[0]) if parts[0].isdigit() else 0
        sub_num = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        return main_num, sub_num

    techniques_sorted = sorted(techniques_raw, key=tech_sort_key)

    result = {
        "version": "2.1",
        "technique_count": len(techniques_sorted),
        "tactic_count": len(tactic_map),
        "techniques": techniques_sorted,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    logger.info("Writing %d techniques to %s...", len(techniques_sorted), output_path)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    file_size_mb = output_path.stat().st_size / (1024 * 1024)
    logger.info("Successfully saved ATT_CK.json (%.2f MB).", file_size_mb)
    return result


if __name__ == "__main__":
    build_att_ck_json()
