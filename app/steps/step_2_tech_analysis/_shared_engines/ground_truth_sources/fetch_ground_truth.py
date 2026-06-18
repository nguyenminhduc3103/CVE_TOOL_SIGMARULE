"""Fetch ground truth files (CAPEC STIX + CTID CVE→ATT&CK mappings).

Downloads:
  1. capec_stix.json - MITRE CAPEC STIX 2.1 bundle (4.3MB)
     Source: https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json
  2. cti_mappings.csv - CTID MITRE CVE→ATT&CK direct mapping (34KB)
     Source: https://raw.githubusercontent.com/center-for-threat-informed-defense/attack_to_cve/main/Att&ckToCveMappings.csv

Usage:
    python -m app.steps.step_2_tech_analysis._shared_engines.ground_truth_sources.fetch_ground_truth
    # hoặc:
    cd f:\\cve-ti-platform
    python -X utf8 -m app.steps.step_2_tech_analysis._shared_engines.ground_truth_sources.fetch_ground_truth

Kết quả:
    app/steps/step_2_tech_analysis/_shared_engines/ground_truth_sources/
        ├── capec_stix.json   (4.3MB)
        ├── cti_mappings.csv  (34KB)
        ├── __init__.py
        └── fetch_ground_truth.py  (file này)
"""
from __future__ import annotations

import json
import logging
import sys
import urllib.error
import urllib.request
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# Đường dẫn tuyệt đối tới thư mục chứa file này
_SCRIPT_DIR = Path(__file__).resolve().parent

# URL gốc từ MITRE
CAPEC_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "capec/2.1/stix-capec.json"
)
CTID_URL = (
    "https://raw.githubusercontent.com/center-for-threat-informed-defense/"
    "attack_to_cve/master/Att%26ckToCveMappings.csv"
)
# MITRE ATT&CK Enterprise STIX bundle (~10-12MB) - extracted to lightweight JSON
# (~50-100KB) at fetch time. Runtime only loads the small JSON for O(1) lookups.
ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

CAPEC_DEST = _SCRIPT_DIR / "capec_stix.json"
CTID_DEST = _SCRIPT_DIR / "cti_mappings.csv"
ATTACK_DEST = _SCRIPT_DIR / "attack_technique_to_tactic.json"

# MITRE ATT&CK tactic shortname → ID (v15)
# Source: https://attack.mitre.org/tactics/enterprise/
TACTIC_SHORTNAME_TO_ID: dict[str, str] = {
    "reconnaissance": "TA0043",
    "resource-development": "TA0042",
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "exfiltration": "TA0010",
    "command-and-control": "TA0011",
    "impact": "TA0040",
}


def _download(url: str, dest: Path, chunk_size: int = 64 * 1024) -> int:
    """Download file từ URL, ghi ra dest. Trả về số bytes đã tải.

    Hiển thị progress bar đơn giản vì CAPEC bundle ~4.3MB, không nên
    chạy silent.
    """
    logger.info("Downloading %s", url)
    logger.info("        → %s", dest)

    # Windows console: force UTF-8 để log không bị lỗi encoding
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        pass

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "CVE-TI-Platform-OntologyManager/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            written = 0
            with open(dest, "wb") as out:
                while True:
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    out.write(chunk)
                    written += len(chunk)
                    # Progress log mỗi ~1MB
                    if total and written // (1024 * 1024) != (written - len(chunk)) // (1024 * 1024):
                        pct = written * 100 // total
                        logger.info(
                            "  ... %d KB / %d KB (%d%%)",
                            written // 1024,
                            total // 1024,
                            pct,
                        )
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        logger.error("Download failed: %s", exc)
        raise

    size_kb = written // 1024
    logger.info("Done: %d KB", size_kb)
    return written


def fetch_capec(force: bool = False) -> Path:
    """Tải CAPEC STIX bundle, skip nếu đã có (trừ khi force=True)."""
    if CAPEC_DEST.exists() and not force:
        size_kb = CAPEC_DEST.stat().st_size // 1024
        logger.info(
            "capec_stix.json đã tồn tại (%d KB) - skip. Dùng force=True để tải lại.",
            size_kb,
        )
        return CAPEC_DEST
    _download(CAPEC_URL, CAPEC_DEST)
    return CAPEC_DEST


def fetch_ctid(force: bool = False) -> Path:
    """Tải CTID CVE→ATT&CK CSV, skip nếu đã có (trừ khi force=True)."""
    if CTID_DEST.exists() and not force:
        size_kb = CTID_DEST.stat().st_size // 1024
        logger.info(
            "cti_mappings.csv đã tồn tại (%d KB) - skip. Dùng force=True để tải lại.",
            size_kb,
        )
        return CTID_DEST
    _download(CTID_URL, CTID_DEST)
    return CTID_DEST


def fetch_attack_tactics(force: bool = False) -> Path:
    """Download MITRE ATT&CK STIX bundle + extract lightweight technique→tactic JSON.

    Workflow:
      1. Download full enterprise-attack.json (~10-12MB) to temp
      2. Parse + extract only technique_id → [tactic_ids, ...]
      3. Save lightweight JSON (~50-100KB) as ATTACK_DEST
      4. Cleanup temp STIX bundle

    Runtime (`OntologyManager`) chỉ load ATTACK_DEST nhỏ, không parse
    STIX bundle lớn mỗi CVE. Performance: <5ms init, <1μs per lookup.
    """
    if ATTACK_DEST.exists() and not force:
        size_kb = ATTACK_DEST.stat().st_size // 1024
        logger.info(
            "attack_technique_to_tactic.json đã tồn tại (%d KB) - skip. "
            "Dùng force=True để tải lại.",
            size_kb,
        )
        return ATTACK_DEST

    temp_path = _SCRIPT_DIR / "_temp_attack_stix.json"
    try:
        _download(ATTACK_URL, temp_path)
        mapping = _extract_technique_to_tactic(temp_path)
        output = {
            "_version": "1.0",
            "_source": "MITRE ATT&CK Enterprise STIX v15",
            "_description": (
                "Lightweight technique→tactic lookup. Pre-extracted from "
                "enterprise-attack.json to avoid runtime STIX parsing."
            ),
            "tactic_shortname_to_id": dict(TACTIC_SHORTNAME_TO_ID),
            "mapping": mapping,
        }
        with open(ATTACK_DEST, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False, sort_keys=True)
        logger.info(
            "Saved attack_technique_to_tactic.json: %d techniques",
            len(mapping),
        )
    finally:
        # Cleanup temp STIX bundle (đã extract xong)
        if temp_path.exists():
            temp_path.unlink()
    return ATTACK_DEST


def _extract_technique_to_tactic(stix_path: Path) -> dict[str, list[str]]:
    """Parse MITRE ATT&CK STIX bundle, extract {technique_id: [tactic_ids, ...]}.

    Lọc:
      - Chỉ attack-pattern objects
      - Bỏ qua revoked/deprecated techniques
      - Extract technique ID từ external_references (source_name='mitre-attack')
      - Extract tactic shortname từ kill_chain_phases, map sang TACTIC_SHORTNAME_TO_ID

    Returns:
        Dict mapping ATT&CK technique ID (vd 'T1190', 'T1071.001') →
        sorted list of Tactic IDs (vd ['TA0001']).
    """
    with open(stix_path, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    mapping: dict[str, list[str]] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        # Skip revoked + deprecated (chỉ giữ current techniques)
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        # Extract technique ID từ external_references
        tech_id: str | None = None
        for ref in obj.get("external_references", []) or []:
            if ref.get("source_name") == "mitre-attack":
                candidate = ref.get("external_id", "")
                if candidate.startswith("T"):
                    tech_id = candidate
                    break
        if not tech_id:
            continue

        # Extract tactic IDs từ kill_chain_phases
        tactic_ids: set[str] = set()
        for phase in obj.get("kill_chain_phases", []) or []:
            if phase.get("kill_chain_name") != "mitre-attack":
                continue
            shortname = phase.get("phase_name", "")
            tactic_id = TACTIC_SHORTNAME_TO_ID.get(shortname)
            if tactic_id:
                tactic_ids.add(tactic_id)

        if tactic_ids:
            mapping[tech_id] = sorted(tactic_ids)

    return mapping


def _validate_capec(path: Path) -> None:
    """Sanity-check: parse CAPEC bundle, in số object + bridge count."""
    logger.info("Validate capec_stix.json ...")
    try:
        with open(path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("CAPEC bundle invalid: %s", exc)
        return

    objects = bundle.get("objects", [])
    attack_patterns = [o for o in objects if o.get("type") == "attack-pattern"]
    logger.info("  Tổng objects:    %d", len(objects))
    logger.info("  attack-patterns: %d", len(attack_patterns))

    cwe_count: set[str] = set()
    tech_count: set[str] = set()
    for obj in attack_patterns:
        for ref in obj.get("external_references", []) or []:
            if ref.get("source_name") == "cwe":
                cwe_count.add(ref.get("external_id", ""))
            elif ref.get("source_name") == "ATTACK":
                tech_count.add(ref.get("external_id", ""))
    logger.info("  Unique CWEs:     %d", len(cwe_count))
    logger.info("  Unique ATT&CK:   %d", len(tech_count))


def _validate_ctid(path: Path) -> None:
    """Sanity-check: parse CTID CSV, in CVE count + technique count."""
    import csv
    logger.info("Validate cti_mappings.csv ...")
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
    except (OSError, csv.Error) as exc:
        logger.error("CTID CSV invalid: %s", exc)
        return
    cves = {r.get("CVE ID", "").strip() for r in rows if r.get("CVE ID")}
    logger.info("  Tổng dòng:    %d", len(rows))
    logger.info("  Unique CVEs:   %d", len(cves))


def _validate_attack_tactics(path: Path) -> None:
    """Sanity-check attack_technique_to_tactic.json - spot-check critical techniques."""
    logger.info("Validate attack_technique_to_tactic.json ...")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("attack_technique_to_tactic.json invalid: %s", exc)
        return
    mapping = data.get("mapping", {})
    logger.info("  Tổng techniques: %d", len(mapping))
    logger.info("  Version:         %s", data.get("_version", "?"))
    logger.info("  Source:          %s", data.get("_source", "?"))
    # Spot-check critical techniques
    for tech in ["T1190", "T1071", "T1210", "T1059", "T1566", "T1105"]:
        if tech in mapping:
            logger.info("  %-7s → %s", tech, mapping[tech])
        else:
            logger.warning("  %-7s MISSING from MITRE mapping!", tech)


def main() -> int:
    """Entry point - tải cả 3 file (CAPEC + CTID + ATT&CK tactics) + validate."""
    logger.info("=" * 60)
    logger.info("Fetch ground truth for OntologyManager (4-Layer Resolver)")
    logger.info("=" * 60)
    logger.info("Output dir: %s", _SCRIPT_DIR)

    try:
        capec_path = fetch_capec()
        ctid_path = fetch_ctid()
        attack_path = fetch_attack_tactics()
    except Exception as exc:
        logger.error("Fetch thất bại: %s", exc)
        return 1

    logger.info("=" * 60)
    logger.info("Validating files ...")
    logger.info("=" * 60)
    _validate_capec(capec_path)
    _validate_ctid(ctid_path)
    _validate_attack_tactics(attack_path)

    logger.info("=" * 60)
    logger.info("✅ DONE. Bỏ env CVE_TI_DISABLE_OFFLINE_ONTOLOGY=1 để dùng.")
    logger.info("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
