"""Fetch ground truth files for Step 4 Telemetry (Sigma Taxonomy & CTID Mappings).

Downloads & generates:
  1. sigma_taxonomy.json - Single Source of Truth cho Sigma Logsources, Allowed Fields & Event IDs.
     Sources:
       - sigma_taxonomy_mappings.json (authoritative domain taxonomy defaults)
       - MITRE CTID sensor-mappings-to-attack (Enterprise Event IDs)
       - SigmaHQ specification (allowed fields cross-validation)
  2. cti_mappings.csv - CTID MITRE CVE→ATT&CK direct mapping (34KB)
     Source: https://raw.githubusercontent.com/center-for-threat-informed-defense/attack_to_cve/main/Att&ckToCveMappings.csv

Note: MITRE ATT&CK STIX bundle & CAPEC STIX bundle downloads are managed
separately via `app/shared/mitre/fetch_stix.py`.

Usage:
    python -m src.infrastructure.local_truth.fetch_ground_truth

Kết quả:
    src/infrastructure/local_truth/
        ├── sigma_taxonomy.json   (~30KB)
        ├── cti_mappings.csv      (~34KB)
        ├── __init__.py
        └── fetch_ground_truth.py (file này)
"""
from __future__ import annotations

import csv
import io
import json
import logging
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("local_truth.fetch_ground_truth")

# Đường dẫn tuyệt đối tới thư mục chứa file này
_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

CTID_URL = (
    "https://raw.githubusercontent.com/center-for-threat-informed-defense/"
    "attack_to_cve/master/Att%26ckToCveMappings.csv"
)

SIGMA_TAXONOMY_URL = (
    "https://raw.githubusercontent.com/SigmaHQ/sigma-specification/main/"
    "specification/sigma-appendix-taxonomy.md"
)

CTID_DEST = _SCRIPT_DIR / "cti_mappings.csv"
SIGMA_TAXONOMY_DEST = _SCRIPT_DIR / "sigma_taxonomy.json"
SIGMA_TAXONOMY_DEFAULTS_PATH = _SCRIPT_DIR / "sigma_taxonomy_mappings.json"


def _download(url: str, dest: Path, chunk_size: int = 64 * 1024) -> int:
    """Download file từ URL, ghi ra dest. Trả về số bytes đã tải."""
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


def _fetch_mitre_ctid_sensor_mappings() -> dict[str, list[str]]:
    """Tải trực tiếp bảng ánh xạ Sensor EIDs từ repository chính thức của MITRE CTID."""
    sysmon_url = "https://raw.githubusercontent.com/center-for-threat-informed-defense/sensor-mappings-to-attack/main/mappings/input/enterprise/csv/Sysmon-sensors-mappings-enterprise.csv"
    winevtx_url = "https://raw.githubusercontent.com/center-for-threat-informed-defense/sensor-mappings-to-attack/main/mappings/input/enterprise/csv/WinEvtx-sensors-mappings-enterprise.csv"
    auditd_url = "https://raw.githubusercontent.com/center-for-threat-informed-defense/sensor-mappings-to-attack/main/mappings/input/enterprise/csv/Auditd-sensors-mappings-enterprise.csv"

    component_to_eids: dict[str, list[str]] = {}

    for url, label in [(sysmon_url, "Sysmon EID"), (winevtx_url, "Windows Security EID"), (auditd_url, "Auditd")]:
        temp_file = _SCRIPT_DIR / f"_temp_{label.replace(' ', '_')}.csv"
        try:
            _download(url, temp_file)
            with open(temp_file, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    comp = row.get("ATT&CK DATA COMPONENT", "").strip()
                    eid = row.get("EVENT ID", "").strip()
                    if comp and eid:
                        item = f"{label} {eid}"
                        if comp not in component_to_eids:
                            component_to_eids[comp] = []
                        if item not in component_to_eids[comp]:
                            component_to_eids[comp].append(item)
        except Exception as e:
            logger.warning("Không thể tải CTID sensor mapping từ %s: %s", url, e)
        finally:
            if temp_file.exists():
                temp_file.unlink()

    return component_to_eids


def _load_taxonomy_defaults() -> dict[str, Any]:
    """Đọc tệp đặc tả quy chuẩn sigma_taxonomy_mappings.json."""
    with open(SIGMA_TAXONOMY_DEFAULTS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _extract_sigmahq_valid_fields(md_text: str) -> set[str]:
    """Bóc tách danh sách tên Field hợp lệ từ bảng Markdown spec của SigmaHQ."""
    valid_fields: set[str] = set()

    # Tên sản phẩm / vendor cần loại trừ (không phải field name)
    product_names = {
        "apache", "aws", "azure", "bitbucket", "cisco", "django", "gcp",
        "github", "huawei", "juniper", "linux", "macos", "modsecurity",
        "m365", "okta", "onelogin", "windows", "zeek",
    }

    for match in re.finditer(r"^\|\s*([A-Za-z0-9_\-]+)\s*\|", md_text, re.M):
        fname = match.group(1).strip()
        if (
            re.match(r"^(cs-|c-|sc-|[A-Z])[A-Za-z0-9_\-]+$", fname)
            and not fname.startswith("--")
            and fname.lower() not in product_names
            and fname.lower() not in {"product", "company", "field", "fieldname", "description", "example", "category", "service"}
        ):
            valid_fields.add(fname)

    return valid_fields


def _build_sigma_taxonomy(
    defaults: dict[str, Any],
    ctid_eids_map: dict[str, list[str]],
    sigmahq_valid_fields: set[str],
) -> dict[str, dict[str, Any]]:
    """Xây dựng sigma_taxonomy.json từ 3 nguồn: defaults JSON + CTID EIDs + SigmaHQ fields."""
    categories = defaults.get("categories", {})
    logsources: dict[str, dict[str, Any]] = {}

    for cat, spec in categories.items():
        mitre_comp = spec.get("mitre_data_component", "")

        # Event IDs: lấy động từ MITRE CTID sensor mappings
        ctid_eids = ctid_eids_map.get(mitre_comp, [])

        # Fields: cross-validate với SigmaHQ spec
        raw_fields = spec.get("allowed_fields", [])
        validated = []
        warnings = []
        for f in raw_fields:
            if f in sigmahq_valid_fields or f.startswith("cs-") or f.startswith("c-") or f.startswith("sc-"):
                validated.append(f)
            else:
                validated.append(f)
                if sigmahq_valid_fields:
                    warnings.append(f)

        logsources[cat] = {
            "product": spec.get("product", "windows"),
            "category": cat,
            "service": spec.get("service"),
            "mitre_data_component": mitre_comp,
            "native_event_ids": ctid_eids if ctid_eids else [],
            "required_events": spec.get("required_events", []),
            "core_fields": spec.get("core_fields", []),
            "allowed_fields": validated,
            "detection_phase": spec.get("detection_phase", "post_exploit"),
        }

        if warnings:
            logger.debug(
                "Category '%s': %d fields không tìm thấy trong SigmaHQ spec (vẫn giữ): %s",
                cat, len(warnings), warnings[:5],
            )

    return logsources


def fetch_sigma_taxonomy(force: bool = False) -> Path:
    """Hybrid: Đọc defaults JSON + tải Event IDs từ MITRE CTID + cross-validate với SigmaHQ spec."""
    if SIGMA_TAXONOMY_DEST.exists() and not force:
        size_kb = SIGMA_TAXONOMY_DEST.stat().st_size // 1024
        logger.info(
            "sigma_taxonomy.json đã tồn tại (%d KB) - skip. "
            "Dùng force=True để tải lại.",
            size_kb,
        )
        return SIGMA_TAXONOMY_DEST

    logger.info("Hybrid build: sigma_taxonomy_mappings.json + MITRE CTID + SigmaHQ spec ...")

    # 1. Đọc đặc tả cấu hình từ JSON bên ngoài
    defaults = _load_taxonomy_defaults()
    logger.info("Đọc %d categories từ sigma_taxonomy_mappings.json", len(defaults.get("categories", {})))

    # 2. Tải động Event IDs từ MITRE CTID sensor mappings
    ctid_eids_map = _fetch_mitre_ctid_sensor_mappings()
    logger.info("Tải %d Data Component → Event ID mappings từ MITRE CTID", len(ctid_eids_map))

    # 3. Tải & bóc tách danh sách Field hợp lệ từ SigmaHQ Markdown spec
    sigmahq_valid_fields: set[str] = set()
    temp_md_path = _SCRIPT_DIR / "_temp_sigma_taxonomy.md"
    try:
        _download(SIGMA_TAXONOMY_URL, temp_md_path)
        with open(temp_md_path, "r", encoding="utf-8", errors="ignore") as f:
            md_content = f.read()
        sigmahq_valid_fields = _extract_sigmahq_valid_fields(md_content)
        logger.info("Trích xuất %d valid field names từ SigmaHQ spec", len(sigmahq_valid_fields))
    except Exception as e:
        logger.warning("Không thể tải SigmaHQ spec (%s), bỏ qua cross-validation", e)
    finally:
        if temp_md_path.exists():
            temp_md_path.unlink()

    # 4. Build sigma_taxonomy.json
    parsed_logsources = _build_sigma_taxonomy(defaults, ctid_eids_map, sigmahq_valid_fields)
    taxonomy_data = {
        "_version": "1.0",
        "_source": "sigma_taxonomy_mappings.json + MITRE CTID sensor-mappings-to-attack + SigmaHQ spec",
        "_description": "Single Source of Truth cho Sigma Logsources, Allowed Fields & Event IDs.",
        "logsources": parsed_logsources,
    }

    with open(SIGMA_TAXONOMY_DEST, "w", encoding="utf-8") as f:
        json.dump(taxonomy_data, f, indent=2, ensure_ascii=False)

    logger.info("Saved sigma_taxonomy.json thành công: %d categories", len(parsed_logsources))

    return SIGMA_TAXONOMY_DEST


def _validate_sigma_taxonomy_file(path: Path) -> None:
    """Sanity-check sigma_taxonomy.json."""
    logger.info("Validate sigma_taxonomy.json ...")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("sigma_taxonomy.json invalid: %s", exc)
        return
    logsources = data.get("logsources", {})
    logger.info("  Tổng logsource categories: %d", len(logsources))
    for cat, meta in logsources.items():
        logger.info(
            "  - %-20s: %d fields, Event IDs: %s",
            cat,
            len(meta.get("allowed_fields", [])),
            meta.get("native_event_ids", []),
        )


def _validate_ctid(path: Path) -> None:
    """Sanity-check: parse CTID CSV, in CVE count + technique count."""
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


def main() -> int:
    """Entry point - tải CTID CSV & xây dựng Sigma Taxonomy."""
    logger.info("=" * 60)
    logger.info("Fetch Sigma Taxonomy & CTID Ground Truth for Step 4")
    logger.info("=" * 60)
    logger.info("Output dir: %s", _SCRIPT_DIR)

    try:
        ctid_path = fetch_ctid()
        sigma_tax_path = fetch_sigma_taxonomy()
    except Exception as exc:
        logger.error("Fetch thất bại: %s", exc)
        return 1

    logger.info("=" * 60)
    logger.info("Validating files ...")
    logger.info("=" * 60)
    _validate_ctid(ctid_path)
    _validate_sigma_taxonomy_file(sigma_tax_path)

    logger.info("=" * 60)
    logger.info("✅ DONE: Sigma Taxonomy & CTID Mappings updated successfully.")
    logger.info("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
