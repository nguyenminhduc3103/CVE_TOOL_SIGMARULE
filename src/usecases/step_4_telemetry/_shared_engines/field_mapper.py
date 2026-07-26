from __future__ import annotations

import json
from pathlib import Path

# Thư mục chứa local truth data (src/infrastructure/local_truth/sigma_taxonomy.json)
_LOCAL_TRUTH_DIR = Path(__file__).resolve().parents[3] / "infrastructure" / "local_truth"
_TAXONOMY_FILE = _LOCAL_TRUTH_DIR / "sigma_taxonomy.json"
_DEFAULTS_FILE = _LOCAL_TRUTH_DIR / "sigma_taxonomy_mappings.json"


def _load_logsource_fields() -> tuple[dict[str, tuple[str, ...]], dict[str, tuple[str, ...]]]:
    """Đọc dữ liệu core_fields và allowed_fields trực tiếp từ sigma_taxonomy.json hoặc defaults."""
    core_map: dict[str, tuple[str, ...]] = {}
    allowed_map: dict[str, tuple[str, ...]] = {}

    target_file = _TAXONOMY_FILE if _TAXONOMY_FILE.exists() else _DEFAULTS_FILE
    if not target_file.exists():
        return core_map, allowed_map

    try:
        with open(target_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        logsources = data.get("categories" if "categories" in data else "logsources", {})
        for cat, meta in logsources.items():
            core = meta.get("core_fields", [])
            allowed = meta.get("allowed_fields", [])
            if core:
                core_map[cat] = tuple(core)
            if allowed:
                allowed_map[cat] = tuple(allowed)
        return core_map, allowed_map
    except (OSError, json.JSONDecodeError):
        return core_map, allowed_map


def _load_os_specific_fields() -> dict[str, set[str]]:
    """Nạp bảng field đặc thù theo OS từ JSON."""
    try:
        with open(_DEFAULTS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        raw = data.get("os_specific_fields", {})
        return {k: set(v) for k, v in raw.items() if not k.startswith("_") and isinstance(v, list)}
    except (OSError, json.JSONDecodeError):
        return {}


# Single Source of Truth cho Logsource Fields
LOGSOURCE_CORE_FIELDS, LOGSOURCE_FIELDS = _load_logsource_fields()
OS_SPECIFIC_FIELDS = _load_os_specific_fields()


def map_required_fields(
    logsources: list[str],
    use_core_only: bool = True,
) -> list[str]:
    """Trả về danh sách fields cần thiết dựa trên các logsource categories hợp lệ.
    
    Khi `use_core_only=True` (mặc định): Ưu tiên lấy core_fields của từng category
    để lọc trường ngắn gọn, chính xác cho Step 6, tránh bị loãng bởi optional fields.
    """
    target_map = LOGSOURCE_CORE_FIELDS if use_core_only else LOGSOURCE_FIELDS
    fields: list[str] = []

    for logsource in logsources:
        # Fallback về LOGSOURCE_FIELDS nếu category không có core_fields
        cat_fields = target_map.get(logsource) or LOGSOURCE_FIELDS.get(logsource, ())
        fields.extend(cat_fields)

    # Deduplicate giữ thứ tự
    unique_fields: list[str] = []
    seen: set[str] = set()
    for field in fields:
        if field not in seen:
            seen.add(field)
            unique_fields.append(field)
    return unique_fields
