from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from src.domain.models.telemetry import SigmaLogsource

# Thư mục chứa local truth data (src/infrastructure/local_truth/)
_LOCAL_TRUTH_DIR = Path(__file__).resolve().parents[3] / "infrastructure" / "local_truth"
_TAXONOMY_FILE = _LOCAL_TRUTH_DIR / "sigma_taxonomy.json"
_DEFAULTS_FILE = _LOCAL_TRUTH_DIR / "sigma_taxonomy_mappings.json"


def _load_taxonomy_logsources() -> dict[str, dict[str, Any]]:
    """Tải trực tiếp định nghĩa Logsource từ sigma_taxonomy.json làm Single Source of Truth."""
    if not _TAXONOMY_FILE.exists():
        return {}
    try:
        with open(_TAXONOMY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("logsources", {})
    except (OSError, json.JSONDecodeError):
        return {}


def _load_defaults() -> dict[str, Any]:
    """Tải cấu hình mapping từ sigma_taxonomy_mappings.json."""
    if not _DEFAULTS_FILE.exists():
        return {}
    try:
        with open(_DEFAULTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


# Single Source of Truth cho Taxonomy Logsources (nạp từ JSON)
TAXONOMY_LOGSOURCES: dict[str, dict[str, Any]] = _load_taxonomy_logsources()

# Nạp toàn bộ mappings từ sigma_taxonomy_mappings.json — không hardcode trong Python
_DEFAULTS = _load_defaults()

# Ánh xạ Behavior (từ Step 2) → Taxonomy Category Key
BEHAVIOR_TO_CATEGORY: dict[str, str] = {
    k: v for k, v in _DEFAULTS.get("behavior_to_category", {}).items()
    if not k.startswith("_")
}

# Ánh xạ MITRE ATT&CK Technique → Taxonomy Category Key
TECHNIQUE_TO_CATEGORY: dict[str, str] = {
    k: v for k, v in _DEFAULTS.get("technique_to_category", {}).items()
    if not k.startswith("_")
}


def _get_logsource_tuple(category_key: str) -> tuple[list[SigmaLogsource], tuple[str, ...], tuple[str, ...], tuple[str, ...]] | None:
    """Rút trích list SigmaLogsource (theo mảng product), required_events, native_event_ids, allowed_fields từ taxonomy JSON."""
    meta = TAXONOMY_LOGSOURCES.get(category_key)
    if not meta:
        return None

    products = meta.get("product", ["windows"])
    if isinstance(products, str):
        products = [products]

    ls_list = []
    for prod in products:
        ls_list.append(SigmaLogsource(
            category=meta.get("category", category_key),
            product=prod,
            service=meta.get("service"),
        ))

    req_events = tuple(meta.get("required_events", []))
    native_eids = tuple(meta.get("native_event_ids", []))
    allowed_fields = tuple(meta.get("allowed_fields", []))
    return ls_list, req_events, native_eids, allowed_fields


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _resolve_technique(technique_id: str) -> str | None:
    """Resolve technique ID: ưu tiên sub-technique chính xác, fallback lên parent."""
    if technique_id in TECHNIQUE_TO_CATEGORY:
        return TECHNIQUE_TO_CATEGORY[technique_id]
    # Fallback: thử parent technique (VD: T1059.008 → T1059)
    parent = technique_id.rsplit(".", 1)[0] if "." in technique_id else None
    if parent and parent in TECHNIQUE_TO_CATEGORY:
        return TECHNIQUE_TO_CATEGORY[parent]
    return None


def map_logsources(
    mandatory_behaviors: list[str] | None = None,
    techniques: list[str] | None = None,
    categories: list[str] | None = None,
) -> tuple[list[SigmaLogsource], list[str], list[str]]:
    """Ánh xạ behaviors, techniques và categories sang danh sách SigmaLogsource hợp lệ, required_events và native_event_ids."""
    logsources: list[SigmaLogsource] = []
    events: list[str] = []
    event_ids: list[str] = []

    cat_keys: list[str] = list(categories or [])
    for behavior in mandatory_behaviors or []:
        cat = BEHAVIOR_TO_CATEGORY.get(behavior)
        if cat and cat not in cat_keys:
            cat_keys.append(cat)

    for technique in techniques or []:
        cat = _resolve_technique(technique)
        if cat and cat not in cat_keys:
            cat_keys.append(cat)

    for cat_key in cat_keys:
        mapped = _get_logsource_tuple(cat_key)
        if not mapped:
            continue
        ls_list, required_events, required_event_ids, _ = mapped
        logsources.extend(ls_list)
        events.extend(required_events)
        event_ids.extend(required_event_ids)

    unique_logsources: list[SigmaLogsource] = []
    seen = set()
    for logsource in logsources:
        key = (logsource.category, logsource.product, logsource.service)
        if key in seen:
            continue
        seen.add(key)
        unique_logsources.append(logsource)

    return unique_logsources, _unique(events), _unique(event_ids)


def extract_events_from_logsources(
    logsources: list[SigmaLogsource],
) -> tuple[list[str], list[str]]:
    """Trích xuất required_events và native_event_ids chỉ từ các logsource đã vượt qua bộ lọc."""
    events: list[str] = []
    event_ids: list[str] = []
    seen_cats: set[str] = set()

    for ls in logsources:
        if ls.category in seen_cats:
            continue
        seen_cats.add(ls.category)
        mapped = _get_logsource_tuple(ls.category)
        if mapped:
            _, req_evs, native_eids, _ = mapped
            events.extend(req_evs)
            event_ids.extend(native_eids)

    return _unique(events), _unique(event_ids)
