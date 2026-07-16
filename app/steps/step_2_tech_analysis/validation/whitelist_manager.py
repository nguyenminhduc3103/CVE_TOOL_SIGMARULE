"""Whitelist Manager — Bộ lọc False Positive dựa trên OS whitelist.

Tải danh sách OS-level whitelist (Windows + Linux) từ whitelist.json tĩnh
và cung cấp interface để kiểm tra process/behavior có hợp lệ không.

Mục đích: Nếu AI đưa ra behaviors/processes nằm trong whitelist → đó là
dấu hiệu luật Sigma sẽ gây False Positive khi deploy trên hệ thống thực.

Design:
    - Lazy load: whitelist.json chỉ đọc 1 lần, cache vào module-level var.
    - Platform filter: hỗ trợ "windows", "linux", "any".
    - Case-insensitive matching (normalize về lowercase).
    - Chỉ hỗ trợ Windows + Linux (MVP scope).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Literal

logger = logging.getLogger(__name__)

# Module-level cache — chỉ load JSON 1 lần trong lifetime process
_WHITELIST_CACHE: dict | None = None
_WHITELIST_FILE = Path(__file__).parent / "whitelist.json"

PlatformType = Literal["windows", "linux", "any"]


def _load_whitelist() -> dict:
    """Lazy load whitelist.json. Trả về parsed dict, cache module-level.

    Graceful fallback: nếu file missing/malformed → trả empty dict.
    """
    global _WHITELIST_CACHE
    # Kiểm tra xem dữ liệu đã được tải lên RAM chưa. Nếu có rồi thì tái sử dụng ngay để tối ưu hiệu năng
    if _WHITELIST_CACHE is not None:
        return _WHITELIST_CACHE

    try:
        # Mở file whitelist.json chứa danh sách tiến trình/hành vi hệ thống mặc định
        with open(_WHITELIST_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        # Xây dựng các tập hợp (frozenset) từ dữ liệu đọc được.
        # Frozenset giúp tra cứu O(1) và không bị sửa đổi vô ý. Ép tất cả về chữ thường (lower) để case-insensitive.
        _WHITELIST_CACHE = {
            "windows": frozenset(e.lower() for e in (data.get("windows") or [])),
            "linux": frozenset(e.lower() for e in (data.get("linux") or [])),
            "behaviors": frozenset(e.lower() for e in (data.get("behaviors") or [])),
        }
        
        # Ghi log số lượng phần tử đã load được từ file
        logger.debug(
            "[whitelist_manager] Loaded whitelist: windows=%d linux=%d behaviors=%d",
            len(_WHITELIST_CACHE["windows"]),
            len(_WHITELIST_CACHE["linux"]),
            len(_WHITELIST_CACHE["behaviors"]),
        )
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        # Nếu đọc file lỗi (thiếu file, sai format), log lại cảnh báo nhưng KHÔNG CÓ crash chương trình.
        logger.warning(
            "[whitelist_manager] Failed to load whitelist.json: %s — FP filter disabled",
            exc,
        )
        # Khởi tạo cache rỗng để thuật toán validation vẫn có thể tiếp tục chạy (bypass filter)
        _WHITELIST_CACHE = {"windows": frozenset(), "linux": frozenset(), "behaviors": frozenset()}

    return _WHITELIST_CACHE


def is_whitelisted(name: str, platform: PlatformType = "any") -> bool:
    """Kiểm tra process/behavior có trong OS whitelist không.

    Args:
        name:     Tên process hoặc behavior string (vd "svchost.exe", "bash").
        platform: "windows" | "linux" | "any".
                  "any" → kiểm tra cả Windows + Linux + behaviors lists.

    Returns:
        True nếu là process/behavior hệ thống hợp lệ (FP candidate).
        False nếu không có trong whitelist (cần điều tra thêm).
    """
    # Nếu giá trị truyền vào trống hoặc không phải chuỗi thì lập tức bỏ qua
    if not name or not isinstance(name, str):
        return False

    # Gọi hàm load dữ liệu (lấy từ cache nếu có)
    wl = _load_whitelist()
    
    # Xoá khoảng trắng và ép về chữ thường để khớp với định dạng trong whitelist
    normalized = name.strip().lower()

    # Kiểm tra theo từng loại platform
    if platform == "windows":
        return normalized in wl["windows"]
    if platform == "linux":
        return normalized in wl["linux"]
        
    # Trường hợp "any": check xem cái tên này có nằm ở bất kỳ danh sách nào (windows, linux, hay behaviors chung)
    return (
        normalized in wl["windows"]
        or normalized in wl["linux"]
        or normalized in wl["behaviors"]
    )


def scan_behaviors_for_fp(
    behaviors: list[str],
    platform: PlatformType = "any",
) -> list[str]:
    """Quét list behaviors/processes → trả list nào nằm trong whitelist.

    Dùng để tính `whitelist_hits` trong ValidationResult. Caller dùng
    kết quả này để đánh giá FP risk của luật Sigma AI sinh ra.

    Args:
        behaviors: List behaviors/processes AI sinh ra từ mandatory_behaviors.
        platform:  "windows" | "linux" | "any".

    Returns:
        List các item từ `behaviors` nằm trong OS whitelist (FP candidates).
        Trả [] nếu không có item nào nằm trong whitelist.
    """
    # Nếu danh sách behaviors trống thì trả về mảng rỗng
    if not behaviors:
        return []
        
    # Dùng List Comprehension để lặp qua tất cả behaviors, 
    # lọc giữ lại các hành vi `b` nào là thuộc Whitelist của hệ thống -> Tức là những dấu hiệu cảnh báo False Positive
    return [b for b in behaviors if is_whitelisted(b, platform)]


def reset_cache() -> None:
    """Reset module-level cache (chỉ dùng cho unit test)."""
    global _WHITELIST_CACHE
    _WHITELIST_CACHE = None
