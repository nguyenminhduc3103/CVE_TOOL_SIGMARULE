from __future__ import annotations

from src.usecases.step_4_telemetry._shared_engines.field_mapper import LOGSOURCE_FIELDS, OS_SPECIFIC_FIELDS


def validate_fields_by_logsources(
    logsources: list[str], 
    fields: list[str],
    target_products: set[str] | None = None
) -> tuple[list[str], list[str], list[str]]:
    """
    Kiểm tra tính hợp lệ của các trường dữ liệu (fields) theo danh sách logsource và hệ điều hành mục tiêu.
    Loại bỏ các trường không thuộc taxonomy hoặc trường đặc thù OS không khớp với target_products.
    Trả về: (validated_fields, invalid_fields, warnings)
    """
    allowed: set[str] = set()
    for logsource in logsources:
        allowed.update(LOGSOURCE_FIELDS.get(logsource, ()))

    validated_fields: list[str] = []
    invalid_fields: list[str] = []
    warnings: list[str] = []

    for field in fields:
        if field in allowed:
            # Kiểm tra trường đặc thù OS (ví dụ: cấm dùng field Linux trên rule Windows)
            if target_products:
                is_blocked = False
                for os_name, os_fields in OS_SPECIFIC_FIELDS.items():
                    if field in os_fields and os_name not in target_products:
                        if field not in invalid_fields:
                            invalid_fields.append(field)
                        warnings.append(f"os_field_mismatch:{field} ({os_name}-only, but target is {list(target_products)})")
                        is_blocked = True
                        break
                if is_blocked:
                    continue

            if field not in validated_fields:
                validated_fields.append(field)
            continue

        if field not in invalid_fields:
            invalid_fields.append(field)
        warnings.append(f"invalid_field_removed:{field}")

    return validated_fields, invalid_fields, warnings


def validate_logsources_by_cpe(
    logsources: list, cpes: list[str] | None
) -> tuple[list, list, list[str]]:
    """
    Lọc bỏ các logsource không tương thích với hệ điều hành xác định từ danh sách CPE (Windows vs Linux).
    Trả về: (valid_logsources, invalid_logsources, warnings)
    """
    if not cpes:
        return logsources, [], []

    # Xác định OS từ chuỗi CPE
    cpe_str = " ".join(cpes).lower()
    is_windows = "windows" in cpe_str
    is_linux = "linux" in cpe_str

    valid_logsources = []
    invalid_logsources = []
    warnings = []

    for ls in logsources:
        # Nếu logsource không phụ thuộc OS cụ thể thì luôn giữ lại
        if not ls.product or ls.product not in ["windows", "linux", "macos"]:
            valid_logsources.append(ls)
            continue

        # Kiểm tra xung đột nền tảng OS
        if ls.product == "windows" and is_linux and not is_windows:
            invalid_logsources.append(ls)
            warnings.append(
                f"logsource_cpe_mismatch: dropped '{ls.category}' (product '{ls.product}') because CVE CPE indicates Linux."
            )
        elif ls.product == "linux" and is_windows and not is_linux:
            invalid_logsources.append(ls)
            warnings.append(
                f"logsource_cpe_mismatch: dropped '{ls.category}' (product '{ls.product}') because CVE CPE indicates Windows."
            )
        else:
            valid_logsources.append(ls)

    return valid_logsources, invalid_logsources, warnings


def validate_logsources_by_cvss(
    logsources: list, cvss_vector: str | None
) -> tuple[list, list, list[str]]:
    """
    Lọc bỏ các logsource mạng (network_connection, webserver...) nếu lỗ hổng chỉ khai thác cục bộ (AV:L / AV:P).
    Cảnh báo nếu lỗ hổng khai thác từ xa (AV:N / AV:A) nhưng thiếu logsource theo dõi mạng.
    Cảnh báo điểm mù nếu lỗ hổng cần tương tác người dùng (UI:R) hoặc phá hoại tính toàn vẹn cao (I:H) nhưng thiếu logsource tương ứng.
    Trả về: (valid_logsources, invalid_logsources, warnings)
    """
    if not cvss_vector:
        return logsources, [], []

    valid_ls = []
    invalid_ls = []
    warnings = []

    NETWORK_LOGSOURCES = {"network_connection", "webserver", "dns_query"}

    from src.shared.parsers.cvss_parser import is_local_only, is_network_reachable, parse_cvss_vector

    is_local = is_local_only(cvss_vector)  # AV:L or theoretically AV:P
    if "/AV:P" in cvss_vector:
        is_local = True

    is_network = is_network_reachable(cvss_vector) or "/AV:A" in cvss_vector  # AV:N or AV:A

    has_network_log = False

    for ls in logsources:
        is_net_ls = ls.category in NETWORK_LOGSOURCES
        if is_net_ls:
            has_network_log = True

        if is_local and is_net_ls:
            # Lỗ hổng Local nhưng dùng log Network -> Drop!
            invalid_ls.append(ls)
            warnings.append(
                f"cvss_av_mismatch: dropped '{ls.category}' because CVSS Attack Vector is Local/Physical, "
                "which does not involve network delivery/exploitation."
            )
            continue

        valid_ls.append(ls)

    if is_network and not has_network_log:
        warnings.append(
            "cvss_av_missing_network: CVSS indicates Network/Adjacent attack vector, "
            "but no network logsources were selected. Detection may miss the initial delivery phase."
        )

    # Smart CVSS Warnings (UI & Integrity monitoring gaps)
    cvss_metrics = parse_cvss_vector(cvss_vector)
    valid_categories = {ls.category for ls in valid_ls}

    CLIENT_LOGSOURCES = {"process_creation", "file_event", "image_load"}
    if cvss_metrics.get("UI") == "R" and not valid_categories.intersection(CLIENT_LOGSOURCES):
        warnings.append(
            "cvss_ui_missing_client_logs: CVSS indicates User Interaction Required (UI:R), "
            "but no client-side execution or file monitoring logsources were selected. Detection may miss phishing or client-side payload execution."
        )

    INTEGRITY_LOGSOURCES = {"file_event", "file_change", "file_delete", "registry_event", "process_creation"}
    integrity = cvss_metrics.get("I") or cvss_metrics.get("VI")
    if integrity == "H" and not valid_categories.intersection(INTEGRITY_LOGSOURCES):
        warnings.append(
            "cvss_integrity_missing_monitoring: CVSS indicates High Integrity Impact (I:H), "
            "but no system state change logsources (file/registry/process) were selected."
        )

    return valid_ls, invalid_ls, warnings
