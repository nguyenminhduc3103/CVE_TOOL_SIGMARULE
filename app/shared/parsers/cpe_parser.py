from typing import Any

def parse_cpe(cpe_str: str) -> dict[str, Any] | None:
    """Phân tích chuỗi CPE (Common Platform Enumeration) phiên bản 2.2 hoặc 2.3 thành các trường có cấu trúc.

    Định dạng CPE 2.3:
    cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other

    Định dạng CPE 2.2:
    cpe:/part:vendor:product:version:update:edition:language
    """
    if not cpe_str:
        return None

    cpe_str = cpe_str.strip()

    # Xử lý CPE 2.3
    if cpe_str.startswith("cpe:2.3:"):
        parts = cpe_str.split(":")
        # Bổ sung các trường còn thiếu để đủ 13 trường theo đặc tả
        while len(parts) < 13:
            parts.append("*")

        part = parts[2]
        vendor = parts[3]
        product = parts[4]
        version = parts[5]
        update = parts[6]
        edition = parts[7]
        language = parts[8]
        sw_edition = parts[9]
        target_sw = parts[10]
        target_hw = parts[11]
        other = parts[12]

        # Thay thế ký tự escape trong các trường
        vendor = vendor.replace("\\:", ":")
        product = product.replace("\\:", ":")
        version = version.replace("\\:", ":")

        part_labels = {
            "o": "Operating System",
            "a": "Application",
            "h": "Hardware"
        }

        return {
            "cpe_version": "2.3",
            "part": part,
            "part_label": part_labels.get(part, "Unknown"),
            "vendor": vendor,
            "product": product,
            "version": version,
            "update": update,
            "edition": edition,
            "language": language,
            "sw_edition": sw_edition,
            "target_sw": target_sw,
            "target_hw": target_hw,
            "other": other,
        }

    # Xử lý CPE 2.2
    elif cpe_str.startswith("cpe:/"):
        cpe_data = cpe_str[5:]
        parts = cpe_data.split(":")
        while len(parts) < 7:
            parts.append("*")

        part = parts[0]
        vendor = parts[1]
        product = parts[2]
        version = parts[3]
        update = parts[4]
        edition = parts[5]
        language = parts[6]

        part_labels = {
            "o": "Operating System",
            "a": "Application",
            "h": "Hardware"
        }

        return {
            "cpe_version": "2.2",
            "part": part,
            "part_label": part_labels.get(part, "Unknown"),
            "vendor": vendor,
            "product": product,
            "version": version,
            "update": update,
            "edition": edition,
            "language": language,
            "sw_edition": "*",
            "target_sw": "*",
            "target_hw": "*",
            "other": "*",
        }

    return None


def parse_cpe_list(raw_cpes: list) -> list[dict[str, Any]]:
    """Phân tích danh sách chuỗi CPE thô thành danh sách đối tượng chi tiết có cấu trúc."""
    if not raw_cpes:
        return []
    results = []
    for cpe in raw_cpes:
        parsed = parse_cpe(str(cpe))
        if parsed:
            results.append(parsed)
    return results
