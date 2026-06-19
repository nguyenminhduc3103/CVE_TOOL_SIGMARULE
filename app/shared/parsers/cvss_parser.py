def parse_cvss(vector: str | None) -> dict:
    """Phân tích cú pháp chuỗi CVSS Vector (v2, v3.x, v4.0) thành cấu trúc JSON rõ ràng.

    Hỗ trợ ánh xạ các trường viết tắt (như AV, AC, PR, UI, C, I, A) thành tên tiếng Việt và Anh đầy đủ.
    """
    if not vector:
        return {"version": "Unknown", "raw_vector": ""}

    vector = vector.strip().strip("()")

    # Xác định phiên bản CVSS
    version = "3.x"
    if vector.startswith("CVSS:4.0/"):
        version = "4.0"
    elif vector.startswith("CVSS:3.1/"):
        version = "3.1"
    elif vector.startswith("CVSS:3.0/"):
        version = "3.0"
    elif vector.startswith("CVSS:2.0/") or "Au:" in vector or (not vector.startswith("CVSS:") and "AV:" in vector):
        version = "2.0"

    # Chuẩn hóa chuỗi vector thành dạng danh sách các cặp key-value
    clean_vector = vector
    for prefix in ["CVSS:4.0/", "CVSS:3.1/", "CVSS:3.0/", "CVSS:2.0/"]:
        if clean_vector.startswith(prefix):
            clean_vector = clean_vector[len(prefix):]
            break

    parts = clean_vector.split("/")
    metrics = {}
    for part in parts:
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k.strip()] = v.strip()

    # Các từ điển ánh xạ chi tiết
    av_map = {
        "N": "Network (Mạng)",
        "A": "Adjacent (Mạng lân cận)",
        "L": "Local (Nội bộ/Cục bộ)",
        "P": "Physical (Vật lý)"
    }

    ac_map = {
        "L": "Low (Thấp)",
        "M": "Medium (Trung bình)",  # v2
        "H": "High (Cao)"
    }

    pr_map = {
        "N": "None (Không)",
        "L": "Low (Thấp)",
        "H": "High (Cao)"
    }

    ui_map = {
        "N": "None (Không cần tương tác)",
        "R": "Required (Yêu cầu tương tác)"
    }

    s_map = {
        "U": "Unchanged (Không thay đổi)",
        "C": "Changed (Đã thay đổi)"
    }

    # Mức độ ảnh hưởng (Confidentiality, Integrity, Availability)
    impact_map = {
        "N": "None (Không ảnh hưởng)",
        "L": "Low (Ảnh hưởng thấp)",
        "P": "Partial (Ảnh hưởng một phần)",   # v2
        "C": "Complete (Ảnh hưởng hoàn toàn)",  # v2
        "H": "High (Ảnh hưởng cao)"
    }

    # Phân tích Vector
    attack_vector = av_map.get(metrics.get("AV", ""), "Unknown")
    attack_complexity = ac_map.get(metrics.get("AC", ""), "Unknown")

    # Quyền hạn yêu cầu (PR hoặc Au)
    privileges_required = "Unknown"
    if "PR" in metrics:
        privileges_required = pr_map.get(metrics.get("PR"), "Unknown")
    elif "Au" in metrics:  # v2 Authentication
        au_map = {
            "N": "None (Không cần xác thực)",
            "S": "Single (Xác thực 1 lần)",
            "M": "Multiple (Xác thực nhiều lần)"
        }
        privileges_required = au_map.get(metrics.get("Au"), "Unknown")

    # Tương tác người dùng (UI)
    user_interaction = "Unknown"
    if "UI" in metrics:
        user_interaction = ui_map.get(metrics.get("UI"), "Unknown")
    elif version == "2.0":
        user_interaction = "None (Không yêu cầu tương tác)"

    scope = s_map.get(metrics.get("S", ""), "Not Applicable")

    # Mức độ ảnh hưởng bảo mật (v2, v3, v4)
    c_val = metrics.get("C") or metrics.get("VC")  # VC trong v4
    i_val = metrics.get("I") or metrics.get("VI")  # VI trong v4
    a_val = metrics.get("A") or metrics.get("VA")  # VA trong v4

    confidentiality = impact_map.get(c_val, "Unknown") if c_val else "Unknown"
    integrity = impact_map.get(i_val, "Unknown") if i_val else "Unknown"
    availability = impact_map.get(a_val, "Unknown") if a_val else "Unknown"

    return {
        "version": version,
        "raw_vector": vector,
        "attack_vector": attack_vector,
        "attack_complexity": attack_complexity,
        "privileges_required": privileges_required,
        "user_interaction": user_interaction,
        "scope": scope,
        "confidentiality_impact": confidentiality,
        "integrity_impact": integrity,
        "availability_impact": availability
    }
