"""Shared CVSS vector parser.

Consolidated CVSS parsing helpers - dùng chung cho Step 1 (exploit classifier),
Step 2 (exploit ontology, ontology_manager/CveContext), và bất kỳ module nào
cần inspect CVSS metrics.

CVSS vector format (CVSS:3.0/3.1):
    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    ^^^^^^^^ ^^^ ^^ ^^ ^^ ^^ ^^ ^^ ^^ ^^
    prefix   metric key:value pairs separated by '/'

Returns:
    parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        -> {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
            "S": "U", "C": "H", "I": "H", "A": "H"}

Giữ behavior identical với `_parse_cvss_vector` cũ trong
`exploit_classifier.py` / `exploit_ontology.py`: split trên "/", lấy cặp
key:value đầu tiên, upper-case cả key & value.
"""
from __future__ import annotations


def parse_cvss_vector(cvss_string: str | None) -> dict[str, str]:
    """Parse CVSS vector string thành dict[metric_key, metric_value].

    Args:
        cvss_string: CVSS vector dạng "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/..."
                     (hoặc None/empty).

    Returns:
        Dict upper-case metric -> upper-case value. Empty dict nếu input
        falsy hoặc không parse được segment nào.
    """
    if not cvss_string:
        return {}

    metrics: dict[str, str] = {}
    for segment in cvss_string.split("/"):
        if ":" not in segment:
            continue
        key, value = segment.split(":", 1)
        metrics[key.strip().upper()] = value.strip().upper()
    return metrics


def get_cvss_metric(cvss_dict: dict[str, str], key: str) -> str | None:
    """Lookup 1 metric từ dict đã parse (case-insensitive key).

    Args:
        cvss_dict: Output của `parse_cvss_vector`.
        key: Metric key (vd "AV", "PR"). Case-insensitive.

    Returns:
        Upper-case value hoặc None nếu không có.
    """
    if not cvss_dict or not key:
        return None
    return cvss_dict.get(key.strip().upper())


def is_network_reachable(cvss_string: str | None) -> bool:
    """True nếu CVSS Attack Vector = Network (AV:N).

    Behavior identical với `CveContext.is_network_reachable()` cũ:
    match `/AV:N` substring (regex `r"/AV:N"`).
    """
    return bool(cvss_string and "/AV:N" in cvss_string)


def is_pre_auth(cvss_string: str | None) -> bool:
    """True nếu CVSS Privileges Required = None (PR:N).

    Behavior identical với `CveContext.is_pre_auth()` cũ:
    match `/PR:N` substring (regex `r"/PR:N"`).
    """
    return bool(cvss_string and "/PR:N" in cvss_string)


def is_local_only(cvss_string: str | None) -> bool:
    """True nếu CVSS Attack Vector = Local (AV:L).

    Behavior identical với `CveContext.is_local_only()` cũ:
    match `/AV:L` substring (regex `r"/AV:L"`).
    """
    return bool(cvss_string and "/AV:L" in cvss_string)