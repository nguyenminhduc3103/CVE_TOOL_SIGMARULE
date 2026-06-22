"""MITRE ATT&CK Validator - Safety Net cho Step 2.

Validate TTP IDs (Tactics & Techniques) do AI hoặc rule-based sinh ra theo
danh sách chuẩn MITRE ATT&CK Enterprise.

Sau refactor Phase 2: whitelist không còn hardcode tĩnh (50% matrix) mà
đọc từ MITRE STIX qua `MitreAttackWhitelist.get()` (~95%+ matrix, auto-update
7 ngày). Hardcode chỉ còn làm baseline fallback khi STIX load fail (network
down, env CVE_TI_MITRE_OFFLINE=1, file corrupt).

Ràng buộc theo tài liệu (dòng 24): "Mã TTP do AI sinh ra phải được đối chiếu
và xác thực với danh sách chuẩn của MITRE. Mã không hợp lệ sẽ bị loại bỏ."
"""
from __future__ import annotations

import re

# Regex format: T1059, T1059.001, TA0001
_TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")
_TACTIC_PATTERN = re.compile(r"^TA\d{4}$")


def _get_whitelist():
    """Lazy import + accessor. Tránh forcing 30MB STIX parse chỉ vì import
    module này cho 1 helper function.
    """
    from app.shared.mitre.loader import MitreAttackWhitelist
    return MitreAttackWhitelist.get()


# Dynamic accessors (replacement cho hardcoded VALID_* frozensets).
# Backward-compat: caller cũ `value in VALID_TECHNIQUES` vẫn work vì frozenset
# supports `in`. Caller mới nên dùng `_get_whitelist().is_known(value)`.


def __getattr__(name: str):
    """Module-level __getattr__ cho backward-compat lazy access.

    Cho phép `from attack_validator import VALID_TECHNIQUES` giữ working —
    mỗi access đi qua live MitreAttackWhitelist singleton.
    """
    if name in ("VALID_TACTICS", "VALID_TECHNIQUES", "VALID_SUBTECHNIQUES"):
        wl = _get_whitelist()
        if name == "VALID_TACTICS":
            return wl.tactics
        if name == "VALID_TECHNIQUES":
            # legacy: caller expects ALL technique IDs (parent + sub)
            return wl.all_techniques
        if name == "VALID_SUBTECHNIQUES":
            return wl.subtechniques
    raise AttributeError(f"module 'attack_validator' has no attribute {name!r}")


def _normalize_id(value: object) -> str | None:
    """Chuẩn hóa ID về dạng 'T1059' hoặc 'TA0001' (uppercase, strip whitespace)."""
    if not isinstance(value, str):
        return None
    text = value.strip().upper()
    if not text:
        return None
    # Map từ format dài 'attack.t1059' về ngắn 'T1059'.
    if text.startswith("ATTACK."):
        text = text[len("ATTACK."):]
    return text


def is_known_ttp(value: str) -> str | None:
    """Phân loại một TTP ID (đã normalize) theo dynamic STIX whitelist.

    Returns:
        - "tactic" : ID khớp _TACTIC_PATTERN và có trong whitelist.
        - "parent" : base technique (T1059) có trong whitelist.
        - "sub"    : subtechnique (T1059.001) có trong whitelist HOẶC có parent
                     technique hợp lệ (parent-child fallback).
        - None     : ID không hợp lệ về format hoặc không có trong whitelist.

    Lưu ý: "sub" trả về ngay cả khi match qua parent-child fallback vì
    validate_technique() vẫn pass.
    """
    if not value:
        return None
    wl = _get_whitelist()
    if _TACTIC_PATTERN.match(value) and value in wl.tactics:
        return "tactic"
    if not _TECHNIQUE_PATTERN.match(value):
        return None
    if "." in value:
        # Subtechnique - ưu tiên whitelist.
        if value in wl.subtechniques:
            return "sub"
        # Fallback: parent technique hợp lệ → coi như sub-technique hợp lý.
        # STIX dynamic whitelist (~475 subtechniques) cover gần hết phổ biến,
        # fallback chỉ trigger khi AI propose subtechnique cực mới.
        parent = value.split(".", 1)[0]
        if parent in wl.techniques:
            return "sub"
        return None
    if value in wl.techniques:
        return "parent"
    return None


def validate_tactic(value: object) -> bool:
    """Kiểm tra 1 tactic ID có hợp lệ không."""
    normalized = _normalize_id(value)
    if normalized is None:
        return False
    return is_known_ttp(normalized) == "tactic"


def validate_technique(value: object) -> bool:
    """Kiểm tra 1 technique ID có hợp lệ không.

    Quy tắc:
    - Technique (T1059): phải có trong whitelist (STIX dynamic).
    - Subtechnique (T1059.001): ưu tiên check whitelist. Nếu không có,
      fallback: chấp nhận nếu parent technique hợp lệ (vd AI trả T1021.003
      dù chưa list trong whitelist nhưng T1021 hợp lệ → pass). Vẫn reject
      T9999.001 (parent invalid).
    """
    normalized = _normalize_id(value)
    if normalized is None:
        return False
    return is_known_ttp(normalized) in ("parent", "sub")


def validate_ttp_list(
    tactics: list[str] | None,
    techniques: list[str] | None,
    subtechniques: list[str] | None = None,
) -> dict[str, object]:
    """Validate một list TTP, trả về kết quả tách valid/invalid.

    Returns:
        {
            "valid_tactics": [...], "valid_techniques": [...], "valid_subtechniques": [...],
            "invalid_tactics": [...], "invalid_techniques": [...], "invalid_subtechniques": [...],
            "warnings": ["invalid_technique_dropped:T9999", ...],
            "passed": bool (True nếu không có invalid nào),
        }
    """
    valid_tactics: list[str] = []
    invalid_tactics: list[str] = []
    valid_techniques: list[str] = []
    invalid_techniques: list[str] = []
    valid_subtechniques: list[str] = []
    valid_subtechniques_seen: set[str] = set()
    invalid_subtechniques: list[str] = []
    warnings: list[str] = []

    for raw in tactics or []:
        normalized = _normalize_id(raw)
        if normalized and validate_tactic(normalized):
            if normalized not in valid_tactics:
                valid_tactics.append(normalized)
        else:
            invalid_tactics.append(raw if isinstance(raw, str) else str(raw))
            warnings.append(f"invalid_tactic_dropped:{raw}")

    for raw in techniques or []:
        normalized = _normalize_id(raw)
        if normalized and validate_technique(normalized):
            if "." in normalized:
                # Subtechnique.
                if normalized not in valid_subtechniques_seen:
                    valid_subtechniques_seen.add(normalized)
                    valid_subtechniques.append(normalized)
                # Đồng thời thêm base vào techniques nếu chưa có.
                base = normalized.split(".", 1)[0]
                if base not in valid_techniques:
                    valid_techniques.append(base)
            else:
                if normalized not in valid_techniques:
                    valid_techniques.append(normalized)
        else:
            invalid_techniques.append(raw if isinstance(raw, str) else str(raw))
            warnings.append(f"invalid_technique_dropped:{raw}")

    for raw in subtechniques or []:
        normalized = _normalize_id(raw)
        if normalized and validate_technique(normalized):
            if normalized not in valid_subtechniques_seen:
                valid_subtechniques_seen.add(normalized)
                valid_subtechniques.append(normalized)
        else:
            invalid_subtechniques.append(raw if isinstance(raw, str) else str(raw))
            warnings.append(f"invalid_subtechnique_dropped:{raw}")

    return {
        "valid_tactics": valid_tactics,
        "valid_techniques": valid_techniques,
        "valid_subtechniques": valid_subtechniques,
        "invalid_tactics": invalid_tactics,
        "invalid_techniques": invalid_techniques,
        "invalid_subtechniques": invalid_subtechniques,
        "warnings": warnings,
        "passed": not (invalid_tactics or invalid_techniques or invalid_subtechniques),
    }


def filter_attack_mapping(
    tactics: list[str] | None,
    techniques: list[str] | None,
    subtechniques: list[str] | None = None,
) -> dict[str, list[str] | None]:
    """Helper: validate + filter, chỉ trả về clean list (None nếu rỗng)."""
    result = validate_ttp_list(tactics, techniques, subtechniques)
    return {
        "tactics": result["valid_tactics"] or None,
        "techniques": result["valid_techniques"] or None,
        "subtechniques": result["valid_subtechniques"] or None,
    }


# Aliases phổ biến -> VulnerabilityFamily enum value (lowercase)
# Dùng để normalize family name từ AI output (e.g. "Apache Log4j2" -> "jndi_injection")
FAMILY_ALIASES: dict[str, str] = {
    "log4j": "jndi_injection",
    "log4shell": "jndi_injection",
    "apache log4j": "jndi_injection",
    "apache log4j2": "jndi_injection",
    "jndi": "jndi_injection",
    "jndi_injection": "jndi_injection",
    "jndi injection": "jndi_injection",
    "spring4shell": "spring4shell",
    "spring": "spring4shell",
    "spring framework": "spring4shell",
    "data binding": "spring4shell",
    "printnightmare": "privilege_escalation",
    "printspooler": "privilege_escalation",
    "spooler": "privilege_escalation",
    "spoolsv": "privilege_escalation",
    "path traversal": "path_traversal",
    "directory traversal": "path_traversal",
    "traversal": "path_traversal",
    "deserialization": "deserialization",
    "deserial": "deserialization",
    "file upload": "file_upload",
    "upload": "file_upload",
    "webshell": "webshell",
    "shell upload": "webshell",
    "code injection": "code_injection",
    "command injection": "code_injection",
    "struts": "expression_language_injection",
    "ognl": "expression_language_injection",
    "template injection": "code_injection",
    "ssti": "code_injection",
    "server-side template injection": "code_injection",
    "el injection": "expression_language_injection",
    "spel": "expression_language_injection",
    "mvel": "expression_language_injection",
    "ssrf": "ssrf",
    "server-side request forgery": "ssrf",
    "information disclosure": "information_disclosure",
    "info disclosure": "information_disclosure",
    "privesc": "privilege_escalation",
    "privilege escalation": "privilege_escalation",
    "elevation": "privilege_escalation",
}


def normalize_family(value: object) -> str | None:
    """Chuẩn hóa family name về 1 giá trị chuẩn (VulnerabilityFamily enum value).

    Returns:
        - "jndi_injection", "spring4shell", ... nếu match alias
        - "unknown" nếu không match (default fallback)
        - None nếu input rỗng
    """
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not text:
        return None

    # Exact match
    if text in FAMILY_ALIASES:
        return FAMILY_ALIASES[text]

    # Substring match (first match wins)
    for alias, family in FAMILY_ALIASES.items():
        if alias in text:
            return FAMILY_ALIASES[alias] if False else family
            return family

    # No match -> unknown
    return "unknown"


# Semantic validation - filter techniques MÂU THUẪN context CVE.
# Mục đích: bắt hallucination AI obvious - technique không hợp với CVSS vector
# hoặc description. KHÔNG dùng ground truth CAPEC (quá rộng).
#
# Theo spec (CVE-2-Sigma.md): Step 2 phân tích đúng thì Step 3 mới có ý nghĩa.
# Validation này giúp Step 2 loại bỏ techniques sai trước khi pass cho Step 3.

# Network-only techniques - chỉ hợp lý khi CVE exploit được từ xa.
# Dùng frozenset constants (không query STIX) vì đây là semantic, không phải format.
_NETWORK_ONLY_TECHNIQUES: frozenset[str] = frozenset({
    "T1190",  # Exploit Public-Facing Application
    "T1133",  # External Remote Services
    "T1199",  # Trusted Relationship
    "T1566",  # Phishing (nếu remote)
    "T1078",  # Valid Accounts (nếu remote)
    "T1071",  # Application Layer Protocol (C2 network)
})

# Phishing-specific techniques - chỉ hợp với social engineering context.
_PHISHING_TECHNIQUES: frozenset[str] = frozenset({
    "T1566", "T1566.001", "T1566.002", "T1566.003",
    "T1598", "T1598.001", "T1598.002", "T1598.003",
})


def _is_local_only(cvss_vector: str | None) -> bool:
    """CVSS AV:L (Local) - exploit cần local access."""
    if not cvss_vector:
        return False
    return "AV:L" in cvss_vector.upper()


def _has_hardware_context(description: str | None) -> bool:
    """CVE description nhắc tới local/hardware/physical access."""
    if not description:
        return False
    text = description.lower()
    keywords = (
        "local ", "locally", "physical access", "physically",
        "hardware", "usb", "kernel driver", "kernel module",
        "requires physical", "on the same machine",
    )
    return any(kw in text for kw in keywords)


def validate_against_cve_context(
    techniques: list[str] | None,
    cvss_vector: str | None,
    description: str | None,
) -> dict[str, list[str]]:
    """Filter techniques MÂU THUẪN context CVE (semantic validation).

    3 rule (mở rộng được):
      Rule 1: Network-only (T1190, T1133, ...) MÂU THUẪN với AV:L.
      Rule 2: Phishing (T1566, ...) MÂU THUẪN với description local/hardware/physical.
      Rule 3: T1190 vs explicit local context (explicit cho debug).

    Args:
        techniques: List technique IDs AI trả (vd ['T1190', 'T1059']).
        cvss_vector: CVSS vector string (vd 'CVSS:3.1/AV:N/AC:L/...').
        description: CVE description text.

    Returns:
        {
            "kept": [...],
            "dropped": [...],
            "dropped_reasons": {tech: reason, ...},
        }
    """
    kept: list[str] = []
    dropped: list[str] = []
    dropped_reasons: dict[str, str] = {}

    for tech in techniques or []:
        if not isinstance(tech, str):
            continue
        norm = tech.strip().upper()
        if not norm.startswith("T"):
            # Không phải technique ID → giữ nguyên để caller xử lý
            if norm not in kept:
                kept.append(norm)
            continue

        # Rule 1: Network-only vs AV:L
        if _is_local_only(cvss_vector) and norm in _NETWORK_ONLY_TECHNIQUES:
            dropped.append(norm)
            dropped_reasons[norm] = "network_only_vs_AV_L"
            continue

        # Rule 2: Phishing vs hardware context
        if _has_hardware_context(description) and norm in _PHISHING_TECHNIQUES:
            dropped.append(norm)
            dropped_reasons[norm] = "phishing_vs_hardware_context"
            continue

        # Rule 3: T1190 vs explicit local context
        if _has_hardware_context(description) and norm == "T1190":
            dropped.append(norm)
            dropped_reasons[norm] = "t1190_vs_local_context"
            continue

        if norm not in kept:
            kept.append(norm)

    return {"kept": kept, "dropped": dropped, "dropped_reasons": dropped_reasons}
