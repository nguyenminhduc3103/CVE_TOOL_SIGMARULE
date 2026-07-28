"""MITRE ATT&CK Validator - Safety Net cho Step 2. Đọc whitelist từ MITRE STIX (~95%+ matrix, auto-update 7 ngày); chỉ fallback hardcode khi STIX load fail."""
from __future__ import annotations

import re

# Regex format: T1059, T1059.001, TA0001
_TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")
_TACTIC_PATTERN = re.compile(r"^TA\d{4}$")


def _get_whitelist():
    """Lazy import + accessor. Tránh forcing 30MB STIX parse chỉ vì import module này cho 1 helper function."""
    from src.shared.mitre.loader import MitreAttackWhitelist
    return MitreAttackWhitelist.get()


# Dynamic accessors thay cho hardcoded VALID_* frozensets; caller mới nên dùng `_get_whitelist().is_known(value)`.


def __getattr__(name: str):
    """Module-level __getattr__ cho backward-compat lazy access qua live MitreAttackWhitelist singleton."""
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
    """Phân loại một TTP ID theo dynamic STIX whitelist: 'tactic' / 'parent' / 'sub' (parent-child fallback) / None."""
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
    """Kiểm tra 1 technique ID có hợp lệ không (parent whitelist + sub whitelist với parent-child fallback)."""
    normalized = _normalize_id(value)
    if normalized is None:
        return False
    return is_known_ttp(normalized) in ("parent", "sub")


def validate_ttp_list(
    tactics: list[str] | None,
    techniques: list[str] | None,
    subtechniques: list[str] | None = None,
) -> dict[str, object]:
    """Validate một list TTP, trả về kết quả tách valid/invalid với warnings và passed flag."""
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
    """Chuẩn hóa family name về 1 giá trị chuẩn (VulnerabilityFamily enum value); 'unknown' fallback hoặc None nếu rỗng."""
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
            return family

    # No match -> unknown
    return "unknown"


# (validate_against_cve_context removed — unused; replaced by evidence-to-TTP consensus)


# CONSENSUS PROMPTING: Evidence-to-TTP Matrix Validation.
# Zero-hardcode dynamic validation: techniques must cite Phase 1 behavior anchors; no anchor → hallucination.


def _validate_file_operation_against_phase1(
    technique_id: str,
    anchor: str,
    phase1_behaviors: list[str],
    behavior_set: set[str],
) -> bool:
    """Validate file operation, privilege escalation, and cryptographic techniques via Phase 1 keyword evidence."""
    # T1505 family (Web Shell, Server Software Component)
    if technique_id.startswith("T1505"):
        for behavior in behavior_set:
            for kw in _FILE_OPERATION_KEYWORDS:
                if kw in behavior or behavior in kw:
                    return True
        return False

    # T1068 (Exploitation for Privilege Escalation)
    if technique_id == "T1068":
        for behavior in behavior_set:
            for kw in _PRIVILEGE_ESCALATION_KEYWORDS:
                if kw in behavior or behavior in kw:
                    return True
        return False

    # T1556 (Modify Authentication Process) - cryptographic flaws, auth bypass
    if technique_id == "T1556":
        for behavior in behavior_set:
            for kw in _CRYPTOGRAPHIC_FLAW_KEYWORDS:
                if kw in behavior or behavior in kw:
                    return True
        return False

    # T1105 (Ingress Tool Transfer) - file download
    if technique_id == "T1105":
        for behavior in behavior_set:
            if "download" in behavior or "transfer" in behavior or "tool" in behavior:
                return True
        return False

    # Generic check for privilege escalation techniques (T1068.xxx)
    if technique_id.startswith("T1068"):
        for behavior in behavior_set:
            for kw in _PRIVILEGE_ESCALATION_KEYWORDS:
                if kw in behavior or behavior in kw:
                    return True
        return False

    # Generic check for auth modification techniques (T1556.xxx)
    if technique_id.startswith("T1556"):
        for behavior in behavior_set:
            for kw in _CRYPTOGRAPHIC_FLAW_KEYWORDS:
                if kw in behavior or behavior in kw:
                    return True
        return False

    # Generic file operation check for anchor
    if anchor:
        anchor_lower = anchor.lower()
        for kw in _FILE_OPERATION_KEYWORDS | _PRIVILEGE_ESCALATION_KEYWORDS | _CRYPTOGRAPHIC_FLAW_KEYWORDS:
            if kw in anchor_lower:
                for behavior in behavior_set:
                    if kw in behavior or behavior in kw:
                        return True
    return False


def _extract_keywords_from_behaviors(behaviors: list[str]) -> set[str]:
    """Extract individual keywords from behaviors for flexible matching."""
    keywords = set()
    for behavior in behaviors:
        words = behavior.lower().replace("_", " ").replace("-", " ").split()
        keywords.update(words)
    return keywords


def validate_technique_chain_against_phase1(
    attack_chain: list[dict],
    phase1_behaviors: list[str],
) -> dict[str, list[dict] | dict[str, str]]:
    """Validate techniques have matching behavior anchors from Phase 1 (pure set membership + fuzzy keyword match)."""
    valid_entries = []
    invalid_entries = []
    kept_technique_ids = []
    dropped_technique_ids = []
    dropped_reasons: dict[str, str] = {}

    if not phase1_behaviors:
        # No behaviors from Phase 1 - accept all techniques (cannot validate)
        for entry in attack_chain:
            tech_id = entry.get("technique_id", "")
            if tech_id:
                kept_technique_ids.append(tech_id.upper())
                valid_entries.append(entry)
        return {
            "valid_entries": valid_entries,
            "invalid_entries": [],
            "dropped_reasons": {},
            "kept_technique_ids": kept_technique_ids,
            "dropped_technique_ids": [],
        }

    # Normalize Phase 1 behaviors for matching
    behavior_set = {b.lower().strip() for b in phase1_behaviors}
    behavior_keywords = _extract_keywords_from_behaviors(phase1_behaviors)

    for entry in attack_chain:
        technique_id = entry.get("technique_id", "")
        anchor = entry.get("exact_behavior_anchor", "").lower().strip()

        if not technique_id:
            continue

        technique_id = technique_id.upper()

        # Check if anchor matches any Phase 1 behavior
        # Match strategies:
        # 1. Exact match
        # 2. Partial match (anchor substring of behavior or vice versa)
        # 3. Keyword overlap
        matched = False
        matched_behavior = None

        for behavior in behavior_set:
            # Exact match
            if anchor == behavior:
                matched = True
                matched_behavior = behavior
                break
            # Partial match
            if anchor in behavior or behavior in anchor:
                matched = True
                matched_behavior = behavior
                break

        # Keyword-based fuzzy matching
        if not matched and anchor:
            anchor_words = anchor.replace("_", " ").replace("-", " ").split()
            for behavior in behavior_set:
                behavior_words = behavior.replace("_", " ").replace("-", " ").split()
                # Check if any word overlaps
                if any(w in behavior_words for w in anchor_words if len(w) > 3):
                    matched = True
                    matched_behavior = behavior
                    break

        # Special handling for file operation techniques (T1505, T1105, etc.)
        # These need file_write/file_upload evidence from Phase 1
        if not matched:
            matched = _validate_file_operation_against_phase1(
                technique_id, anchor, phase1_behaviors, behavior_set
            )

        if matched:
            valid_entries.append(entry)
            if technique_id not in kept_technique_ids:
                kept_technique_ids.append(technique_id)
        else:
            invalid_entries.append(entry)
            if technique_id not in dropped_technique_ids:
                dropped_technique_ids.append(technique_id)
            dropped_reasons[technique_id] = (
                f"Anchor '{anchor}' not found in Phase 1 behaviors. "
                f"Available: {list(phase1_behaviors)}"
            )

    return {
        "valid_entries": valid_entries,
        "invalid_entries": invalid_entries,
        "dropped_reasons": dropped_reasons,
        "kept_technique_ids": kept_technique_ids,
        "dropped_technique_ids": dropped_technique_ids,
    }

