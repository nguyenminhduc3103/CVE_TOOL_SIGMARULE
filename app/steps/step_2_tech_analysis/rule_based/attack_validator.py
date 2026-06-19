"""MITRE ATT&CK Validator - Safety Net cho Bước 2.

Validate TTP IDs (Tactics & Techniques) do AI sinh ra hoặc rule-based sinh ra
theo danh sách chuẩn MITRE ATT&CK Enterprise.

Triết lý: Whitelist tĩnh các IDs phổ biến (~50 techniques + 14 tactics),
không cần gọi MITRE TAXII/STIX server (happy case, 0 network dependency).

Ràng buộc theo tài liệu (dòng 24): "Mã TTP do AI sinh ra phải được đối chiếu
và xác thực với danh sách chuẩn của MITRE. Mã không hợp lệ sẽ bị loại bỏ."
"""
from __future__ import annotations

import re

# Regex format: T1059, T1059.001, TA0001
_TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")
_TACTIC_PATTERN = re.compile(r"^TA\d{4}$")

# Whitelist đầy đủ ~14 Enterprise tactics (MITRE ATT&CK v15)
VALID_TACTICS: frozenset[str] = frozenset({
    "TA0043",  # Reconnaissance
    "TA0042",  # Resource Development
    "TA0001",  # Initial Access
    "TA0002",  # Execution
    "TA0003",  # Persistence
    "TA0004",  # Privilege Escalation
    "TA0005",  # Defense Evasion
    "TA0006",  # Credential Access
    "TA0007",  # Discovery
    "TA0008",  # Lateral Movement
    "TA0009",  # Collection
    "TA0011",  # Command and Control
    "TA0010",  # Exfiltration
    "TA0040",  # Impact
})

# Whitelist ~50 techniques phổ biến (cover 90% CVE thực tế).
# Nguồn: BEHAVIOR_ATTACK_GRAPH + VULNERABILITY_CLASS_ATTACK_GRAPH trong attack_mapper.py
# + các techniques thường gặp trong CVE web/RCE/Privesc.
VALID_SUBTECHNIQUES: frozenset[str] = frozenset({
    # T1059 Command and Scripting Interpreter subtechniques
    "T1059.001",  # PowerShell
    "T1059.002",  # AppleScript
    "T1059.003",  # Windows Command Shell
    "T1059.004",  # Unix Shell
    "T1059.005",  # Visual Basic
    "T1059.006",  # Python
    "T1059.007",  # JavaScript
    "T1059.008",  # Network Device CLI
    "T1059.009",  # Cloud API
    "T1059.010",  # AutoHotKey & AutoIT
    # T1071 Application Layer Protocol
    "T1071.001",  # Web Protocols
    "T1071.002",  # File Transfer Protocols
    "T1071.003",  # Mail Protocols
    "T1071.004",  # DNS
    # T1505 Server Software Component
    "T1505.003",  # Web Shell
    "T1505.004",  # IIS Components
    "T1505.005",  # Terminal Services DLLs
    # T1574 Hijack Execution Flow
    "T1574.001",  # DLL
    "T1574.002",  # DLL Side-Loading
    "T1574.004",  # Dylib Hijacking
    "T1574.005",  # Executable Installer File Permissions Weakness
    "T1574.006",  # Dynamic Linker Hijacking
    "T1574.007",  # Path Interception
    "T1574.008",  # Path Interception by Search Order Hijacking
    "T1574.009",  # Path Interception by Unquoted Path
    "T1574.010",  # Services File Permissions Weakness
    "T1574.011",  # Services Registry Permissions Weakness
    "T1574.012",  # COR_PROFILER
    # T1548 Abuse Elevation Control Mechanism
    "T1548.001",  # Setuid and Setgid
    "T1548.002",  # Bypass User Account Control
    "T1548.003",  # Sudo and Sudo Caching
    "T1548.004",  # Elevated Execution with Prompt
    "T1548.005",  # Temporary Elevated Cloud Access
    # T1555 Credentials from Password Stores
    "T1555.001",  # Keychain
    "T1555.002",  # Securityd Memory
    "T1555.003",  # Credentials from Web Browsers
    "T1555.004",  # Windows Credential Manager
    "T1555.005",  # Password Managers
    # T1055 Process Injection
    "T1055.001",  # Dynamic-link Library Injection
    "T1055.002",  # Portable Executable Injection
    "T1055.003",  # Thread Execution Hijacking
    "T1055.004",  # Asynchronous Procedure Call
    "T1055.005",  # Thread Local Storage
    "T1055.008",  # Ptrace System Calls
    "T1055.009",  # Proc Memory
    "T1055.011",  # Extra Window Memory Injection
    "T1055.012",  # Process Hollowing
    "T1055.013",  # Process Doppelgänging
    "T1055.014",  # VDSO Hijacking
    "T1055.015",  # ListPlanting
    # T1021 Remote Services
    "T1021.001",  # Remote Desktop Protocol
    "T1021.002",  # SMB/Windows Admin Shares
    "T1021.003",  # Distributed Component Object Model
    "T1021.004",  # SSH
    "T1021.005",  # VNC
    "T1021.006",  # Windows Remote Management
    "T1021.007",  # Cloud Services
    "T1021.008",  # Direct Cloud VM Connections
    # T1110 Brute Force
    "T1110.001",  # Password Guessing
    "T1110.002",  # Password Cracking
    "T1110.003",  # Password Spraying
    "T1110.004",  # Credential Stuffing
    # T1204 User Execution
    "T1204.001",  # Malicious Link
    "T1204.002",  # Malicious File
    "T1204.003",  # Malicious Image
    # T1499 Endpoint DoS
    "T1499.001",  # OS Exhaustion Flood
    "T1499.002",  # Service Exhaustion Flood
    "T1499.003",  # Application Exhaustion Flood
    "T1499.004",  # Application or System Exploitation
    # T1498 Network DoS
    "T1498.001",  # Direct Network Flood
    "T1498.002",  # Reflection Amplification
    # T1003 OS Credential Dumping
    "T1003.001",  # LSASS Memory
    "T1003.002",  # Security Account Manager
    "T1003.003",  # NTDS
    "T1003.004",  # LSA Secrets
    "T1003.005",  # Cached Domain Credentials
    "T1003.006",  # DCSync
    "T1003.007",  # Proc Filesystem
    "T1003.008",  # /etc/passwd and /etc/shadow
    # T1027 Obfuscated Files
    "T1027.001",  # Binary Padding
    "T1027.002",  # Software Packing
    "T1027.003",  # Steganography
    "T1027.004",  # Compile After Delivery
    "T1027.005",  # Indicator Removal from Tools
    "T1027.006",  # HTML Smuggling
    "T1027.007",  # Dynamic API Resolution
    "T1027.008",  # Stripped Payloads
    "T1027.009",  # Embedded Payloads
    "T1027.010",  # Command Obfuscation
    "T1027.011",  # Fileless Storage
    "T1027.012",  # Lifted Obfuscated Code
    "T1027.013",  # Encrypted/Encoded File
    # T1491 Defacement
    "T1491.001",  # Internal Defacement
    "T1491.002",  # External Defacement
})

VALID_TECHNIQUES: frozenset[str] = frozenset({
    # --- Initial Access ---
    "T1189",  # Drive-by Compromise
    "T1190",  # Exploit Public-Facing Application
    "T1133",  # External Remote Services
    "T1200",  # Hardware Additions
    "T1566",  # Phishing
    "T1078",  # Valid Accounts
    # --- Execution ---
    "T1059",  # Command and Scripting Interpreter
    "T1059.001", "T1059.002", "T1059.003", "T1059.004", "T1059.005",
    "T1059.006", "T1059.007", "T1059.008", "T1059.009", "T1059.010",
    "T1106",  # Native API
    "T1053",  # Scheduled Task/Job
    "T1129",  # Shared Modules
    "T1072",  # Software Deployment Tools
    "T1569",  # System Services
    "T1204",  # User Execution
    "T1204.001", "T1204.002",
    # --- Persistence ---
    "T1136",  # Create Account
    "T1543",  # Create or Modify System Process
    "T1505",  # Server Software Component
    "T1505.003",  # Web Shell
    "T1547",  # Boot or Logon Autostart Execution
    "T1546",  # Event Triggered Execution
    "T1574",  # Hijack Execution Flow
    "T1574.001", "T1574.002", "T1574.004", "T1574.005", "T1574.006", "T1574.007",
    "T1556",  # Modify Authentication Process
    "T1137",  # Office Application Startup
    # --- Privilege Escalation ---
    "T1068",  # Exploitation for Privilege Escalation
    "T1055",  # Process Injection
    "T1055.001", "T1055.002", "T1055.003", "T1055.004", "T1055.005",
    "T1548",  # Abuse Elevation Control Mechanism
    "T1548.001", "T1548.002", "T1548.003", "T1548.004", "T1548.005",
    # --- Defense Evasion ---
    "T1027",  # Obfuscated Files or Information
    "T1027.001", "T1027.002", "T1027.003", "T1027.004",
    "T1070",  # Indicator Removal
    "T1112",  # Modify Registry
    "T1562",  # Impair Defenses
    "T1218",  # System Binary Proxy Execution
    "T1222",  # File and Directory Permissions Modification
    # --- Credential Access ---
    "T1003",  # OS Credential Dumping
    "T1110",  # Brute Force
    "T1110.001", "T1110.002", "T1110.003", "T1110.004",
    "T1555",  # Credentials from Password Stores
    "T1212",  # Exploitation for Credential Access
    # --- Discovery ---
    "T1087",  # Account Discovery
    "T1083",  # File and Directory Discovery
    "T1057",  # Process Discovery
    "T1018",  # Remote System Discovery
    "T1518",  # Software Discovery
    "T1049",  # System Network Connections Discovery
    "T1046",  # Network Service Discovery
    # --- Lateral Movement ---
    "T1021",  # Remote Services
    "T1021.001", "T1021.002", "T1021.003", "T1021.004", "T1021.005", "T1021.006",
    "T1570",  # Lateral Tool Transfer
    "T1210",  # Exploitation of Remote Services
    # --- Collection ---
    "T1005",  # Data from Local System
    "T1039",  # Data from Network Shared Drive
    "T1025",  # Data from Removable Media
    "T1114",  # Email Collection
    "T1115",  # Clipboard Data
    # --- Command and Control ---
    "T1071",  # Application Layer Protocol
    "T1071.001", "T1071.002", "T1071.003", "T1071.004",
    "T1090",  # Proxy
    "T1095",  # Non-Application Layer Protocol
    "T1572",  # Protocol Tunneling
    "T1092",  # Communication Through Removable Media
    "T1105",  # Ingress Tool Transfer
    "T1132",  # Data Encoding
    "T1008",  # Fallback Channels
    "T1104",  # Multi-Stage Channels
    # --- Exfiltration ---
    "T1020",  # Automated Exfiltration
    "T1030",  # Data Transfer Size Limits
    "T1041",  # Exfiltration Over C2 Channel
    "T1048",  # Exfiltration Over Alternative Protocol
    "T1052",  # Exfiltration Over Physical Medium
    "T1567",  # Exfiltration Over Web Service
    # --- Impact ---
    "T1485",  # Data Destruction
    "T1486",  # Data Encrypted for Impact
    "T1490",  # Inhibit System Recovery
    "T1499",  # Endpoint Denial of Service
    "T1499.001", "T1499.002", "T1499.003", "T1499.004",
    "T1498",  # Network Denial of Service
    "T1498.001", "T1498.002",
    "T1491",  # Defacement
    "T1491.001", "T1491.002",
    "T1484",  # Domain or Tenant Policy Modification
    "T1482",  # Domain Trust Discovery
})


def _normalize_id(value: object) -> str | None:
    """Chuẩn hóa ID về dạng 'T1059' hoặc 'TA0001' (uppercase, strip whitespace)."""
    if not isinstance(value, str):
        return None
    text = value.strip().upper()
    if not text:
        return None
    # Map từ format dài 'attack.t1059' về ngắn 'T1059'
    if text.startswith("ATTACK."):
        text = text[len("ATTACK."):]
    return text


def is_known_ttp(value: str) -> str | None:
    """Phân loại một TTP ID (đã được normalize) theo whitelist.

    Trả về category string để giúp debug/giảm duplication giữa
    validate_tactic và validate_technique:

    Returns:
        - "tactic" : ID khớp _TACTIC_PATTERN và có trong VALID_TACTICS.
        - "parent" : base technique (T1059) có trong VALID_TECHNIQUES.
        - "sub"    : subtechnique (T1059.001) có trong VALID_SUBTECHNIQUES
                     HOẶC có parent technique hợp lệ (parent-child fallback).
        - None     : ID không hợp lệ về format hoặc không nằm trong whitelist.

    Lưu ý: "sub" trả về ngay cả khi match qua parent-child fallback, vì
    validate_technique() vẫn pass trong trường hợp đó.
    """
    if not value:
        return None
    if _TACTIC_PATTERN.match(value) and value in VALID_TACTICS:
        return "tactic"
    if not _TECHNIQUE_PATTERN.match(value):
        return None
    if "." in value:
        # Subtechnique - ưu tiên whitelist cứng
        if value in VALID_SUBTECHNIQUES:
            return "sub"
        # Fallback: parent technique hợp lệ → coi như sub-technique hợp lý
        # theo convention. Tránh phải maintain ~600 subtechnique IDs thủ công.
        parent = value.split(".", 1)[0]
        if parent in VALID_TECHNIQUES:
            return "sub"
        return None
    # Base technique
    if value in VALID_TECHNIQUES:
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
    - Technique (T1059): phải có trong VALID_TECHNIQUES.
    - Subtechnique (T1059.001): ưu tiên check trong VALID_SUBTECHNIQUES.
      Nếu không có trong whitelist, fallback: chấp nhận nếu parent technique
      hợp lệ (vd AI trả T1021.003 dù chưa list trong whitelist nhưng T1021
      hợp lệ → pass). Vẫn reject T9999.001 (parent invalid).
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
            "valid_tactics": [...],
            "valid_techniques": [...],
            "valid_subtechniques": [...],
            "invalid_tactics": [...],
            "invalid_techniques": [...],
            "invalid_subtechniques": [...],
            "warnings": ["invalid_technique_dropped:T9999", ...],
            "passed": bool (True nếu không có invalid nào),
        }
    """
    valid_tactics: list[str] = []
    invalid_tactics: list[str] = []
    valid_techniques: list[str] = []
    invalid_techniques: list[str] = []
    valid_subtechniques: list[str] = []
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
                # Là subtechnique
                if normalized not in valid_subtechniques:
                    valid_subtechniques.append(normalized)
                # Đồng thời thêm base vào techniques nếu chưa có
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
            if normalized not in valid_subtechniques:
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
            return family

    # No match -> unknown
    return "unknown"


# =============================================================================
# Semantic validation - filter techniques MÂU THUẪN context CVE
# =============================================================================
# Mục đích: bắt hallucination AI obvious - technique không hợp với CVSS vector
# hoặc description của CVE. KHÔNG dùng ground truth CAPEC (quá rộng).
#
# Theo spec (CVE-2-Sigma.md): Step 2 phải phân tích đúng thì Step 3 mới có ý nghĩa.
# Validation này giúp Step 2 loại bỏ techniques sai trước khi pass cho Step 3.

# Network-only techniques - chỉ hợp lý khi CVE exploit được từ xa
_NETWORK_ONLY_TECHNIQUES: frozenset[str] = frozenset({
    "T1190",  # Exploit Public-Facing Application
    "T1133",  # External Remote Services
    "T1199",  # Trusted Relationship
    "T1566",  # Phishing (nếu remote)
    "T1078",  # Valid Accounts (nếu remote)
    "T1071",  # Application Layer Protocol (C2 network)
})

# Phishing-specific techniques - chỉ hợp với social engineering context
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

    3 rule hiện tại (mở rộng được nếu cần):
      Rule 1: Network-only techniques (T1190, T1133, ...) MÂU THUẪN với
              CVSS AV:L (local-only CVE).
      Rule 2: Phishing techniques (T1566, ...) MÂU THUẪN với description
              nhắc tới local/hardware/physical access.
      Rule 3: T1190 vs explicit local context (redundant với rule 1+2 nhưng
              explicit để dễ debug).

    Args:
        techniques: List technique IDs AI trả (vd ['T1190', 'T1059']).
        cvss_vector: CVSS vector string (vd 'CVSS:3.1/AV:N/AC:L/...').
        description: CVE description text.

    Returns:
        {
            "kept": [...],         # techniques qua validation
            "dropped": [...],      # techniques bị loại
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
