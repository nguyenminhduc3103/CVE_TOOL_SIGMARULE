"""OntologyManager - 4-Layer Truth Resolver (Single Source of Truth cho expected TTP).

Vấn đề trước kia:
- 2 hàm compute_ground_truth() và map_attack() dùng 2 bảng mapping khác nhau
  → AI bị so sánh với ground truth không nhất quán (Source of Truth Mismatch)
- Nếu CWE không có trong whitelist 8 CWE → expected_behaviors rỗng
  → compute_coverage chia 0 → fallback 1.0 (100% giả tạo, "Coverage Hallucination")
- Extra techniques bị phạt 5%/cái kể cả khi hợp lệ với CVE context
  (Strict Penalty paradox: AI bị phạt vì... đúng hơn whitelist)

Giải pháp 4-Layer Fallback:
  Layer 1: CTID direct (CVE-level, highest quality)
  Layer 2: CAPEC bridge (CWE-level, high coverage)
  Layer 3: Whitelist 8 CWE (backward compat)
  Layer 4: UNKNOWN (honest fallback - không fabricate ground truth)

Bổ sung: is_contradiction() để filter extras có thật sự sai context CVE hay không.
"""
from __future__ import annotations

import csv
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from app.shared.utils.cvss_parser import (
    is_local_only as _is_local_only,
    is_network_reachable as _is_network_reachable,
    is_pre_auth as _is_pre_auth,
)
from app.steps.step_2_tech_analysis.rule_based.cwe_mapper import (
    CWE_BEHAVIOR_MAP,
)

# NOTE: BEHAVIOR_ATTACK_GRAPH định nghĩa trong attack_mapper.py nhưng
# attack_mapper import từ ontology_manager → CIRCULAR.
# Dùng lazy import trong _resolve_layer23() để tránh vòng lặp.

logger = logging.getLogger(__name__)

# Quality enum cho ground truth resolution
GroundTruthSource = Literal["CTID", "CAPEC", "WHITELIST", "MIXED", "UNKNOWN"]
GroundTruthQuality = Literal["HIGH", "PARTIAL", "UNKNOWN"]


# Đường dẫn tới data files (relative với file này)
_DATA_DIR = Path(__file__).parent / "ground_truth_sources"
_CAPEC_FILE = _DATA_DIR / "capec_stix.json"
_CTID_FILE = _DATA_DIR / "cti_mappings.csv"

# Flag: có thể disable load data files qua env var (cho test môi trường
# không có file - vd CI/CD, sandbox)
_DISABLE_OFFLINE_DATA = os.environ.get("CVE_TI_DISABLE_OFFLINE_ONTOLOGY") == "1"


@dataclass(frozen=True)
class CveContext:
    """Context bundle cho ontology resolution + contradiction detection.

    Gom tất cả thông tin CVE thành 1 struct bất biến - tránh threading
    nhiều tham số qua các helper.
    """
    cve_id: str
    description: str | None = ""
    cwe_ids: tuple[str, ...] = ()
    cvss_vector: str | None = None

    def is_local_only(self) -> bool:
        """CVSS AV:L (Local) - exploit cần local access."""
        return _is_local_only(self.cvss_vector)

    def is_network_reachable(self) -> bool:
        """CVSS AV:N (Network) - exploit qua network."""
        return _is_network_reachable(self.cvss_vector)

    def is_pre_auth(self) -> bool:
        """CVSS PR:N - không cần authentication."""
        return _is_pre_auth(self.cvss_vector)

    def has_local_hardware_context(self) -> bool:
        """CVE description nhắc tới local-only/hardware/physical access."""
        if not self.description:
            return False
        text = self.description.lower()
        keywords = (
            "local ", "locally", "physical access", "physically",
            "hardware", "usb", "kernel driver", "kernel module",
            "requires physical", "on the same machine",
        )
        return any(kw in text for kw in keywords)


@dataclass(frozen=True)
class ExpectedTTPs:
    """Kết quả resolve() - expected ground truth cho 1 CVE.

    Các trường expected_* là sets rỗng nếu layer 4 (UNKNOWN).
    Có thêm metadata về source + quality để downstream quyết định
    confidence khi đánh giá AI output.
    """
    cve_id: str | None
    expected_cwes: frozenset[str] = field(default_factory=frozenset)
    expected_behaviors: frozenset[str] = field(default_factory=frozenset)
    expected_techniques: frozenset[str] = field(default_factory=frozenset)
    expected_tactics: frozenset[str] = field(default_factory=frozenset)
    ground_truth_source: GroundTruthSource = "UNKNOWN"
    ground_truth_quality: GroundTruthQuality = "UNKNOWN"

    def is_unknown(self) -> bool:
        return self.ground_truth_quality == "UNKNOWN"

    def to_dict(self) -> dict[str, set[str] | str]:
        """Serialize về dict format mà gap_analysis.compute_coverage() expect.

        Bổ sung 2 key mới: 'ground_truth_source' + 'ground_truth_quality'
        """
        return {
            "expected_cwes": set(self.expected_cwes),
            "expected_behaviors": set(self.expected_behaviors),
            "expected_techniques": set(self.expected_techniques),
            "expected_tactics": set(self.expected_tactics),
            "ground_truth_source": self.ground_truth_source,
            "ground_truth_quality": self.ground_truth_quality,
        }


class OntologyManager:
    """4-Layer Truth Resolver - load offline MITRE data + resolve CVE → expected TTP.

    Singleton-friendly: instance có thể share giữa gap_analysis và attack_mapper
    để đảm bảo cùng source. Lazy load: chỉ parse JSON khi instance đầu tiên
    được tạo.

    Example:
        >>> mgr = OntologyManager()
        >>> ctx = CveContext(cve_id="CVE-2021-44228", cwe_ids=("CWE-502",), ...)
        >>> expected = mgr.resolve(ctx)
        >>> expected.expected_techniques
        {'T1059', 'T1190'}
        >>> expected.ground_truth_quality
        'PARTIAL'  # vì layer 3 whitelist
    """

    # Singleton state (per-class, để test có thể reset nếu cần)
    _instance: "OntologyManager | None" = None

    def __new__(cls) -> "OntologyManager":
        # Singleton - tránh parse JSON 4.3MB nhiều lần trong 1 process
        if cls._instance is None:
            inst = super().__new__(cls)
            inst._initialized = False
            cls._instance = inst
        return cls._instance

    def __init__(self) -> None:
        if getattr(self, "_initialized", False):
            return
        self._initialized = True
        self._capec_index: dict[str, set[str]] = {}  # CWE-id -> ATT&CK techniques
        self._ctid_index: dict[str, dict[str, set[str]]] = {}  # CVE-id -> {primary, secondary, exploitation}
        # MITRE ATT&CK technique → tactic(s) lookup (data-driven from STIX bundle).
        # Populated by _load_attack_tactics() from lightweight JSON file
        # (~50-100KB) extracted offline by fetch_ground_truth.py.
        self._attack_tactics_index: dict[str, list[str]] = {}
        self._load_capec()
        self._load_ctid()
        self._load_attack_tactics()
        logger.debug(
            "OntologyManager initialized: %d CWEs in CAPEC bridge, %d CVEs in CTID direct, "
            "%d ATT&CK techniques in tactic index",
            len(self._capec_index), len(self._ctid_index), len(self._attack_tactics_index),
        )

    def reset(self) -> None:
        """Reset singleton (chỉ dùng cho test)."""
        OntologyManager._instance = None
        self._initialized = False
        self._capec_index = {}
        self._ctid_index = {}

    # =================================================================
    # Loaders
    # =================================================================

    def _load_capec(self) -> None:
        """Parse capec_stix.json (MITRE STIX 2.1 bundle) → CWE → ATT&CK techniques.

        Structure thực tế (đã verify):
          - objects[].type == 'attack-pattern' (CAPEC)
          - objects[].external_references[]: list of {source_name, external_id}
              source_name='cwe' → CWE-id
              source_name='ATTACK' → Txxxx
          - 1 CAPEC có thể có nhiều CWE + 1 ATT&CK ID
        """
        if _DISABLE_OFFLINE_DATA:
            logger.debug("OntologyManager: CAPEC load disabled (env CVE_TI_DISABLE_OFFLINE_ONTOLOGY=1)")
            return
        if not _CAPEC_FILE.exists():
            logger.debug("OntologyManager: %s not found, skipping CAPEC layer", _CAPEC_FILE.name)
            return
        try:
            with open(_CAPEC_FILE, "r", encoding="utf-8") as f:
                bundle = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("OntologyManager: failed to load CAPEC bundle: %s", exc)
            return

        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            cwes: set[str] = set()
            techs: set[str] = set()
            for ref in obj.get("external_references", []) or []:
                src = ref.get("source_name")
                eid = ref.get("external_id", "")
                if src == "cwe" and eid.startswith("CWE-"):
                    cwes.add(eid.upper())
                elif src == "ATTACK" and eid.startswith("T"):
                    techs.add(eid)
            for c in cwes:
                self._capec_index.setdefault(c, set()).update(techs)

    def _load_ctid(self) -> None:
        """Parse cti_mappings.csv (CTID MITRE) → CVE → ATT&CK techniques.

        CSV format (đã verify):
          CVE ID, Primary Impact, Secondary Impact, Exploitation Technique, Uncategorized, Phase
          Multi-value separator: ';'
        LƯU Ý: Nhiều CVE chỉ có techniques trong cột "Uncategorized" (vd
        CVE-2019-0708 BlueKeep → Uncategorized: T1574; T1068). Phải đọc
        cả 4 cột để tránh miss data.
        """
        if _DISABLE_OFFLINE_DATA:
            return
        if not _CTID_FILE.exists():
            logger.debug("OntologyManager: %s not found, skipping CTID layer", _CTID_FILE.name)
            return
        try:
            with open(_CTID_FILE, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    cve = (row.get("CVE ID") or "").strip()
                    if not cve:
                        continue
                    # Union tất cả 4 cột techniques (Primary/Secondary/Exploitation/Uncategorized)
                    # - giữ trọng số để biết technique nào primary, nhưng
                    #   resolve() union tất cả nên không quan trọng thứ tự.
                    self._ctid_index[cve.upper()] = {
                        "primary": self._split_techs(row.get("Primary Impact")),
                        "secondary": self._split_techs(row.get("Secondary Impact")),
                        "exploitation": self._split_techs(row.get("Exploitation Technique")),
                        "uncategorized": self._split_techs(row.get("Uncategorized")),
                    }
        except (OSError, csv.Error, KeyError) as exc:
            logger.warning("OntologyManager: failed to load CTID CSV: %s", exc)

    @staticmethod
    def _split_techs(value: str | None) -> set[str]:
        """Split multi-value cell 'T1059; T1190' → {'T1059', 'T1190'}."""
        if not value:
            return set()
        return {t.strip() for t in value.split(";") if t.strip()}

    # =================================================================
    # MITRE ATT&CK technique → tactic (data-driven)
    # =================================================================

    _ATTACK_TACTICS_FILE = _DATA_DIR / "attack_technique_to_tactic.json"

    def _load_attack_tactics(self) -> None:
        """Load MITRE ATT&CK technique→tactic mapping từ lightweight JSON.

        File `attack_technique_to_tactic.json` (~50-100KB) được pre-extract
        offline bởi `fetch_ground_truth.py` từ MITRE ATT&CK STIX bundle
        (~12MB). Runtime chỉ load JSON nhỏ → O(N) dict lookup, <5ms init.

        Graceful fallback: nếu file missing/malformed, `_attack_tactics_index`
        giữ rỗng → `_technique_to_tactic()` fallback về `_HEURISTIC_TACTIC_MAP`
        in-memory (~20 techniques).
        """
        if _DISABLE_OFFLINE_DATA or not self._ATTACK_TACTICS_FILE.exists():
            logger.debug(
                "OntologyManager: attack_technique_to_tactic.json not found, "
                "using heuristic fallback (~20 techniques)"
            )
            return
        try:
            with open(self._ATTACK_TACTICS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._attack_tactics_index = data.get("mapping", {}) or {}
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning(
                "OntologyManager: failed to load attack tactics: %s - "
                "using heuristic fallback", exc
            )

    # =================================================================
    # 4-Layer Resolution
    # =================================================================

    def resolve(self, ctx: CveContext) -> ExpectedTTPs:
        """Resolve CVE → expected TTP sử dụng 4-layer fallback chain.

        Layer 1: CTID direct (CVE-level, HIGH quality)
            - Direct lookup _ctid_index[cve_id]
            - Nếu hit → return ngay (highest confidence)
        Layer 2: CAPEC bridge (CWE-level, high coverage)
            - Mỗi CWE trong cwe_ids → tra _capec_index → collect techniques
        Layer 3: Whitelist 8 CWE (backward compat)
            - CWE có trong CWE_BEHAVIOR_MAP → derive từ behaviors
            - Dùng BEHAVIOR_ATTACK_GRAPH để map behaviors → techniques
            - Combine với layer 2 (quality = PARTIAL)
        Layer 4: UNKNOWN
            - Tất cả layer trên đều miss → trả sets rỗng + quality UNKNOWN

        Args:
            ctx: CveContext bundle chứa cve_id, cwe_ids, description, cvss_vector.

        Returns:
            ExpectedTTPs với 4 sets + source/quality metadata.
        """
        # Lazy import để tránh circular import (attack_mapper → ontology_manager)
        from app.steps.step_2_tech_analysis.rule_based.attack_mapper import (
            BEHAVIOR_ATTACK_GRAPH,
        )

        cve_id = ctx.cve_id
        # Filter NVD placeholder CWEs (vd "NVD-CWE-noinfo", "NVD-CWE-Other") -
        # chúng không phải CWE thật, không có trong CAPEC/WHITELIST, sẽ làm
        # PRIMARY CWE selection rơi vào placeholder → inflate ground truth
        # với techniques từ CWE "primary" không có thật.
        cwe_ids = tuple(
            c.upper() for c in (ctx.cwe_ids or ())
            if not c.upper().startswith("NVD-CWE")
        )

        # ----------------------------------------------------------------
        # Layer 1: CTID direct lookup
        # ----------------------------------------------------------------
        ctid_hit = self._ctid_index.get(cve_id.upper()) if cve_id else None
        if ctid_hit:
            techs = (
                ctid_hit.get("primary", set())
                | ctid_hit.get("secondary", set())
                | ctid_hit.get("exploitation", set())
                | ctid_hit.get("uncategorized", set())  # Nhiều CVE chỉ có ở đây
            )
            tactics: set[str] = set()
            for t in techs:
                tactics.update(self._technique_to_tactic(t))
            return ExpectedTTPs(
                cve_id=cve_id,
                expected_cwes=frozenset(cwe_ids),
                expected_behaviors=frozenset(),
                expected_techniques=frozenset(techs),
                expected_tactics=frozenset(tactics),
                ground_truth_source="CTID",
                ground_truth_quality="HIGH",
            )

        # ----------------------------------------------------------------
        # Layer 2 + 3: CAPEC bridge ∪ Whitelist fallback
        # ----------------------------------------------------------------
        # CHỐNG MULTI-CWE INFLATION:
        # - Chọn PRIMARY CWE = CWE đầu tiên có trong whitelist (CWE_BEHAVIOR_MAP)
        #   HOẶC CWE đầu tiên có trong CAPEC index.
        # - PRIMARY CWE quyết định techniques chính (anchor).
        # - Secondary CWEs chỉ BỔ SUNG behaviors (không inflate techniques).
        #   Lý do: 1 CVE thực tế không khai thác TẤT CẢ techniques của mọi CWE
        #   liên quan. CWE-400 (DoS) không áp dụng cho Log4Shell exploit chain
        #   dù NVD liệt kê nó.
        primary_cwe: str | None = None
        for cwe in cwe_ids:
            if cwe in CWE_BEHAVIOR_MAP:
                primary_cwe = cwe
                break
        if primary_cwe is None:
            for cwe in cwe_ids:
                if cwe in self._capec_index:
                    primary_cwe = cwe
                    break
        # Fallback: nếu không match whitelist/CAPEC, dùng CWE đầu tiên
        if primary_cwe is None and cwe_ids:
            primary_cwe = cwe_ids[0]

        capec_techs: set[str] = set()
        whitelist_techs: set[str] = set()
        whitelist_behaviors: set[str] = set()

        if primary_cwe:
            # PRIMARY CWE: lấy techniques đầy đủ từ CAPEC + Whitelist
            if primary_cwe in self._capec_index:
                capec_techs.update(self._capec_index[primary_cwe])
            if primary_cwe in CWE_BEHAVIOR_MAP:
                profile = CWE_BEHAVIOR_MAP[primary_cwe]
                whitelist_behaviors.update(profile.mandatory_behaviors)
                for behavior in profile.mandatory_behaviors:
                    mapped = BEHAVIOR_ATTACK_GRAPH.get(behavior)
                    if mapped:
                        whitelist_techs.update(mapped["techniques"])

            # Secondary CWEs: chỉ bổ sung behaviors (không thêm techniques)
            # để tránh inflate expected set với techniques không đặc trưng
            # cho exploit chain thực tế.
            for cwe in cwe_ids:
                if cwe == primary_cwe:
                    continue
                if cwe in CWE_BEHAVIOR_MAP:
                    profile = CWE_BEHAVIOR_MAP[cwe]
                    whitelist_behaviors.update(profile.mandatory_behaviors)

        # Merge: union (CAPEC bổ sung cho whitelist)
        combined_techs = capec_techs | whitelist_techs

        if combined_techs or whitelist_behaviors:
            # Xác định source
            if capec_techs and whitelist_techs:
                source: GroundTruthSource = "MIXED"
            elif capec_techs:
                source = "CAPEC"
            else:
                source = "WHITELIST"

            tactics: set[str] = set()
            for t in combined_techs:
                tactics.update(self._technique_to_tactic(t))
            return ExpectedTTPs(
                cve_id=cve_id,
                expected_cwes=frozenset(cwe_ids),
                expected_behaviors=frozenset(whitelist_behaviors),
                expected_techniques=frozenset(combined_techs),
                expected_tactics=frozenset(tactics),
                ground_truth_source=source,
                ground_truth_quality="PARTIAL",
            )

        # ----------------------------------------------------------------
        # Layer 4: UNKNOWN
        # ----------------------------------------------------------------
        return ExpectedTTPs(
            cve_id=cve_id,
            expected_cwes=frozenset(cwe_ids),
            expected_behaviors=frozenset(),
            expected_techniques=frozenset(),
            expected_tactics=frozenset(),
            ground_truth_source="UNKNOWN",
            ground_truth_quality="UNKNOWN",
        )

    # =================================================================
    # Contradiction detection (semantic penalty)
    # =================================================================

    # Network-only techniques - mâu thuẫn với local-only CVE (CVSS AV:L)
    _NETWORK_ONLY_TECHNIQUES: frozenset[str] = frozenset({
        "T1190",  # Exploit Public-Facing Application
        "T1133",  # External Remote Services
        "T1199",  # Trusted Relationship
        "T1566",  # Phishing
        "T1078",  # Valid Accounts (nếu remote)
        "T1071",  # Application Layer Protocol (network C2)
    })

    # Phishing-specific techniques
    _PHISHING_TECHNIQUES: frozenset[str] = frozenset({
        "T1566", "T1566.001", "T1566.002", "T1566.003",
        "T1598", "T1598.001", "T1598.002", "T1598.003",
    })

    def is_contradiction(self, technique: str, ctx: CveContext) -> bool:
        """Kiểm tra 1 technique có mâu thuẫn với CVE context hay không.

        Chỉ phạt extras thật sự vô lý với CVE - tránh Strict Penalty paradox
        (AI đúng hơn whitelist vẫn bị phạt 5%/cái).

        Rules (mở rộng được):
          1. Network-only techniques (T1190, T1133, ...) mâu thuẫn với
             CVSS AV:L (local-only)
          2. Phishing techniques (T1566, ...) mâu thuẫn với description
             nhắc tới local/hardware/physical access
          3. Pre-auth + remote-only techniques mâu thuẫn với description
             nhắc tới hardware/USB driver (không thể remote exploit)

        Args:
            technique: ATT&CK technique ID (e.g. 'T1190', 'T1566.001').
            ctx: CveContext bundle với description + cvss_vector.

        Returns:
            True nếu technique mâu thuẫn với context, False nếu hợp lý.
        """
        t = technique.upper().strip()
        if not t.startswith("T"):
            return False  # Không phải technique ID hợp lệ

        # Rule 1: Network-only technique vs local-only CVSS
        if ctx.is_local_only() and t in self._NETWORK_ONLY_TECHNIQUES:
            return True

        # Rule 2: Phishing technique vs hardware/physical CVE
        if ctx.has_local_hardware_context() and t in self._PHISHING_TECHNIQUES:
            return True

        # Rule 3: Remote exploit technique (T1190) vs explicit local context
        if ctx.has_local_hardware_context() and t == "T1190":
            return True

        return False

    # =================================================================
    # Helpers
    # =================================================================

    @staticmethod
    def _technique_to_tactic(technique: str) -> list[str]:
        """Map ATT&CK technique → list of Tactic IDs.

        Priority:
          1. Authoritative lookup từ `_attack_tactics_index` (data-driven từ
             MITRE ATT&CK STIX bundle, ~600+ techniques + 1000+ sub-techniques)
          2. Sub-technique fallback: T1071.001 → lookup as parent T1071
          3. Heuristic fallback (`_HEURISTIC_TACTIC_MAP`) khi JSON missing
             (CI/CD, offline dev) - covers ~20 techniques
          4. Trả [] nếu không tìm thấy

        Returns:
            List of Tactic IDs (vd ["TA0001"]). Empty nếu unknown.
        """
        if not technique:
            return []

        instance = OntologyManager._instance
        if instance is not None and instance._attack_tactics_index:
            # 1. Authoritative lookup
            if technique in instance._attack_tactics_index:
                return list(instance._attack_tactics_index[technique])
            # 2. Sub-technique fallback (T1071.001 → T1071)
            if "." in technique:
                parent = technique.split(".", 1)[0]
                if parent in instance._attack_tactics_index:
                    return list(instance._attack_tactics_index[parent])

        # 3. Heuristic fallback
        tactic = _HEURISTIC_TACTIC_MAP.get(technique)
        if tactic is None and "." in technique:
            parent = technique.split(".", 1)[0]
            tactic = _HEURISTIC_TACTIC_MAP.get(parent)
        return [tactic] if tactic else []


# Heuristic fallback - chỉ dùng khi attack_technique_to_tactic.json missing
# (CI/CD, offline dev). Production path: data-driven lookup từ MITRE STIX.
_HEURISTIC_TACTIC_MAP: dict[str, str] = {
    "T1190": "TA0001",  # Initial Access
    "T1133": "TA0001",
    "T1566": "TA0001",  # Phishing
    "T1078": "TA0001",  # Valid Accounts
    "T1210": "TA0008",  # Exploitation of Remote Services
    "T1059": "TA0002",  # Execution
    "T1059.004": "TA0002",
    "T1068": "TA0004",  # Privilege Escalation
    "T1548": "TA0004",
    "T1071": "TA0011",  # Command and Control
    "T1071.001": "TA0011",
    "T1105": "TA0011",  # Ingress Tool Transfer
    "T1083": "TA0007",  # File and Directory Discovery
    "T1046": "TA0007",  # Network Service Scanning (deprecated but still referenced)
    "T1505.003": "TA0003",  # Persistence (Web Shell)
    "T1574": "TA0004",
    "T1574.001": "TA0004",
    "T1027": "TA0005",  # Defense Evasion
    "T1027.006": "TA0005",
    "T1027.009": "TA0005",
    "T1564": "TA0005",
    "T1564.009": "TA0005",
    "T1020": "TA0010",  # Automated Exfiltration
    "T1114": "TA0009",  # Email Collection (Collection tactic, not Exfiltration)
}
