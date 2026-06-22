"""OntologyManager - 2-Layer Truth Resolver (Single Source of Truth cho expected TTP).

Vấn đề trước kia (4-Layer):
- 2 hàm compute_ground_truth() và map_attack() dùng 2 bảng mapping khác nhau
  → AI bị so sánh với ground truth không nhất quán (Source of Truth Mismatch)
- Nếu CWE không có trong whitelist 8 CWE → expected_behaviors rỗng
  → compute_coverage chia 0 → fallback 1.0 (100% giả tạo, "Coverage Hallucination")
- Extra techniques bị phạt 5%/cái kể cả khi hợp lệ với CVE context
  (Strict Penalty paradox: AI bị phạt vì... đúng hơn whitelist)
- Layer 1+2 (CTID + CAPEC) proven "CAPEC union quá rộng" qua test_ai_coverage
  → consumer (compute_coverage, gap_analysis) đã bị gỡ → 2 layer trở thành
  dead code, nhưng vẫn load 4.3MB+34KB mỗi lần import

Giải pháp 2-Layer Fallback (sau refactor Phase 3):
  Layer 3: Whitelist 8 CWE (single source)
  Layer 4: UNKNOWN (honest fallback - không fabricate ground truth)

API giữ nguyên 100% (attack_mapper.py:153,215, run_step2_tech_analysis path
đều dùng .resolve() + ._technique_to_tactic() → backward compat).

ATT&CK technique→tactic mapping delegate sang MitreAttackWhitelist dynamic
loader (MITRE STIX, ~95%+ matrix, 7-day cache, fallback hardcode nếu
network down). Không còn load file JSON local.
"""
from __future__ import annotations

import logging
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
# Dùng lazy import trong resolve() để tránh vòng lặp.

logger = logging.getLogger(__name__)

# Quality enum cho ground truth resolution
# Source giữ "CTID", "CAPEC" trong enum cho backward compat (code cũ có thể
# check equality) - nhưng runtime chỉ emit "WHITELIST" hoặc "UNKNOWN".
GroundTruthSource = Literal["CTID", "CAPEC", "WHITELIST", "MIXED", "UNKNOWN"]
GroundTruthQuality = Literal["HIGH", "PARTIAL", "UNKNOWN"]


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
    """2-Layer Truth Resolver - resolve CVE → expected TTP.

    Singleton-friendly: instance có thể share giữa attack_mapper để đảm bảo
    cùng source. Sau refactor Phase 3, không còn load offline data → instance
    creation gần như zero-cost (~<1ms).

    Example:
        >>> mgr = OntologyManager()
        >>> ctx = CveContext(cve_id="CVE-2021-44228", cwe_ids=("CWE-502",), ...)
        >>> expected = mgr.resolve(ctx)
        >>> expected.expected_techniques
        frozenset({'T1059', 'T1190'})
        >>> expected.ground_truth_quality
        'PARTIAL'  # vì layer 3 whitelist
    """

    # Singleton state (per-class, để test có thể reset nếu cần)
    _instance: "OntologyManager | None" = None

    def __new__(cls) -> "OntologyManager":
        # Singleton - tránh khởi tạo nhiều lần trong 1 process
        if cls._instance is None:
            inst = super().__new__(cls)
            inst._initialized = False
            cls._instance = inst
        return cls._instance

    def __init__(self) -> None:
        if getattr(self, "_initialized", False):
            return
        self._initialized = True
        # ATT&CK technique → tactic(s) lookup. Delegate sang MitreAttackWhitelist
        # singleton (STIX dynamic, ~95%+ matrix) thay vì file JSON local.
        # Backward-compat: _technique_to_tactic() vẫn là public API.
        from app.shared.mitre.loader import MitreAttackWhitelist
        self._attack_whitelist = MitreAttackWhitelist.get()
        logger.debug(
            "OntologyManager initialized (2-layer): %d tactics, %d techniques, "
            "%d subtechniques from MITRE STIX (source=%s)",
            len(self._attack_whitelist.tactics),
            len(self._attack_whitelist.techniques),
            len(self._attack_whitelist.subtechniques),
            self._attack_whitelist.source,
        )

    def reset(self) -> None:
        """Reset singleton (chỉ dùng cho test)."""
        OntologyManager._instance = None
        self._initialized = False

    # =================================================================
    # 2-Layer Resolution
    # =================================================================

    def resolve(self, ctx: CveContext) -> ExpectedTTPs:
        """Resolve CVE → expected TTP sử dụng 2-layer fallback chain.

        Layer 3: Whitelist 8 CWE (single source of truth)
            - CWE có trong CWE_BEHAVIOR_MAP → derive từ behaviors
            - Dùng BEHAVIOR_ATTACK_GRAPH để map behaviors → techniques
            - quality = PARTIAL
        Layer 4: UNKNOWN
            - CWE không có trong whitelist → trả sets rỗng + quality UNKNOWN

        Lý do không còn Layer 1+2 (CTID/CAPEC):
        - CTID (CVE-level) chỉ cover ~836 CVEs (~2% tổng CVE trong NVD).
          Coverage quá thấp → miss hầu hết CVE mới.
        - CAPEC union proven "quá rộng" qua test_ai_coverage (Hướng D):
          AI luôn FAIL dù phân tích đúng. Data này không còn consumer
          downstream (compute_ground_truth, gap_analysis đã bị xóa ở turn
          trước).
        - Layer 3 whitelist (8 CWE phổ biến) đủ cho rule-based fallback path.

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
        # chúng không phải CWE thật, không có trong WHITELIST, sẽ làm
        # PRIMARY CWE selection rơi vào placeholder.
        cwe_ids = tuple(
            c.upper() for c in (ctx.cwe_ids or ())
            if not c.upper().startswith("NVD-CWE")
        )

        # ----------------------------------------------------------------
        # Layer 3: Whitelist fallback (8 core CWE)
        # ----------------------------------------------------------------
        # CHỐNG MULTI-CWE INFLATION:
        # - Chọn PRIMARY CWE = CWE đầu tiên có trong CWE_BEHAVIOR_MAP
        # - PRIMARY CWE quyết định techniques chính (anchor).
        # - Secondary CWEs chỉ BỔ SUNG behaviors (không inflate techniques).
        primary_cwe: str | None = None
        for cwe in cwe_ids:
            if cwe in CWE_BEHAVIOR_MAP:
                primary_cwe = cwe
                break
        # Fallback: nếu không match whitelist, dùng CWE đầu tiên (vẫn ưu tiên
        # thứ tự CWE IDs mà NVD cung cấp)
        if primary_cwe is None and cwe_ids:
            primary_cwe = cwe_ids[0]

        whitelist_techs: set[str] = set()
        whitelist_behaviors: set[str] = set()

        if primary_cwe:
            # PRIMARY CWE: lấy techniques đầy đủ từ Whitelist
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

        if whitelist_techs or whitelist_behaviors:
            tactics: set[str] = set()
            for t in whitelist_techs:
                tactics.update(self._technique_to_tactic(t))
            return ExpectedTTPs(
                cve_id=cve_id,
                expected_cwes=frozenset(cwe_ids),
                expected_behaviors=frozenset(whitelist_behaviors),
                expected_techniques=frozenset(whitelist_techs),
                expected_tactics=frozenset(tactics),
                ground_truth_source="WHITELIST",
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

    def _technique_to_tactic(self, technique: str) -> list[str]:
        """Map ATT&CK technique → list of Tactic IDs.

        Delegate sang MitreAttackWhitelist (STIX dynamic, ~95%+ matrix).
        Sub-technique fallback: T1071.001 → lookup as parent T1071.

        Returns:
            List of Tactic IDs (vd ["TA0001"]). Empty nếu unknown.
        """
        if not technique:
            return []

        return self._attack_whitelist.technique_to_tactics(technique)
