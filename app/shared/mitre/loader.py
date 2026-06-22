"""MITRE ATT&CK Enterprise STIX loader (dynamic whitelist).

Single source of truth cho ATT&CK techniques/subtechniques/tactics. Thay the
hardcoded frozenset trong attack_validator.py (~50% matrix) bang data that
auto-update tu MITRE CTI GitHub moi 7 ngay.

PUBLIC API
----------
MitreAttackWhitelist.get() -> MitreAttackWhitelist  # singleton
    .tactics              -> frozenset[str]            # 14 TA-codes
    .techniques           -> frozenset[str]            # parent T-codes only
    .subtechniques        -> frozenset[str]            # dotted T.codes only
    .all_techniques       -> frozenset[str]            # parent + sub (union)
    .is_known(tcode)      -> bool                      # parent OR sub
    .technique_to_tactics(tcode) -> list[str]          # reverse lookup
    .name_of(tcode)       -> str | None                # for logs
    .is_baseline_fallback -> bool                      # True khi STIX load fail

CACHE
-----
Local file: {mitre_cache_dir}/enterprise-attack.json
TTL: mitre_cache_ttl_seconds (default 7 days). Neu stale → re-fetch tu
raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json.

FALLBACK
--------
Khi network down HOẶC file cache corrupt HOẶC env CVE_TI_MITRE_OFFLINE=1
→ tra ve hardcoded baseline (~50% matrix, ATT&CK v15 subset).

CACHING POLICY CHO LOAD() vs REFRESH()
- .get() = load 1 lan (singleton), cache in-memory for process lifetime.
- .refresh() = force re-read from disk + network if stale.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any

from app.core.config import settings

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------

# STIX 2.1 attack-pattern object type. ATT&CK techniques (parent + sub) are
# modeled as attack-pattern; tactics are kill-chain phases (separate objects).
_STIX_ATTACK_PATTERN = "attack-pattern"
_STIX_KILL_CHAIN_PHASE = "kill-chain-phase"

# MITRE CTI GitHub raw URL (canonical source for ATT&CK STIX bundles).
# Filename is enterprise-attack.json (~30-50MB compressed JSON).
_ENTERPRISE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

# Regex matchers for ATT&CK IDs.
_TACTIC_RE = re.compile(r"^TA\d{4}$")            # TA0001..TA0043
_PARENT_TECH_RE = re.compile(r"^T\d{4}$")          # T1001..T1567 (no dot)
_SUBTECH_RE = re.compile(r"^T\d{4}\.\d{3}$")      # T1059.001..T1567.004

# HTTP timeout cho 1 STIX download (~30-50MB). Dat 60s cho slow networks.
_HTTP_TIMEOUT = 60.0

# User-Agent (MITRE rate-limits ua-less requests).
_USER_AGENT = "CVE-TI-Platform-MitreLoader/1.0 (+https://github.com/local/cve-ti)"


# ----------------------------------------------------------------------
# Hardcoded baseline (FALLBACK ONLY)
# ----------------------------------------------------------------------
# Used khi STIX bundle load fail (network down, file corrupt, env offline).
# Duoc thiet ke de cover ~50% ATT&CK matrix (parent + common sub) cho
# common adversary techniques. NOT meant to be exhaustive.

_BASELINE_TACTICS: frozenset[str] = frozenset({
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

_BASELINE_TECHNIQUES: frozenset[str] = frozenset({
    # Initial Access
    "T1189", "T1190", "T1133", "T1200", "T1566", "T1078",
    # Execution
    "T1059", "T1106", "T1053", "T1129", "T1072", "T1569", "T1204", "T1203",
    # Persistence
    "T1136", "T1543", "T1505", "T1547", "T1546", "T1574", "T1556", "T1137",
    # Privilege Escalation
    "T1068", "T1055", "T1548",
    # Defense Evasion
    "T1027", "T1070", "T1112", "T1562", "T1218", "T1222",
    # Credential Access
    "T1003", "T1110", "T1555", "T1212",
    # Discovery
    "T1087", "T1083", "T1057", "T1018", "T1518", "T1049", "T1046",
    # Lateral Movement
    "T1021", "T1570", "T1210",
    # Collection
    "T1005", "T1039", "T1025", "T1114", "T1115",
    # Command and Control
    "T1071", "T1090", "T1095", "T1572", "T1092", "T1105", "T1132", "T1008", "T1104",
    # Exfiltration
    "T1020", "T1030", "T1041", "T1048", "T1052", "T1567",
    # Impact
    "T1485", "T1486", "T1490", "T1499", "T1498", "T1491", "T1484", "T1482",
})

_BASELINE_SUBTECHNIQUES: frozenset[str] = frozenset({
    # T1059 Command and Scripting Interpreter
    "T1059.001", "T1059.002", "T1059.003", "T1059.004", "T1059.005",
    "T1059.006", "T1059.007", "T1059.008", "T1059.009", "T1059.010",
    # T1204 User Execution
    "T1204.001", "T1204.002",
    # T1078 Valid Accounts
    "T1078.001", "T1078.002", "T1078.003", "T1078.004",
    # T1505 Server Software Component
    "T1505.003",
    # T1574 Hijack Execution Flow
    "T1574.001", "T1574.002", "T1574.004", "T1574.005", "T1574.006", "T1574.007",
    # T1556 Modify Authentication Process
    "T1556.001", "T1556.002", "T1556.003", "T1556.004", "T1556.005", "T1556.006",
    # T1055 Process Injection
    "T1055.001", "T1055.002", "T1055.003", "T1055.004", "T1055.005",
    # T1548 Abuse Elevation Control Mechanism
    "T1548.001", "T1548.002", "T1548.003", "T1548.004", "T1548.005",
    # T1027 Obfuscated Files or Information
    "T1027.001", "T1027.002", "T1027.003", "T1027.004",
    # T1110 Brute Force
    "T1110.001", "T1110.002", "T1110.003", "T1110.004",
    # T1003 OS Credential Dumping
    "T1003.001",
    # T1021 Remote Services
    "T1021.001", "T1021.002", "T1021.003", "T1021.004", "T1021.005", "T1021.006",
    # T1071 Application Layer Protocol
    "T1071.001", "T1071.002", "T1071.003", "T1071.004",
    # T1499 Endpoint Denial of Service
    "T1499.001", "T1499.002", "T1499.003", "T1499.004",
    # T1498 Network Denial of Service
    "T1498.001", "T1498.002",
    # T1491 Defacement
    "T1491.001", "T1491.002",
})


# ----------------------------------------------------------------------
# MitreAttackWhitelist
# ----------------------------------------------------------------------


class MitreAttackWhitelist:
    """In-memory ATT&CK whitelist loaded from MITRE STIX bundle.

    Singleton via .get() (process-wide). All public attributes are frozenset
    for O(1) `in` checks. Re-load via .refresh() (rare; mostly for tests).
    """

    _instance: "MitreAttackWhitelist | None" = None
    _instance_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Singleton
    # ------------------------------------------------------------------

    @classmethod
    def get(cls) -> "MitreAttackWhitelist":
        """Return process-wide singleton. Load on first call."""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:  # double-checked
                    cls._instance = cls._load()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Drop the cached singleton (test helper). Next .get() will reload."""
        with cls._instance_lock:
            cls._instance = None

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(
        self,
        tactics: frozenset[str],
        techniques: frozenset[str],
        subtechniques: frozenset[str],
        technique_to_tactics: dict[str, list[str]],
        names: dict[str, str],
        is_baseline_fallback: bool,
        source: str,
    ) -> None:
        self.tactics = tactics
        self.techniques = techniques
        self.subtechniques = subtechniques
        self.all_techniques = techniques | subtechniques
        self._technique_to_tactics = technique_to_tactics
        self._names = names
        self.is_baseline_fallback = is_baseline_fallback
        self.source = source  # "stix" | "baseline" — for log/debug

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_known(self, tcode: str) -> bool:
        """True if `tcode` is a known tactic, parent technique, or subtechnique."""
        if not tcode:
            return False
        return tcode in self.tactics or tcode in self.all_techniques

    def is_subtechnique(self, tcode: str) -> bool:
        return tcode in self.subtechniques

    def technique_to_tactics(self, tcode: str) -> list[str]:
        """Return list of tactic IDs (TA-codes) that `tcode` belongs to.

        Empty list if not a known technique (or no tactic mapping available).
        """
        if tcode in self._technique_to_tactics:
            return list(self._technique_to_tactics[tcode])
        # Fallback: parent technique lookup (sub inherits parent's tactics).
        if "." in tcode:
            parent = tcode.split(".", 1)[0]
            return list(self._technique_to_tactics.get(parent, []))
        return []

    def name_of(self, tcode: str) -> str | None:
        return self._names.get(tcode)

    def refresh(self) -> None:
        """Force reload from disk + network if stale. Updates singleton in-place."""
        new_instance = self._load()
        with self._instance_lock:
            type(self)._instance = new_instance

    # ------------------------------------------------------------------
    # Loaders (classmethods — produce new MitreAttackWhitelist instances)
    # ------------------------------------------------------------------

    @classmethod
    def _load(cls) -> "MitreAttackWhitelist":
        """Try STIX load; fall back to baseline on any failure.

        Order:
        1. If env CVE_TI_MITRE_OFFLINE=1 (settings.mitre_offline) → baseline.
        2. Try local cache file (if fresh) → parse STIX.
        3. Try local cache file (if stale) → try refresh from network.
        4. If all fail → baseline with warning.
        """
        if settings.mitre_offline:
            logger.info(
                "[MitreAttackWhitelist] mitre_offline=True → using hardcoded baseline "
                "(%d tactics, %d techniques, %d subtechniques)",
                len(_BASELINE_TACTICS), len(_BASELINE_TECHNIQUES), len(_BASELINE_SUBTECHNIQUES),
            )
            return cls._baseline_instance(reason="mitre_offline=True")

        cache_path = cls._cache_path()
        if cache_path.exists():
            age = time.time() - cache_path.stat().st_mtime
            if age < settings.mitre_cache_ttl_seconds:
                # Fresh cache → try parse, fall back if corrupt.
                parsed = cls._parse_stix_file(cache_path)
                if parsed is not None:
                    logger.info(
                        "[MitreAttackWhitelist] loaded from cache (%s, age=%.1f days, "
                        "%d tactics, %d techniques, %d subtechniques)",
                        cache_path, age / 86400, len(parsed["tactics"]),
                        len(parsed["techniques"]), len(parsed["subtechniques"]),
                    )
                    return cls(**parsed, source="stix", is_baseline_fallback=False)
                logger.warning(
                    "[MitreAttackWhitelist] cache file corrupt (%s) → trying refresh",
                    cache_path,
                )
            else:
                logger.info(
                    "[MitreAttackWhitelist] cache stale (age=%.1f days) → refreshing",
                    age / 86400,
                )

        # Stale / missing / corrupt → try network refresh.
        if cls._refresh_from_network(cache_path):
            parsed = cls._parse_stix_file(cache_path)
            if parsed is not None:
                logger.info(
                    "[MitreAttackWhitelist] loaded from fresh download "
                    "(%d tactics, %d techniques, %d subtechniques)",
                    len(parsed["tactics"]),
                    len(parsed["techniques"]),
                    len(parsed["subtechniques"]),
                )
                return cls(**parsed, source="stix", is_baseline_fallback=False)

        # All attempts failed → baseline fallback.
        logger.warning(
            "[MitreAttackWhitelist] STIX load failed → using hardcoded baseline. "
            "Set CVE_TI_MITRE_OFFLINE=1 to silence this; check network for STIX bundle.",
        )
        return cls._baseline_instance(reason="load_failed")

    @classmethod
    def _baseline_instance(cls, reason: str) -> "MitreAttackWhitelist":
        # Build a tactic map from hardcoded knowledge. ATT&CK parent -> tactic
        # is well-known and stable; we can hardcode the parent-level map.
        parent_tactic_map = _build_baseline_parent_tactic_map()
        names = _build_baseline_names()
        return cls(
            tactics=_BASELINE_TACTICS,
            techniques=_BASELINE_TECHNIQUES,
            subtechniques=_BASELINE_SUBTECHNIQUES,
            technique_to_tactics=parent_tactic_map,
            names=names,
            is_baseline_fallback=True,
            source="baseline",
        )

    # ------------------------------------------------------------------
    # File I/O
    # ------------------------------------------------------------------

    @staticmethod
    def _cache_path() -> Path:
        return Path(settings.mitre_cache_dir) / "enterprise-attack.json"

    @staticmethod
    def _parse_stix_file(path: Path) -> dict[str, Any] | None:
        """Parse MITRE STIX 2.1 enterprise-attack.json.

        Returns dict with keys: tactics, techniques, subtechniques,
        technique_to_tactics, names. Returns None on any parse error.
        """
        try:
            with open(path, encoding="utf-8") as f:
                bundle = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("[MitreAttackWhitelist] failed to read/parse %s: %s", path, exc)
            return None

        objects = bundle.get("objects") if isinstance(bundle, dict) else None
        if not isinstance(objects, list):
            logger.warning("[MitreAttackWhitelist] invalid STIX bundle: no 'objects' list")
            return None

        # 1. Tactic objects: phase_name → TA-code (from external_references)
        # Tactic STIX: x_mitre_shortname e.g. "initial-access", external_id e.g. "TA0001"
        tactic_shortname_to_id: dict[str, str] = {}
        tactic_id_to_shortname: dict[str, str] = {}
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            if obj.get("x_mitre_domains") and "enterprise-attack" in obj.get("x_mitre_domains", []):
                for ref in obj.get("external_references", []) or []:
                    eid = ref.get("external_id", "")
                    if _TACTIC_RE.match(eid):
                        tactic_shortname = obj.get("x_mitre_shortname", "")
                        tactic_shortname_to_id[tactic_shortname] = eid
                        tactic_id_to_shortname[eid] = obj.get("name", eid)
                        break

        # 2. attack-pattern objects: extract techniques + subtechniques + tactic mapping
        techniques: set[str] = set()
        subtechniques: set[str] = set()
        technique_to_tactics: dict[str, list[str]] = {}
        names: dict[str, str] = {}

        for obj in objects:
            if not isinstance(obj, dict):
                continue
            if obj.get("type") != _STIX_ATTACK_PATTERN:
                continue
            # Skip revoked / deprecated attack patterns
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue

            # Find the T-code from external_references
            tcode: str | None = None
            for ref in obj.get("external_references", []) or []:
                eid = ref.get("external_id", "")
                if _SUBTECH_RE.match(eid) or _PARENT_TECH_RE.match(eid):
                    tcode = eid
                    break
            if not tcode:
                continue

            # Bucket by type
            if _SUBTECH_RE.match(tcode):
                subtechniques.add(tcode)
            elif _PARENT_TECH_RE.match(tcode):
                techniques.add(tcode)
            else:
                continue

            names[tcode] = obj.get("name", tcode)

            # Map technique → tactics via kill_chain_phases
            tactic_ids: list[str] = []
            for phase in obj.get("kill_chain_phases", []) or []:
                if phase.get("kill_chain_name") == "mitre-attack":
                    shortname = phase.get("phase_name", "")
                    ta = tactic_shortname_to_id.get(shortname)
                    if ta:
                        tactic_ids.append(ta)
            if tactic_ids:
                technique_to_tactics[tcode] = tactic_ids

        # 3. Add tactic shortnames to names dict (for logs)
        names.update(tactic_id_to_shortname)

        if not techniques and not subtechniques:
            logger.warning("[MitreAttackWhitelist] parsed 0 techniques from %s", path)
            return None

        return {
            "tactics": frozenset(tactic_shortname_to_id.values()),
            "techniques": frozenset(techniques),
            "subtechniques": frozenset(subtechniques),
            "technique_to_tactics": technique_to_tactics,
            "names": names,
        }

    @classmethod
    def _refresh_from_network(cls, dest: Path) -> bool:
        """Download STIX bundle from MITRE CTI GitHub → `dest`.

        Returns True on success, False on any failure (network/parse/IO).
        Uses httpx (same as NVD provider). Atomic write via temp file.
        """
        try:
            import httpx  # local import — keep top-level imports lean
        except ImportError:
            logger.warning("[MitreAttackWhitelist] httpx not installed; cannot refresh STIX")
            return False

        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = dest.with_suffix(dest.suffix + ".tmp")
            with httpx.Client(
                timeout=_HTTP_TIMEOUT,
                follow_redirects=True,
                headers={"User-Agent": _USER_AGENT},
            ) as client:
                with client.stream("GET", _ENTERPRISE_ATTACK_URL) as response:
                    response.raise_for_status()
                    with open(tmp_path, "wb") as out:
                        for chunk in response.iter_bytes(chunk_size=64 * 1024):
                            out.write(chunk)
            # Atomic rename to avoid leaving partial file on crash.
            os.replace(tmp_path, dest)
            size_mb = dest.stat().st_size / (1024 * 1024)
            logger.info(
                "[MitreAttackWhitelist] downloaded STIX bundle: %s (%.1f MB)",
                dest, size_mb,
            )
            return True
        except Exception as exc:
            logger.warning(
                "[MitreAttackWhitelist] network refresh failed: %s", exc,
            )
            # Best-effort cleanup of temp file.
            tmp_path = dest.with_suffix(dest.suffix + ".tmp")
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
            except OSError:
                pass
            return False


# ----------------------------------------------------------------------
# Baseline tactic mapping (used only when STIX load fails)
# ----------------------------------------------------------------------


def _build_baseline_parent_tactic_map() -> dict[str, list[str]]:
    """Hardcoded parent-technique → tactic mapping for fallback only.

    Based on ATT&CK v15 (subset matching _BASELINE_TECHNIQUES). Used ONLY
    when STIX bundle load fails. Subtechniques inherit parent's tactics
    via MitreAttackWhitelist.technique_to_tactics() (which checks parent).
    """
    return {
        # Initial Access
        "T1189": ["TA0001"], "T1190": ["TA0001"], "T1133": ["TA0001"],
        "T1200": ["TA0001"], "T1566": ["TA0001"], "T1078": ["TA0001", "TA0003", "TA0004", "TA0005"],
        # Execution
        "T1059": ["TA0002"], "T1106": ["TA0002"], "T1053": ["TA0002", "TA0003"],
        "T1129": ["TA0002"], "T1072": ["TA0002"], "T1569": ["TA0002"],
        "T1204": ["TA0002"], "T1203": ["TA0002"],
        # Persistence
        "T1136": ["TA0003"], "T1543": ["TA0003", "TA0004"],
        "T1505": ["TA0003"], "T1547": ["TA0003", "TA0004"],
        "T1546": ["TA0003", "TA0004"], "T1574": ["TA0003", "TA0004"],
        "T1556": ["TA0003", "TA0006"], "T1137": ["TA0003"],
        # Privilege Escalation
        "T1068": ["TA0004"], "T1055": ["TA0004"], "T1548": ["TA0004"],
        # Defense Evasion
        "T1027": ["TA0005"], "T1070": ["TA0005"], "T1112": ["TA0005"],
        "T1562": ["TA0005"], "T1218": ["TA0005"], "T1222": ["TA0005"],
        # Credential Access
        "T1003": ["TA0006"], "T1110": ["TA0006"], "T1555": ["TA0006"], "T1212": ["TA0006"],
        # Discovery
        "T1087": ["TA0007"], "T1083": ["TA0007"], "T1057": ["TA0007"],
        "T1018": ["TA0007"], "T1518": ["TA0007"], "T1049": ["TA0007"], "T1046": ["TA0007"],
        # Lateral Movement
        "T1021": ["TA0008"], "T1570": ["TA0008"], "T1210": ["TA0008"],
        # Collection
        "T1005": ["TA0009"], "T1039": ["TA0009"], "T1025": ["TA0009"],
        "T1114": ["TA0009"], "T1115": ["TA0009"],
        # Command and Control
        "T1071": ["TA0011"], "T1090": ["TA0011"], "T1095": ["TA0011"],
        "T1572": ["TA0011"], "T1092": ["TA0011"], "T1105": ["TA0011"],
        "T1132": ["TA0011"], "T1008": ["TA0011"], "T1104": ["TA0011"],
        # Exfiltration
        "T1020": ["TA0010"], "T1030": ["TA0010"], "T1041": ["TA0010"],
        "T1048": ["TA0010"], "T1052": ["TA0010"], "T1567": ["TA0010"],
        # Impact
        "T1485": ["TA0040"], "T1486": ["TA0040"], "T1490": ["TA0040"],
        "T1499": ["TA0040"], "T1498": ["TA0040"], "T1491": ["TA0040"],
        "T1484": ["TA0040"], "T1482": ["TA0040"],
    }


def _build_baseline_names() -> dict[str, str]:
    """Short names for baseline techniques (used by .name_of() in fallback)."""
    return {
        "TA0001": "Initial Access", "TA0002": "Execution", "TA0003": "Persistence",
        "TA0004": "Privilege Escalation", "TA0005": "Defense Evasion",
        "TA0006": "Credential Access", "TA0007": "Discovery",
        "TA0008": "Lateral Movement", "TA0009": "Collection",
        "TA0010": "Exfiltration", "TA0011": "Command and Control",
        "TA0040": "Impact", "TA0042": "Resource Development",
        "TA0043": "Reconnaissance",
        "T1190": "Exploit Public-Facing Application",
        "T1059": "Command and Scripting Interpreter",
        "T1210": "Exploitation of Remote Services",
        "T1071": "Application Layer Protocol",
        "T1078": "Valid Accounts",
        "T1068": "Exploitation for Privilege Escalation",
        "T1021": "Remote Services",
    }
