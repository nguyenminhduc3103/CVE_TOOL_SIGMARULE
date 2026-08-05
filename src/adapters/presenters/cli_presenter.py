"""Rich-ish presenter cho full pipeline (Step 1 → 2 → 4 → 6).

ANSI VT100 (auto-enabled); box headers / aligned keys / status icons; no rich/colorama.
Public API: print_step1_triage / print_step2_analysis / print_step4_telemetry / print_step6_sigma / print_metadata_footer.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

# can be set in the project's .env file and reach os.getenv below.
try:
    from dotenv import load_dotenv

    _PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
    load_dotenv(_PROJECT_ROOT / ".env", override=False)
except Exception:
    pass


# --- ANSI helpers --------------------------------------------------------

def _enable_vt100() -> None:
    """Enable ANSI escape sequences on Windows console (best effort)."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x4
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x4)
    except Exception:
        pass


_ENABLE_COLOR = os.getenv("NO_COLOR", "") == ""
if _ENABLE_COLOR:
    _enable_vt100()


# Full-output mode: opt-in qua CVE_TI_FULL_OUTPUT=1 (env / .env).
# Tắt mọi truncate site trong file này. Default OFF = output như cũ.
_FULL_OUTPUT = os.getenv("CVE_TI_FULL_OUTPUT", "0").lower() in ("1", "true", "yes")


class _C:
    """ANSI color codes (empty nếu NO_COLOR set)."""
    RESET = "\033[0m" if _ENABLE_COLOR else ""
    BOLD = "\033[1m" if _ENABLE_COLOR else ""
    DIM = "\033[2m" if _ENABLE_COLOR else ""
    RED = "\033[31m" if _ENABLE_COLOR else ""
    GREEN = "\033[32m" if _ENABLE_COLOR else ""
    YELLOW = "\033[33m" if _ENABLE_COLOR else ""
    BLUE = "\033[34m" if _ENABLE_COLOR else ""
    MAGENTA = "\033[35m" if _ENABLE_COLOR else ""
    CYAN = "\033[36m" if _ENABLE_COLOR else ""
    WHITE = "\033[37m" if _ENABLE_COLOR else ""
    BG_RED = "\033[41m" if _ENABLE_COLOR else ""
    BG_GREEN = "\033[42m" if _ENABLE_COLOR else ""
    BG_BLUE = "\033[44m" if _ENABLE_COLOR else ""


# --- Generic primitives --------------------------------------------------

def _section_header(title: str, color: str = _C.CYAN) -> None:
    """Big section banner."""
    bar = "═" * 78
    print(f"\n{color}{bar}{_C.RESET}")
    print(f"{color}{_C.BOLD} {title}{_C.RESET}")
    print(f"{color}{bar}{_C.RESET}")


def _subsection(title: str, color: str = _C.BLUE) -> None:
    bar = "─" * 78
    print(f"\n{color}┌─ {title}{_C.RESET}")
    print(f"{color}│{_C.RESET}")


def _kv(key: str, value: Any, indent: int = 2, key_color: str = _C.BOLD) -> str:
    """Format key:value với aligned key column."""
    pad = " " * indent
    val_str = str(value) if value is not None else "(none)"
    return f"{pad}{key_color}{key:<22}{_C.RESET}{val_str}"


def _list_value(key: str, items: list | None, indent: int = 2) -> None:
    """Print a list với bullet, hoặc (none) nếu rỗng."""
    pad = " " * indent
    if not items:
        print(f"{pad}{_C.BOLD}{key:<22}{_C.RESET}{_C.DIM}(none){_C.RESET}")
        return
    print(f"{pad}{_C.BOLD}{key:<22}{_C.RESET}{len(items)} item(s)")
    for idx, item in enumerate(items, 1):
        item_str = str(item)
        # Truncate quá dài (disabled in full-output mode)
        if not _FULL_OUTPUT and len(item_str) > 70:
            item_str = item_str[:67] + "..."
        print(f"{pad}  {_C.DIM}{idx:>3}.{_C.RESET} {item_str}")


def _status(ok: bool, label: str) -> str:
    return f"{_C.GREEN}✓{_C.RESET} {label}" if ok else f"{_C.RED}✗{_C.RESET} {label}"


def _warn(label: str) -> str:
    return f"{_C.YELLOW}⚠{_C.RESET} {label}"


def _confidence_color(value: float | None) -> str:
    if value is None:
        return _C.DIM
    if value >= 0.8:
        return _C.GREEN
    if value >= 0.5:
        return _C.YELLOW
    return _C.RED


def _decision_color(decision: str | None) -> str:
    if not decision:
        return _C.DIM
    d = decision.upper()
    if "GO" in d and "NO" not in d:
        return _C.GREEN
    if "NO-GO" in d or "STOP" in d:
        return _C.RED
    return _C.YELLOW


# --- Step 1: Triage ------------------------------------------------------

def print_step1_triage(enriched: Any) -> None:
    core = enriched.core
    triage = enriched.triage

    _section_header(f"STEP 1 — TRIAGE & ENRICHMENT · {core.cve_id}", _C.CYAN)

    # CVE basics
    _subsection("CVE Snapshot")
    print(_kv("CVE ID:", core.cve_id))
    print(_kv("Severity:", core.severity or "(none)", indent=2))
    print(_kv("CVSS Score:", core.cvss_score or "(none)"))
    print(_kv("CVSS Vector:", core.cvss_vector or "(none)"))
    print(_kv("CWE IDs:", ", ".join(core.cwe_ids) if core.cwe_ids else "(none)"))
    products = core.affected_products or core.cpes or []
    _list_value("Products/CPEs:", products)

    # Threat intel
    _subsection("Threat Intelligence")
    in_kev_str = _status(bool(triage.in_kev), str(triage.in_kev))
    print(_kv("In KEV:", in_kev_str))
    ransomware_str = _status(bool(triage.ransomware_usage), str(triage.ransomware_usage))
    print(_kv("Ransomware:", ransomware_str))

    epss_str = f"{triage.epss_score:.4f} ({triage.epss_score * 100:.2f}%)" if triage.epss_score is not None else "(none)"
    print(_kv("EPSS:", epss_str))

    print(_kv("Public PoC:", _status(bool(triage.public_poc), str(triage.public_poc))))
    print(_kv("Observed ITW:", _status(bool(triage.observed_in_the_wild), str(triage.observed_in_the_wild))))
    _list_value("Threat Actors:", triage.threat_actors)
    _list_value("PoC References:", triage.poc_references)

    # Priority + decision
    _subsection("Priority & Decision")
    print(_kv("Capability:", triage.capability_assessment or "(none)"))
    priority_color = _C.GREEN if (triage.priority or "").upper() in ("HIGH", "CRITICAL") else _C.YELLOW
    print(f"  {_C.BOLD}{'Priority:':<22}{_C.RESET}{priority_color}{triage.priority or '(none)'}{_C.RESET}")
    print(_kv("Priority Score:", triage.priority_score or "(none)"))
    decision = triage.decision or "(none)"
    decision_color = _decision_color(decision)
    print(f"  {_C.BOLD}{'Decision:':<22}{_C.RESET}{decision_color}{_C.BOLD}{decision}{_C.RESET}")

    reason = (triage.decision_reason or "").strip()
    if reason:
        print(f"  {_C.BOLD}{'Reason:':<22}{_C.RESET}")
        reason_lines = reason.splitlines() if _FULL_OUTPUT else reason.splitlines()[:5]
        for line in reason_lines:
            print(f"  {line}")

    # Provider status
    if hasattr(enriched, "provider_status") and enriched.provider_status:
        _subsection("Provider Status")
        for name, status in enriched.provider_status.items():
            ok = status == "success"
            icon = _status(ok, status)
            print(f"  {_C.DIM}{name:6s}{_C.RESET}  {icon}")


# --- Step 2: Analysis + ATT&CK ------------------------------------------

def print_step2_analysis(enriched: Any) -> None:
    a = getattr(enriched, "analysis", None)
    if a is None:
        _section_header("STEP 2 — TECH ANALYSIS · skipped (no analysis)", _C.DIM)
        return

    _section_header(f"STEP 2 — TECH ANALYSIS · {enriched.core.cve_id}", _C.MAGENTA)

    # Round-2: 2-group layout — CVSS Deterministic + AI Behavior Analysis
    _subsection("CVSS Deterministic (from CVSS parser)")
    print(_kv("Exploit Vector:", a.exploit_vector or "(none)"))
    print(_kv("Pre-auth:", _status(bool(a.pre_auth), str(a.pre_auth))))
    print(_kv("Remote Expl.:", _status(bool(a.remote_exploitable), str(a.remote_exploitable))))
    print(_kv("Complexity:", a.exploit_complexity or "(none)"))
    print(_kv("User Interaction:", _status(bool(a.user_interaction_required), str(a.user_interaction_required))))

    _subsection("AI Behavior Analysis")
    print(_kv("Exec Surface:", a.execution_surface or "(none)"))
    print(_kv("Delivery:", a.delivery_vector or "(none)"))
    print(_kv("Confidence:", f"{_confidence_color(a.confidence)}{a.confidence:.2f}{_C.RESET}"))

    _list_value("Mandatory Behaviors:", a.mandatory_behaviors or [])
    _list_value("Evasive Indicators:", a.evasive_indicators or [])
    _list_value("Exploit Requirements:", a.exploit_requirements or [])
    _list_value("Reasoning:", a.reasoning or [])

    # ATT&CK Mapping (Phase 2A + Phase 2B)
    atk = getattr(enriched, "attack", None)
    if atk is not None:
        _subsection("ATT&CK Mapping")
        print(_kv("AI used:", _status(bool(atk.ai_used), str(atk.ai_used))))
        print(_kv("AI model:", atk.ai_model or "(none)"))
        print(_kv("AI retries:", atk.ai_retry_count))

        # Phase 2A: TTPs extracted
        _list_value("Tactics:", atk.tactics or [])
        _list_value("Techniques:", atk.techniques or [])
        _list_value("Sub-techniques:", atk.subtechniques or [])

        # Phase 2B: Chain Reasoning
        print(_kv("Is Attack Chain:", str(atk.is_attack_chain) if atk.is_attack_chain is not None else "(none)"))
        _list_value("Chain Reasoning:", getattr(atk, "chain_reasoning", None) or [])
        _list_value("Mapping Reasoning:", getattr(atk, "mapping_reasoning", None) or getattr(atk, "mapping_reasons", None) or [])
        print(_kv("Confidence:", atk.confidence_level or "(none)"))

        # Attack chain steps
        chain = getattr(atk, "attack_chain", None)
        if chain:
            _subsection("Attack Chain")
            for step in chain:
                if isinstance(step, dict):
                    print(f"  Step {step.get('step')}: {step.get('technique_id')} ({step.get('tactic_id')})")
                    desc = step.get('description', '')
                    if desc:
                        print(f"    {desc}")
                    reasoning = step.get('reasoning', '')
                    if reasoning:
                        print(f"    Reasoning: {reasoning}")

        # ATT&CK Summary — display-only partition (confirmed vs chain-derived).
        techniques_for_summary = getattr(atk, "techniques", None) or []
        chain_for_summary = getattr(atk, "attack_chain", None) or []
        if techniques_for_summary or chain_for_summary:
            confirmed, chain_derived = _partition_attack_techniques(atk)
            import json as _json
            summary = {
                "confirmed_techniques": confirmed,
                "chain_derived_techniques": chain_derived,
            }
            _subsection("ATT&CK Summary")
            print(_json.dumps(summary, indent=2))


def _partition_attack_techniques(atk: Any) -> tuple[list[str], list[str]]:
    """Partition attack techniques into confirmed vs chain-derived (display-only).

    Confirmed = attack.techniques; chain-derived = chain \\ mapping (no mutation).
    """
    techniques = list(getattr(atk, "techniques", []) or [])
    chain = getattr(atk, "attack_chain", None) or []

    chain_techs: list[str] = [
        step.get("technique_id")
        for step in chain
        if isinstance(step, dict) and step.get("technique_id")
    ]

    # Preserve original ordering of attack.techniques for the confirmed list.
    confirmed: list[str] = list(techniques)

    # Chain-derived = chain-only (preserves chain order, dedup keeps first hit).
    seen: set[str] = set(techniques)
    chain_derived: list[str] = []
    for tech in chain_techs:
        if tech not in seen:
            chain_derived.append(tech)
            seen.add(tech)

    return confirmed, chain_derived


# --- Step 4: Telemetry ---------------------------------------------------

def print_step4_telemetry(enriched: Any) -> None:
    t = getattr(enriched, "telemetry", None)
    if t is None:
        _section_header("STEP 4 — TELEMETRY PLAN · skipped", _C.DIM)
        return

    _section_header(f"STEP 4 — TELEMETRY PLAN · {enriched.core.cve_id}", _C.YELLOW)

    ai_model = getattr(t, "ai_model", None) or "(step4 model not set)"
    ai_used = bool(getattr(t, "ai_used", True))
    conf = getattr(t, "telemetry_confidence", None)

    _subsection("AI Service")
    print(_kv("AI used:", _status(ai_used, "yes" if ai_used else "no")))
    print(_kv("AI model:", str(ai_model)))
    if conf is not None:
        conf_color = _confidence_color(conf)
        print(
            f"  {_C.BOLD}{'Telemetry Confidence:':<22}{_C.RESET}"
            f"{conf_color}{conf:.2f}{_C.RESET}"
        )

    # Target environment
    te = getattr(t, "target_environment", None)
    if te is not None:
        _subsection("Target Environment")
        _list_value("Platforms:", list(getattr(te, "platforms", []) or []))
        _list_value("Deployment:", list(getattr(te, "deployment", []) or []))
        _list_value("App Types:", list(getattr(te, "application_types", []) or []))
        _list_value("Technologies:", list(getattr(te, "technologies", []) or []))
        _list_value("Special Env:", list(getattr(te, "special_environments", []) or []))

    # Detection axis
    da = getattr(t, "detection_axis", None)
    if da is not None:
        _subsection("Detection Axis")
        primary = getattr(da, "primary", None)
        secondary = list(getattr(da, "secondary", []) or [])
        print(_kv("Primary:", primary or "(none)"))
        if secondary:
            print(_kv("Secondary:", ", ".join(secondary)))
        else:
            print(_kv("Secondary:", "(none)"))

    # Detection strategy (free text)
    strategy = getattr(t, "detection_strategy", None)
    if strategy:
        _subsection("Detection Strategy")
        for line in str(strategy).splitlines() or [str(strategy)]:
            print(f"    {line}")

    # Correlation + gaps
    print(
        _kv(
            "Correlation:",
            _status(
                bool(getattr(t, "correlation_required", False)),
                "YES" if getattr(t, "correlation_required", False) else "NO",
            ),
        )
    )

    gap_severity = getattr(t, "gap_severity", None)
    gaps = list(getattr(t, "telemetry_gaps", []) or [])
    if gaps or gap_severity:
        _subsection("Telemetry Gaps")
        sev_color = {
            "high": _C.RED,
            "medium": _C.YELLOW,
            "low": _C.GREEN,
        }.get((gap_severity or "").lower(), _C.RESET)
        print(
            f"  {_C.BOLD}{'Gap severity:':<22}{_C.RESET}"
            f"{sev_color}{(gap_severity or 'unknown').upper()}{_C.RESET}"
        )
        if gaps:
            for idx, gap in enumerate(gaps, 1):
                gap_str = str(gap)
                if not _FULL_OUTPUT and len(gap_str) > 120:
                    gap_str = gap_str[:117] + "..."
                print(f"    {_C.DIM}{idx:>3}.{_C.RESET} {gap_str}")

    # Candidate features (stable / conditional / optional)
    cf = getattr(t, "candidate_features", None)
    if cf is not None:
        for tier, label, color in (
            ("stable", "Stable", _C.GREEN),
            ("conditional", "Conditional", _C.YELLOW),
            ("optional", "Optional", _C.DIM),
        ):
            tier_features = list(getattr(cf, tier, []) or [])
            _subsection(f"Candidate Features · {label} ({len(tier_features)})", color)
            if not tier_features:
                print(f"    {_C.DIM}(none){_C.RESET}")
                continue
            for idx, feat in enumerate(tier_features, 1):
                _format_candidate_feature(idx, feat)

    # Sigma Logsources — post-pass derived from candidate_features × platforms.
    sigma_ls = list(getattr(t, "sigma_logsources", []) or [])
    _subsection("Sigma Logsources", _C.MAGENTA)
    if not sigma_ls:
        print(f"    {_C.DIM}(none){_C.RESET}")
    else:
        print(f"    {_C.BOLD}{'Logsource entries:':<22}{_C.RESET}{len(sigma_ls)} item(s)")
        for idx, ls in enumerate(sigma_ls, 1):
            product = getattr(ls, "product", None)
            category = getattr(ls, "category", "?")
            allowed = getattr(ls, "allowed_fields", {}) or {}
            print(
                f"      {_C.DIM}{idx:>3}.{_C.RESET} "
                f"{{product: {_C.CYAN}{repr(product)}{_C.RESET}, "
                f"category: {_C.MAGENTA}{category!r}{_C.RESET}}}"
            )
            if allowed:
                print(f"        {_C.DIM}allowed_fields:{_C.RESET}")
                # Sort keys for stable CLI output, but operators stay in source order.
                for field_name in sorted(allowed.keys()):
                    ops = allowed[field_name]
                    ops_str = ", ".join(ops)
                    print(
                        f"          {_C.DIM}{field_name:<16}{_C.RESET}→ {ops_str}"
                    )
            else:
                print(f"        {_C.DIM}allowed_fields: (none){_C.RESET}")


def _format_candidate_feature(idx: int, feat: Any) -> None:
    """Render one CandidateFeature (new Step 4 shape)."""
    semantic = getattr(feat, "semantic", "?")
    concept = getattr(feat, "telemetry_concept", "?")
    evidence = list(getattr(feat, "evidence", []) or [])

    if not _FULL_OUTPUT and len(semantic) > 90:
        semantic = semantic[:87] + "..."
    print(
        f"    {_C.DIM}{idx:>3}.{_C.RESET} "
        f"{_C.CYAN}{concept}{_C.RESET} — {semantic}"
    )
    if evidence:
        ev_str = ", ".join(str(e) for e in evidence)
        if not _FULL_OUTPUT and len(ev_str) > 70:
            ev_str = ev_str[:67] + "..."
        print(f"        {_C.DIM}evidence:{_C.RESET} {ev_str}")


# --- Step 6: Sigma generation -------------------------------------------

def print_step6_sigma(result: Any, enriched: Any) -> None:
    if result is None:
        _section_header("STEP 6 — SIGMA GENERATION · skipped", _C.DIM)
        return

    cve_id = getattr(enriched.core, "cve_id", "CVE-UNKNOWN")
    _section_header(f"STEP 6 — SIGMA GENERATION · {cve_id}", _C.GREEN)

    # NOTE: PoC input comes from Step 1 nuclei crawl; consumed by Step 6 internally.
    # Skip the PoC Input section here (Step 1 already printed it).

    # --- Detections (architect v9: detection.id = "rule_N") ---
    detections = getattr(result, "detections", []) or []
    _subsection("Detections (semantic Step 6 plan)")
    print(_kv("AI model:", getattr(result, "ai_model", None) or "(none)"))
    print(_kv("Detection count:", len(detections)))
    if not detections:
        print(f"  {_C.YELLOW}⚠ No detections emitted by Step 6 AI.{_C.RESET}")
    else:
        for det in detections:
            det_id = getattr(det, "id", "?")
            rule = getattr(det, "rule", None)
            logsource = getattr(rule, "logsource", None) if rule else None
            ls_category = getattr(logsource, "category", "?") if logsource else "?"
            ls_product = getattr(logsource, "product", None) if logsource else None
            ls_label = f"{ls_category}/{ls_product}" if ls_product else ls_category
            level = getattr(rule, "level", "?") if rule else "?"
            level_color = (
                _C.RED if level == "critical"
                else _C.YELLOW if level in ("high", "medium")
                else _C.DIM
            )
            desc = getattr(rule, "description", "") if rule else ""
            desc_short = desc if _FULL_OUTPUT else _truncate(desc, 120)
            print(
                f"    {_C.DIM}{det_id:<8}{_C.RESET} "
                f"{level_color}{level.upper():<10}{_C.RESET} "
                f"{_C.BOLD}{ls_label:<24}{_C.RESET} {desc_short}"
            )
            selection = getattr(getattr(rule, "detection", None), "selection", []) if rule else []
            for sel in selection:
                sel_name = getattr(sel, "name", "?")
                sel_modifier = getattr(sel, "modifier", None)
                sel_value = getattr(sel, "value", "")
                mod_str = f"|{sel_modifier}" if sel_modifier else ""
                value_short = sel_value if _FULL_OUTPUT else _truncate(sel_value, 60)
                print(
                    f"             {_C.DIM}↳{_C.RESET} {sel_name}{mod_str} {_C.DIM}= {value_short}{_C.RESET}"
                )
                # Inline reasoning — schema moved `reason` into selection[]
                sel_reason = getattr(sel, "reason", None)
                if sel_reason:
                    reason_short = sel_reason if _FULL_OUTPUT else _truncate(sel_reason, 140)
                    print(f"             {_C.DIM}↳ {reason_short}{_C.RESET}")


            # Per-detection false positives (render bullet list after selections).
            fps = list(getattr(rule, "falsepositives", []) or []) if rule else []
            if fps:
                print(f"             {_C.DIM}False Positives:{_C.RESET}")
                for fp in fps:
                    print(f"               {_C.DIM}•{_C.RESET} {_truncate(fp, 120)}")
    # --- Correlations ---
    correlations = getattr(result, "correlations", []) or []
    _subsection("Correlations")
    if not correlations:
        print(f"  {_C.DIM}(none){_C.RESET}")
    else:
        for corr in correlations:
            corr_rule = getattr(corr, "rule", None)
            corr_body = getattr(corr_rule, "correlation", None) if corr_rule else None
            refs = getattr(corr_body, "rules", []) if corr_body else []
            ctype = getattr(corr_body, "type", "?") if corr_body else "?"
            window = getattr(corr_body, "window", None) if corr_body else None
            level = getattr(corr_rule, "level", "?") if corr_rule else "?"
            desc = getattr(corr_rule, "description", "") if corr_rule else ""
            window_str = f" · window={window}" if window else ""
            print(
                f"  {_C.DIM}•{_C.RESET} {level.upper():<10} "
                f"{ctype}{window_str} "
                f"→ {_C.BOLD}{', '.join(refs)}{_C.RESET}"
            )
            if desc:
                print(f"             {_C.DIM}{_truncate(desc, 140)}{_C.RESET}")
            # Structured reasoning: correlation_strategy + parameter_reasoning
            corr_reasoning = getattr(corr, "reasoning", None)
            if corr_reasoning:
                strategy = getattr(corr_reasoning, "correlation_strategy", "") or ""
                if strategy:
                    print(f"             {_C.DIM}↳ {_truncate(strategy, 200)}{_C.RESET}")
                for pr in getattr(corr_reasoning, "parameter_reasoning", []) or []:
                    pr_param = getattr(pr, "parameter", "?")
                    pr_value = getattr(pr, "value", "")
                    pr_reason = getattr(pr, "reason", "")
                    if pr_reason:
                        short = _truncate(pr_reason, 140)
                        print(
                            f"             {_C.DIM}↳ {pr_param}={pr_value}: {short}{_C.RESET}"
                        )
            # Back-compat: if reasoning is plain string (legacy shape), print as-is.
            elif isinstance(corr_reasoning, str) and corr_reasoning:
                print(f"             {_C.DIM}↳ {_truncate(corr_reasoning, 140)}{_C.RESET}")

    # --- Top-level reasoning ---
    top_reasoning = getattr(result, "reasoning", "") or ""
    if top_reasoning:
        _subsection("Reasoning")
        reasoning_short = top_reasoning if _FULL_OUTPUT else _truncate(top_reasoning, 480)
        for line in reasoning_short.splitlines():
            print(f"  {_C.DIM}{line}{_C.RESET}")


def _truncate(text: str | None, max_len: int = 200, suffix: str = "…") -> str:
    """Truncate text với suffix nếu vượt max_len. No-op khi _FULL_OUTPUT."""
    if not text:
        return ""
    if _FULL_OUTPUT:
        return str(text).strip()
    s = str(text).strip()
    if len(s) <= max_len:
        return s
    return s[: max_len - 1].rstrip() + suffix


def _level_color(level: str | None) -> str:
    lvl = (level or "").lower()
    if lvl == "critical":
        return _C.RED
    if lvl in ("high", "medium"):
        return _C.YELLOW
    return _C.DIM


def _print_logsource(logsource: dict | None) -> str:
    if not isinstance(logsource, dict):
        return "(none)"
    parts = []
    if logsource.get("product"):
        parts.append(f"product={logsource['product']}")
    if logsource.get("category"):
        parts.append(f"category={logsource['category']}")
    if logsource.get("service"):
        parts.append(f"service={logsource['service']}")
    return " ".join(parts) or "(none)"


def _print_rule_detail(idx: int, rule: Any) -> None:
    """Print Tier 1-3 + selection summary cho 1 Sigma rule."""
    meta = getattr(rule, "metadata", None)
    rule_id = getattr(meta, "id", "?") if meta else "?"
    rule_id_short = rule_id[:8] if rule_id and rule_id != "?" else "?"
    rule_level = getattr(meta, "level", "?") if meta else "?"
    rule_title = getattr(meta, "title", "?") if meta else "?"
    rule_status = getattr(meta, "status", "?") if meta else "?"
    rule_date = getattr(meta, "date", "?") if meta else "?"
    rule_author = getattr(meta, "author", "?") if meta else "?"
    rule_desc = getattr(meta, "description", "") if meta else ""
    rule_tags = getattr(meta, "tags", []) or []
    rule_refs = getattr(meta, "references", []) or []
    rule_fps = getattr(meta, "falsepositives", []) or []
    rule_related = getattr(meta, "related", []) or []

    level_color = _level_color(rule_level)

    # Header: idx · level · id_short
    print(f"  {_C.DIM}{idx:>3}.{_C.RESET} {level_color}{rule_level:<10}{_C.RESET} "
          f"{_C.BOLD}{rule_id_short}{_C.RESET} {_C.DIM}({rule_id}){_C.RESET}")
    print(f"       title:    {_C.DIM}'{rule_title}'{_C.RESET}")

    # Tier 1 — always show
    print(_kv("status:", rule_status, indent=7))
    print(_kv("date:", rule_date or "(none)", indent=7))
    print(_kv("author:", rule_author or "(none)", indent=7))
    print(_kv("logsource:", _print_logsource(getattr(rule, "logsource", None)), indent=7))

    detection = getattr(rule, "detection", None)
    condition = getattr(detection, "condition", "") if detection else ""
    print(_kv("condition:", condition or "(any match)", indent=7))

    # Tier 2 — only when non-empty
    if rule_desc:
        desc_truncated = _truncate(rule_desc, 200)
        first_line = desc_truncated.split("\n", 1)[0]
        print(_kv("description:", first_line, indent=7))
        if len(desc_truncated) >= 200 or "\n" in (rule_desc or ""):
            print(f"           {_C.DIM}({_truncate(rule_desc, 280)}){_C.RESET}")

    if rule_tags:
        print(_kv("tags:", ", ".join(rule_tags), indent=7))
    if rule_refs:
        # Show count + first 2 refs inline
        print(_kv("references:", f"{len(rule_refs)} url(s)", indent=7))
        for r_idx, ref in enumerate(rule_refs, 1):
            ref_short = _truncate(ref, 70)
            print(f"           {_C.DIM}{r_idx}.{_C.RESET} {ref_short}")
        if not _FULL_OUTPUT and len(rule_refs) > 3:
            print(f"           {_C.DIM}… (+{len(rule_refs) - 3} more){_C.RESET}")
    if rule_fps:
        print(_kv("false positives:", f"{len(rule_fps)} item(s)", indent=7))
        for fp_idx, fp in enumerate(rule_fps, 1):
            print(f"           {_C.DIM}{fp_idx}.{_C.RESET} {_truncate(fp, 70)}")
        if not _FULL_OUTPUT and len(rule_fps) > 3:
            print(f"           {_C.DIM}… (+{len(rule_fps) - 3} more){_C.RESET}")
    if rule_related:
        print(_kv("related:", f"{len(rule_related)} link(s)", indent=7))

    # Tier 3 — correlation (gated by x_correlation_required)
    if getattr(rule, "x_correlation_required", False):
        corr_logic = getattr(rule, "x_correlation_logic", False)
        corr_reasoning = getattr(rule, "x_correlation_reasoning", "") or ""
        secondary = getattr(rule, "x_secondary_logsources", []) or []
        print(f"       {_C.MAGENTA}{_C.BOLD}⟶ CORRELATION rule{_C.RESET}")
        print(_kv("  parent logic:", _status(bool(corr_logic), str(corr_logic)), indent=7))
        if corr_reasoning:
            print(_kv("  reasoning:", _truncate(corr_reasoning, 200), indent=7))
        if secondary:
            print(_kv("  secondary logs:", ", ".join(secondary), indent=7))

    # Selection summary (only if rule has selections — skip for correlation parents)
    selections = getattr(detection, "selections", {}) if detection else {}
    if selections:
        print(f"       {_C.BOLD}selection logic:{_C.RESET} {len(selections)} selection(s)")
        for sel_name, sel_fields in selections.items():
            n_fields = len(sel_fields)
            field_names = list(sel_fields.keys())
            shown = field_names if _FULL_OUTPUT else field_names[:5]
            fields_str = ", ".join(shown)
            if not _FULL_OUTPUT and len(field_names) > 5:
                fields_str += f" {_C.DIM}(+{len(field_names) - 5} more){_C.RESET}"
            print(f"           {_C.DIM}{sel_name:<20}{_C.RESET} "
                  f"{n_fields} field(s): {fields_str}")
    elif getattr(rule, "x_correlation_required", False):
        # Correlation parent — empty selections is expected
        print(f"       {_C.DIM}(parent rule — no selections, condition từ sub-rules){_C.RESET}")


# --- Footer --------------------------------------------------------------

def print_metadata_footer(enriched: Any, total_ms: int) -> None:
    cve_id = getattr(enriched.core, "cve_id", "CVE-UNKNOWN")
    ai_models: set[str] = set()
    for attr in ("analysis", "attack", "telemetry"):
        obj = getattr(enriched, attr, None)
        if obj is None:
            continue
        model = getattr(obj, "ai_model", None)
        if model:
            ai_models.add(model)

    print()
    bar = "═" * 78
    print(f"{_C.DIM}{bar}{_C.RESET}")
    print(f"{_C.BOLD} Pipeline complete: {cve_id} · {total_ms:,} ms{_C.RESET}")
    if ai_models:
        print(f" AI models used: {', '.join(sorted(ai_models))}")
    else:
        print(f" AI models used: {_C.DIM}(none — rule-based only){_C.RESET}")
    print(f"{_C.DIM}{bar}{_C.RESET}\n")