"""MITRE ATT&CK + CAPEC data loaders (dynamic whitelist + hint query).

Modules:
    loader     - MitreAttackWhitelist singleton. Loads MITRE ATT&CK Enterprise
                 STIX 2.1 bundle from local cache (or fetches from MITRE CTI
                 GitHub on stale). Falls back to a hardcoded baseline when
                 network is unavailable.
    capec_hint - query_capec_for_cwe(): given a CWE ID, returns up to N
                 CAPEC attack patterns as INSPIRATION hints for the AI prompt
                 (not as ground truth).
    fetch_stix - CLI entry point to download / refresh the STIX + CAPEC
                 bundles (e.g. `python -m app.shared.mitre.fetch_stix`).
"""
from app.shared.mitre.loader import MitreAttackWhitelist
from app.shared.mitre.capec_hint import query_capec_for_cwe

__all__ = ["MitreAttackWhitelist", "query_capec_for_cwe"]
