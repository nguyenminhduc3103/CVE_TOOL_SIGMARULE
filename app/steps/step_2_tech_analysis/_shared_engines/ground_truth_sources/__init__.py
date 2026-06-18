"""Ground truth sources cho Step 2 - ontology expansion layer.

Layer 1 (CTID): center-for-threat-informed-defense/attack_to_cve
  - File: cti_mappings.csv (MITRE, 836 CVEs direct mapped to ATT&CK)
  - Highest quality (CVE-level precision)

Layer 2 (CAPEC): mitre/cti/capec/2.1/stix-capec.json
  - File: capec_stix.json (CAPEC <-> CWE bridge -> ATT&CK)
  - CWE-level coverage: 149 CWEs have bridge to ATT&CK

Layer 3 (Whitelist): existing CWE_BEHAVIOR_MAP (8 core CWEs)
  - Hand-curated, highest confidence for our core CWE set

Layer 4 (UNKNOWN): honest fallback
  - None of the above layers have data
  - Don't fabricate ground truth, mark as UNKNOWN

Files in this directory are downloaded by fetch_ground_truth.py
(GitHub release artifacts) and loaded lazily by OntologyManager.
"""
