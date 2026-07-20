"""Ground Truth adapters — interface layer cho Task 4 Validate Stage.

Package này cung cấp API mỏng bọc ngoài OntologyManager (singleton đã
có sẵn trong step_2_tech_analysis/rule_based/). Không tải lại data,
chỉ đóng gói interface để validate_stage.py dùng.

Modules:
    ground_adapter: CVE-ID + CWE-IDs → GroundTruthProfile (4-layer resolver)
"""
