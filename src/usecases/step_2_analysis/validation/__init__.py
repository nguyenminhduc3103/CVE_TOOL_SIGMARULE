"""Validation sub-package cho Step 2 Technical Analysis.

Package này chứa Lớp 3 validation (External Ground Truth) của Step 2,
bổ sung sau 2 lớp nội bộ trong _validation.py (format + semantic).

Modules:
    whitelist_manager: OS-level whitelist filter (Windows + Linux)
    scoring:           Tính match rates, FP risk, verdict
    validate_stage:    run_validate_stage() — main entry point

Thiết kế: Nằm trong step_2_tech_analysis/ theo sơ đồ C4 (Validator
là cấu phần của Technical Analysis), được gọi từ TriageOrchestrator
sau khi run_step2_tech_analysis() hoàn thành.
"""
