"""Constants for Step 2 - Technical & ATT&CK Analyzer.

Single source of truth cho các hằng số dùng chung giữa orchestrator
và retry (tránh circular import).
"""

# Retry budget: tối đa số retry attempts khi AI coverage chưa đạt.
# 3 = đủ cho 1 attempt chính + 3 corrections (giảm runaway, tăng coverage).
MAX_RETRIES = 3
