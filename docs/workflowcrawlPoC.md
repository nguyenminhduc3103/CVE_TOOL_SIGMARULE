                             ┌────────────────────────┐
                             │        CVE ID          │
                             └───────────┬────────────┘
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 ▼                                               ▼
   ┌───────────────────────────┐                   ┌───────────────────────────┐
   │ NHÁNH 1: PoC Repositories │                   │ NHÁNH 2: Telemetry Repos  │
   │ (GitHub / nomi-sec / NVD) │                   │ (OTRF/Mordor/Splunk/EVTX) │
   └─────────────┬─────────────┘                   └─────────────┬─────────────┘
                 │                                               │
                 ▼                                               ▼
   [Mục tiêu: Hiểu Kỹ Thuật]                         [Mục tiêu: Kéo Log Thật]
   - Parse README, writeup, docs                     - Quét tệp .evtx, .json, .log
   - Parse Code / Payloads (.py, .sh)                - Giải mã .evtx trực tiếp trong RAM
   - Trích ra: ATT&CK Technique ID                   - Lọc Event ID (1, 3, 11, 4688)
   - Trích ra: Target Process & Keywords                         │
                 │                                               │
                 └───────────────────────┬───────────────────────┘
                                         ▼
                         ┌───────────────────────────────┐
                         │   TELEMETRY HYBRID MATCHER    │
                         │ (3 Cấp Ưu Tiên Tìm Kiếm Log)  │
                         └───────────────┬───────────────┘
                                         ▼
                         ┌───────────────────────────────┐
                         │   SCORING & LABELING ENGINE   │
                         │ (Phân Hạng & Đánh Nhãn Log)   │
                         └───────────────┬───────────────┘
                                         ▼
                         ┌───────────────────────────────┐
                         │   ANTI-HALLUCINATION PROMPT   │
                         │ (Cung Cấp Context Cho AI)     │
                         └───────────────┬───────────────┘
                                         ▼
                         ┌───────────────────────────────┐
                         │       OUTPUT SIGMA RULE       │
                         └───────────────────────────────┘


Luồng tìm kiếm
Ưu tiên 1 (Technique + Keyword ──▶ Telemetry): Tìm log vừa thuộc T1059 AND vừa chứa tiến trình/payload đặc thù (vd: msiexec.exe /i).
Ưu tiên 2 (Keyword ──▶ Telemetry): Nếu CVE không có ATT&CK rõ ràng, tìm trực tiếp theo tên tiến trình (msiexec.exe), chuỗi payload (${jndi:), hoặc tên ứng dụng.
Ưu tiên 3 (Technique ──▶ Telemetry Broad Fallback): Chỉ dùng làm phương án dự phòng cuối cùng khi không tìm thấy bất kỳ Keyword cụ thể nào.