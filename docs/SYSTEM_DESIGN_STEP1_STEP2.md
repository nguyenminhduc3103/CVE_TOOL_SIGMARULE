# TÀI LIỆU ĐẶC TẢ THIẾT KẾ HỆ THỐNG (SYSTEM DESIGN SPECIFICATION)
## GIAI ĐOẠN 1: BƯỚC 1 (TRIAGE & ENRICHMENT) & BƯỚC 2 (TECHNICAL ANALYSIS & ATT&CK MAPPING)

> [!NOTE]
> Tài liệu mô tả chi tiết kiến trúc thiết kế, luồng dữ liệu, cơ chế hoạt động và tiêu chuẩn tích hợp công nghệ cho Giai đoạn 1 của hệ thống **CVE Threat Intelligence Platform** (bao gồm **Bước 1** và **Bước 2**). 
> - **Đầu vào**: CVE ID hoặc luồng Ingestion tự động 5 CVE từ OpenCTI TAXII.
> - **Đầu ra**: Dữ liệu đã làm giàu (`CoreCVEData`), phân loại ưu tiên (`TriageContext`), phân tích hành vi kỹ thuật (`TechnicalAnalysis`), và ánh xạ chiến thuật tấn công (`AttackMapping`).

---

## 1. KIẾN TRÚC TỔNG QUAN (SYSTEM ARCHITECTURE)

Hệ thống được thiết kế theo mô hình **Clean Architecture** kết hợp thiết kế hướng module, phân tách rõ ràng trách nhiệm giữa các lớp dữ liệu và lớp xử lý logic.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        LAYER 1: INGESTION LAYER                        │
│  ┌───────────────────────┐             ┌────────────────────────────┐  │
│  │  OpenCTI TAXII Server  │             │     Manual CVE Input       │  │
│  └───────────┬───────────┘             └─────────────┬──────────────┘  │
│              │ (Fetch 5 CVEs)                        │                 │
│              ▼                                       ▼                 │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                        CLI / Test Script                         │  │
│  └───────────────────────────────────┬──────────────────────────────┘  │
└──────────────────────────────────────┼─────────────────────────────────┘
                                       │ (Triggers)
                                       ▼
┌──────────────────────────────────────┴─────────────────────────────────┐
│                   LAYER 2: CORE EXECUTION PIPELINE                     │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                        TriageOrchestrator                        │  │
│  └───────────┬───────────────────────────────────────┬──────────────┘  │
│              │ (Runs Step 1)                         │ (Runs Step 2)   │
│              ▼                                       ▼                 │
│  ┌───────────────────────────┐         ┌────────────────────────────┐  │
│  │     Step 1: Triage        │         │      Step 2: Behavior      │  │
│  │     & Enrichment          │         │          Analysis          │  │
│  └───────────┬───────────┘             └─────────────┬──────────────┘  │
└──────────────┼───────────────────────────────────────┼─────────────────┘
               │                                       │
               ▼                                       ▼
┌──────────────┴───────────────────────┐ ┌─────────────┴─────────────────┐
│  LAYER 3: EXTERNAL DATA PROVIDERS    │ │      LAYER 4: AI ENGINE       │
│  ┌───────────────┬────────────────┐  │ │  ┌─────────────────────────┐  │
│  │ NVD Provider  │ CISA KEV Prov. │  │ │  │    LLM API Endpoint     │  │
│  ├───────────────┼────────────────┤  │ │  │   (Universal Client)    │  │
│  │ EPSS Provider │ OTX Provider   │  │ │  └──────────┬──────────────┘  │
│  ├───────────────┴────────────────┤  │ │             ▼                 │
│  │          PoC Provider          │  │ │  ┌─────────────────────────┐  │
│  └────────────────────────────────┘  │ │  │    Validation Engine    │  │
└──────────────────────────────────────┘ │  │   (& Partial Retry)     │  │
                                         │  └──────────┬──────────────┘  │
                                         │             ▼                 │
                                         │  ┌─────────────────────────┐  │
                                         │  │   Rule-based Fallback   │  │
                                         │  └─────────────────────────┘  │
                                         └───────────────────────────────┘
```

---

## 2. BƯỚC 1: TRIAGE & ENRICHMENT (TIẾP NHẬN & LÀM GIÀU ĐA NGUỒN)

### 2.1 Luồng Thu Thập Dữ Liệu Tự Động Từ OpenCTI
Hệ thống tích hợp trực tiếp với OpenCTI TAXII 2.1 để thu thập các lỗ hổng bảo mật:
1. Kết nối qua `OpenCTIProvider` sử dụng URL, Token, Cookie và Collection ID cấu hình trong tệp `.env`.
2. Tải về gói dữ liệu thô (TAXII Bundle) với giới hạn thu thập **5 CVE** (`limit=5`).
3. Chuẩn hóa dữ liệu qua parser để trích xuất danh sách các CVE ID sẵn sàng đưa vào pipeline xử lý tuần tự.

### 2.2 Làm Giàu Thông Tin Đa Nguồn (Multi-Provider Enrichment)
Để thu thập toàn diện thông tin về lỗ hổng, hệ thống song song gọi đến 5 nhà cung cấp dữ liệu độc lập:

| Provider | Vai trò & Thông tin trích xuất | Đường dẫn mã nguồn |
|:---|:---|:---|
| **NVD Provider** | Lấy mô tả chi tiết, điểm số CVSS, Vector tấn công, mức độ nghiêm trọng (Severity), danh sách CPE và References. | [nvd/provider.py](file:///d:/CVE_TOOL_SIGMARULE/app/shared/providers/nvd/provider.py) |
| **KEV Provider** | Kiểm tra trạng thái bị khai thác trong thực tế (CISA KEV), ngày đưa vào danh mục, sự liên quan tới các chiến dịch ransomware. | [kev/provider.py](file:///d:/CVE_TOOL_SIGMARULE/app/shared/providers/kev/provider.py) |
| **EPSS Provider** | Lấy xác suất bị khai thác trong vòng 30 ngày tới (EPSS Score) và phân vị xếp hạng tương quan (EPSS Percentile). | [epss/provider.py](file:///d:/CVE_TOOL_SIGMARULE/app/shared/providers/epss/provider.py) |
| **OTX Provider** | Truy vấn AlienVault OTX để thu thập thông tin về các nhóm tấn công (Threat Actors) liên quan. | [otx/provider.py](file:///d:/CVE_TOOL_SIGMARULE/app/shared/providers/otx/provider.py) |
| **PoC Provider** | Thu thập các liên kết chứa mã khai thác mẫu (PoC) chất lượng từ các kho lưu trữ công cộng. | [poc/provider.py](file:///d:/CVE_TOOL_SIGMARULE/app/shared/providers/poc/provider.py) |

### 2.3 Cơ Chế Tự Phục Hồi Khi API Gặp Lỗi (OTX Fallback Mechanism)
Do API của NVD thường xuyên gặp lỗi quá tải (HTTP 503 Service Unavailable) hoặc Timeout, hệ thống thiết lập cơ chế **Fallback sang AlienVault OTX** tại phương thức `_build_core_context` của `TriageOrchestrator`:

```text
              [ Bắt đầu làm giàu dữ liệu ]
                           │
                           ▼
                  [ Truy vấn NVD API ]
                           │
                           ▼
               /───────────────────────────\
              <  NVD bị lỗi hoặc trống?     >
               \───────────────────────────/
                 /                       \
          (Có)  /                         \  (Không)
               ▼                           ▼
     [ Ghi nhận log fallback ]    [ Sử dụng dữ liệu NVD làm chính ]
               │                           │
               ▼                           │
   [ Trích xuất dữ liệu OTX ]              │
               │                           │
               ▼                           ▼
      /─────────────────────────────────────────\
     <       Kiểm tra thông tin bị thiếu?        >
      \─────────────────────────────────────────/
        │            │             │           │
   (Description)   (CVSS)        (CWE)   (CPE/Ref/Date)
        │            │             │           │
        ▼            ▼             ▼           ▼
   [ OTX Desc ] [ OTX CVSS ]  [ OTX CWE ] [ OTX CPEs/Refs ]
        │            │             │           │
        └────────────┼─────────────┼───────────┘
                     ▼
       [ Tổng hợp và sinh CoreCVEData ]
                     │
                     ▼
            [ Hoàn thành Bước 1 ]
```

### 2.4 Tiêu Chí Phân Loại & Quyết Định Triage (GO/NO-GO Rules)
Sau khi tổng hợp thông tin, hệ thống tự động đưa ra quyết định có đi tiếp vào Bước 2 để phân tích hay dừng lại:
* **Điều kiện GO (Tiếp tục xử lý)**:
  * Lỗ hổng nằm trong danh mục đang bị khai thác thực tế: `in_kev` là `True`.
  * **HOẶC** Phát hiện có mã khai thác công khai: `public_poc` là `True` (có link PoC từ PoC Provider hoặc có cờ `is_exploit` trong references).
  * **VÀ** Phải thỏa mãn đánh giá năng lực kiểm soát nội bộ (`capability_assessment` trả về `in_scope`).
* **Điều kiện NO-GO (Dừng xử lý)**:
  * Không nằm trong KEV và không có PoC công khai.
  * Hoặc vượt quá năng lực kiểm soát an toàn thông tin nội bộ (`out_of_scope`).

---

## 3. BƯỚC 2: TECHNICAL ANALYSIS & ATT&CK MAPPING

Quyết định **GO** ở Bước 1 sẽ kích hoạt Bước 2. Hệ thống gọi AI Agent để thực hiện phân tích sâu hành vi kỹ thuật của mã độc/lỗ hổng.

### 3.1 Tiêu Chuẩn Tích Hợp AI & Cấu Hình Động (Universal AI Client)
Để tránh phụ thuộc vào một nhà cung cấp AI duy nhất (Vendor Lock-in), lớp giao tiếp AI được trừu tượng hóa qua `BaseAIClient` tương thích chuẩn kết nối OpenAI API:
* Cấu hình dynamic qua file `.env`: `AI_BASE_URL` và `AI_MODEL`.
* Dễ dàng chuyển đổi linh hoạt giữa các dịch vụ API đám mây (Groq, OpenAI, Gemini) hoặc các mô hình mã nguồn mở chạy local (Ollama).

### 3.2 Luồng Logic Của AI Behavior Service
1. **Lắp ráp Prompt**: Lấy system prompt mẫu (`analyze_behavior.system.txt`), nhúng bộ luật ánh xạ kỹ thuật dùng chung (`_shared_mitre_rules.md`) và chèn dữ liệu CVE động của người dùng (`analyze_behavior.user.txt`).
2. **Gọi LLM**: Gửi yêu cầu phân tích kèm cấu hình model đã nạp.
3. **Làm sạch JSON**: AI bắt buộc phải phản hồi ở định dạng JSON thô. Hệ thống sử dụng regex loại bỏ các rào chắn markdown (markdown code fences như \`\`\`json ... \`\`\`) để chuẩn bị đưa vào bộ phân tích cú pháp.

### 3.3 Cơ Chế Xác Thực & Thử Lại Từng Phần (Validation & Partial-Fill Retry)
Hệ thống không tin cậy hoàn toàn kết quả trả về của AI mà áp dụng quy trình kiểm soát chất lượng nghiêm ngặt:

```text
                  [ Gọi AI phân tích ]
                           │
                           ▼
            [ Clean & Parse JSON thành Dict ]
                           │
                           ▼
         [ Validate các trường dữ liệu bắt buộc ]
                           │
                           ▼
               /───────────────────────────\
              <     Dữ liệu hợp lệ?         >
               \───────────────────────────/
                 /                       \
        (Đúng)  /                         \  (Sai)
               ▼                           ▼
    [ Chuyển sang Pydantic ]     /───────────────────────────\
               │                <     Số lần thử <= 3?       >
               ▼                 \───────────────────────────/
    [ Trả về kết quả Bước 2 ]      /                       \
               ▲            (Đúng)/                         \(Sai)
               │                 ▼                           ▼
               │          [ Tạo Payload sửa ]       [ Ghi nhận lỗi cạn kiệt ]
               │                 │                           │
               │                 ▼                           ▼
               │          [ Gọi AI Retry ]          [ Rule-based Fallback ]
               │                 │                           │
               │                 └───────────────────────────┤
               └─────────────────────────────────────────────┘
```

* **Quy tắc thử lại từng phần (Partial-fill)**: Nếu một vài trường dữ liệu không vượt qua được bộ lọc xác thực (ví dụ: `exploit_vector` không nằm trong danh mục cho phép, hoặc thiếu các hành vi bắt buộc), hệ thống chỉ yêu cầu AI sửa và bổ sung các trường bị sai/thiếu ở lượt gọi tiếp theo (tối đa 3 lần), giữ nguyên các trường đã hợp lệ để tiết kiệm thời gian và tài nguyên API.

### 3.4 Cơ Chế Dự Phòng (Rule-based Fallback)
Trong trường hợp xấu nhất (API của AI sập hoàn toàn, hết quota, hoặc AI liên tục trả dữ liệu lỗi sau 3 lần thử lại), hệ thống sẽ chuyển sang chế độ **Rule-based Fallback**:
* Sử dụng phương thức `_build_rule_based_pydantic` để tự động bóc tách các đặc trưng của CVE dựa trên thuật toán heuristic tĩnh (quét từ khóa trong mô tả, phân tích điểm số CVSS, ánh xạ CWE sang TTP cơ bản).
* Trả về kết quả phân tích hành vi cơ bản để luồng quy trình của hệ thống không bị gián đoạn.

---

## 4. HƯỚNG DẪN VẬN HÀNH & KIỂM THỬ (OPERATION GUIDE)

### 4.1 Cấu Hình Môi Môi Trường (.env)
Để chạy thử nghiệm Step 1 và Step 2, cấu hình tệp `.env` như sau:
```env
# AI Model & API Endpoint
AI_ENABLED=true
AI_API_KEY=sk-your-api-key
AI_BASE_URL=http://localhost:20128/v1
AI_MODEL=kc/nvidia/nemotron-3-super-120b-a12b:free

# OpenCTI TAXII Endpoint
OPENCTI_URL=https://your-opencti-domain/taxii2/root
OPENCTI_TOKEN=your-token-uuid
OPENCTI_TAXII_COLLECTION_ID=your-collection-id
OPENCTI_USERNAME=your-username
OPENCTI_PASSWORD=your-password

# AlienVault OTX Endpoint
OTX_API_URL=https://otx.alienvault.com
OTX_API_KEY=your-otx-api-key
```

### 4.2 Chạy Kiểm Thử Đơn Lẻ (Single CVE Run)
Chạy script kiểm thử tích hợp cho một CVE cụ thể để kiểm tra toàn bộ luồng Step 1 & Step 2:
```bash
python -X utf8 -m tests.integration.test_step1_step2_e2e CVE-2021-44228
```

### 4.3 Chạy Kiểm Thử Theo Lô Tự Động (OpenCTI Ingestion Run)
Chạy script kiểm thử không truyền tham số để kích hoạt luồng Ingest 5 CVE tự động từ OpenCTI TAXII:
```bash
python -X utf8 -m tests.integration.test_step1_step2_e2e
```
* **Tính tương tác**: Hệ thống sẽ yêu cầu người dùng nhấn **Enter** để chuyển qua từng giai đoạn và hiển thị bảng lựa chọn tiếp tục hay thoát sau khi hoàn thành mỗi CVE.
