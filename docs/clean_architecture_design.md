# THIẾT KẾ KIẾN TRÚC SẠCH (CLEAN ARCHITECTURE DESIGN SPECIFICATION)
## Đề Xuất Cải Tiến Cấu Trúc Thư Mục Cho Hệ Thống CVE Threat Intelligence & Sigma Generation

> [!NOTE] Mục tiêu thiết kế
> Đề xuất này tái cấu trúc hệ thống hiện tại theo chuẩn **Clean Architecture** (Kiến trúc sạch) nhằm đạt được sự phân tách trách nhiệm tuyệt đối (**Separation of Concerns**), độc lập với các thư viện ngoài (Framework Independence), dễ dàng viết Unit Test (Testability), và sẵn sàng mở rộng quy mô doanh nghiệp.

---

## 1. NGUYÊN TẮC KIẾN TRÚC (DEPENDENCY RULE)

Nguyên tắc cốt lõi của Kiến trúc sạch là **Chiều phụ thuộc duy nhất (The Dependency Rule)**: các lớp vòng ngoài chỉ được phép phụ thuộc vào lớp vòng trong, lớp vòng trong tuyệt đối không được biết bất kỳ thông tin nào về lớp vòng ngoài.

```text
 ┌─────────────────────────────────────────────────────────────┐
 │  LỚP 4: INFRASTRUCTURE (Cơ sở hạ tầng)                      │
 │    - Caching, External Clients, OpenAI, Gemini              │
 │  ┌───────────────────────────────────────────────────────┐  │
 │  │  LỚP 3: INTERFACE ADAPTERS (Bộ điều phối)             │  │
 │  │    - Controllers, CLI, Gateways                       │  │
 │  │  ┌─────────────────────────────────────────────────┐  │  │
 │  │  │  LỚP 2: USE CASES (Nghiệp vụ ứng dụng)          │  │  │
 │  │  │    - TriageUseCase, SigmaGenerationUseCase      │  │  │
 │  │  │  ┌───────────────────────────────────────────┐  │  │  │
 │  │  │  │  LỚP 1: DOMAIN (Nghiệp vụ cốt lõi)        │  │  │  │
 │  │  │  │    - Entities, Models, Scopes, Scores     │  │  │  │
 │  │  │  │                                           │  │  │  │
 │  │  │  └───────────────────────────────────────────┘  │  │  │
 │  │  └─────────────────────────────────────────────────┘  │  │
 │  └───────────────────────────────────────────────────────┘  │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. SƠ ĐỒ CẤU TRÚC THƯ MỤC ĐỀ XUẤT (DIRECTORY STRUCTURE)

Dưới đây là thiết kế chi tiết thư mục dự án chuẩn hóa doanh nghiệp:

```text
cve-ti-platform/
├── config/                          # Cấu hình toàn hệ thống (Infrastructure)
│   ├── settings.py                  # Load tham số cấu hình từ tệp .env (Pydantic Settings)
│   └── logging.py                   # Cấu hình log tập trung (Structlog/Stdlib logging)
│
├── src/                             # Thư mục gốc chứa mã nguồn ứng dụng
│   │
│   ├── domain/                      # 1. DOMAIN LAYER (Nghiệp vụ cốt lõi - Độc lập hoàn toàn)
│   │   ├── models/                  # Các thực thể dữ liệu (Pydantic Schemas tĩnh)
│   │   │   ├── cve.py               # Core CVE data structure (CoreCVEData)
│   │   │   ├── triage.py            # TriageContext model
│   │   │   ├── attack.py            # AttackMapping, TechnicalAnalysis
│   │   │   └── telemetry.py         # TelemetryAssessment schema
│   │   ├── services/                # Các dịch vụ logic tính toán (Pure rules - không kết nối I/O)
│   │   │   ├── priority_score.py    # Thuật toán điểm ưu tiên (CVSS, KEV, EPSS)
│   │   │   ├── capability.py        # Logic phân loại trong/ngoài scope hệ thống
│   │   │   └── ontology.py          # Quy tắc xử lý 4-Layer Ground Truth (OntologyManager)
│   │   └── exceptions.py            # Các lỗi tự định nghĩa (Domain Exceptions)
│   │
│   ├── usecases/                    # 2. USE CASES LAYER (Nghiệp vụ ứng dụng - Điều phối luồng)
│   │   ├── step_1_triage/           # Luồng Triage & Enrichment 
│   │   │   ├── request.py           # Dữ liệu đầu vào của Use Case
│   │   │   └── orchestrator.py      # Logic điều phối Triage & gọi làm giàu dữ liệu
│   │   ├── step_2_analysis/         # Luồng Phân tích ATT&CK & AI Validator 
│   │   ├── step_3_coverage/         # Luồng So sánh tìm khoảng trống Rule 
│   │   ├── step_4_telemetry/        # Luồng Ánh xạ Logsource & Telemetry 
│   │   ├── step_6_generate_sigma/   # Luồng Viết Rule Sigma tự động 
│   │   └── pipeline.py              # Điều phối chung toàn bộ Pipeline 6 bước
│   │
│   ├── adapters/                    # 3. INTERFACE ADAPTERS LAYER (Cầu nối chuyển đổi dữ liệu)
│   │   ├── controllers/             # Điểm tiếp nhận yêu cầu đầu vào (Triggers)
│   │   │   ├── cli/                 # Các câu lệnh điều khiển CLI (Argparse / Click)
│   │   │   
│   │   ├── gateways/                # Bộ chuyển đổi để gửi yêu cầu ra ngoài (Interface)
│   │   │   ├── cti_gateway.py       # Interface giao tiếp với nguồn dữ liệu CVE
│   │   │   ├── ai_gateway.py        # Interface giao tiếp với AI Client
│   │   │   └── storage_gateway.py   # Interface ghi dữ liệu Cache/DB
│   │   └── presenters/              # Bộ định dạng dữ liệu đầu ra (JSON, YAML, HTML)
│   │
│   └── infrastructure/              # 4. INFRASTRUCTURE LAYER (Triển khai công nghệ chi tiết)
│       ├── clients/                 # Triển khai gọi API kết nối mạng cụ thể (HTTP/TAXII)
│       │   ├── nvd_client.py        # NVD API Client
│       │   ├── opencti_client.py    # OpenCTI TAXII Client
│       │   └── otx_client.py        # AlienVault OTX Client
│       ├── ai/                      # Cài đặt chi tiết SDK AI
│       │   ├── openai_adapter.py    # Kết nối OpenAI API compatible
│       │   └── gemini_adapter.py    # Kết nối Gemini Native API
│       ├── cache/                   # Triển khai lưu trữ đệm (Diskcache / Redis)
│       └── local_truth/             # Dữ liệu Ground Truth tải về lưu trữ offline
│           ├── cti_mappings.csv     # File map CTID
│           └── capec_stix.json      # File map CAPEC
│
├── tests/                           # Phân mục kiểm thử rõ ràng
│   ├── unit/                        # Kiểm thử đơn vị (tách theo tầng logic: Domain, Use Cases)
│   └── integration/                 # Kiểm thử tích hợp (Pipeline E2E, API endpoints)
│
├── docs/                            # Tài liệu đặc tả hệ thống
├── pyproject.toml                   # Quản lý dependencies & package metadata (Poetry/Hatch)
└── .env                             # Các token, khóa bảo mật cấu hình local
```

---

## 3. CHI TIẾT VAI TRÒ TỪNG PHÂN TẦNG (LAYER DETAILS)

### 3.1 Vòng 1: Domain (Nghiệp vụ cốt lõi)
* **Trách nhiệm**: Chứa tất cả thực thể dữ liệu (`models/`) và các thuật toán tính toán đặc thù của doanh nghiệp (`services/`).
* **Ràng buộc**: **Tuyệt đối không import bất kỳ thư viện ngoài nào liên quan đến I/O** (như `httpx`, `fastapi`, hay các driver database). Chỉ dùng Python standard lib và Pydantic để định nghĩa schema.
* **Ví dụ**: Logic tính điểm ưu tiên `priority_score.py` chỉ nhận vào điểm CVSS, EPSS và trả về kết quả số. Nó không cần biết các điểm này được lấy từ API nào.

### 3.2 Vòng 2: Use Cases (Quy trình nghiệp vụ ứng dụng)
* **Trách nhiệm**: Chứa các quy trình thực thi cụ thể của ứng dụng (ví dụ: Quy trình phân tích CVE gồm việc gọi làm giàu dữ liệu, sau đó chạy AI, sau đó validate).
* **Cơ chế hoạt động**: Sử dụng **Dependency Inversion (Đảo ngược phụ thuộc)**. Use case định nghĩa ra Interface (giao diện) mà nó cần (ví dụ: `ITriageRepository`), còn việc class nào cài đặt (implement) interface đó sẽ do tầng ngoài thực hiện.

### 3.3 Vòng 3: Interface Adapters (Bộ điều phối & Cầu nối)
* **Trách nhiệm**: Dịch chuyển dữ liệu giữa định dạng của Use Case/Domain sang định dạng của các driver ngoài.
* **Controllers**: Tiếp nhận request từ client, validate payload đầu vào và gọi Use Case tương ứng.
* **Gateways**: Chuyển các lệnh lưu trữ hoặc gọi API của Use Case thành lệnh gọi tương ứng đến Database hay HTTP Clients ở tầng ngoài cùng.

### 3.4 Vòng 4: Infrastructure (Hạ tầng công nghệ)
* **Trách nhiệm**: Nơi chứa các công nghệ chi tiết, framework và các dịch vụ bên thứ ba.
* **Ràng buộc**: Tầng này có tỉ lệ thay đổi cao nhất (ví dụ: thay đổi từ thư viện HTTP này sang thư viện khác, đổi từ cache đệm Diskcache sang Redis, đổi từ OpenAI sang Gemini).
* **Ưu điểm**: Nhờ Clean Architecture, việc thay đổi ở tầng này hoàn toàn **không gây ảnh hưởng** đến mã nguồn xử lý nghiệp vụ ở tầng Use Cases hay Domain.

---

## 4. LUỒNG ĐI CỦA DỮ LIỆU (DATA FLOW EXAMPLE)

Dưới đây là luồng xử lý dữ liệu khi người dùng chạy lệnh CLI hoặc API để phân tích một CVE:

```text
 User Trigger (CLI/API)
       │
       ▼
 [Controller] (adapters/controllers/cli/cve_router.py)
       │ (Chuyển đổi CLI thành Request Model của Use Case)
       ▼
 [Use Case] (usecases/triage_cve/interactor.py)
       │
       ├─► Gọi [Domain Service] (domain/services/priority_score.py) để tính Priority
       │
       ├─► Gọi [AI Gateway Interface] (adapters/gateways/ai_gateway.py)
       │         │ (Use Case gọi qua interface, không gọi trực tiếp SDK)
       │         ▼
       │   [AI Gateway Adapter] (infrastructure/ai/openai_adapter.py) ──► Gọi API OpenAI/Gemini
       │
       ▼
 [Presenter] (Định dạng output thành JSON/YAML) ──► Trả về giao diện cho Người dùng
```

---

## 5. ĐÁNH GIÁ LỢI ÍCH KHI ÁP DỤNG DOANH NGHIỆP

1. **Khả năng kiểm thử (Testability)**: Bạn có thể viết Unit Test cho toàn bộ phần logic tính điểm, kiểm tra scope, ánh xạ ATT&CK (`domain/services/`) mà không cần setup mock HTTP client hay fake API key.
2. **Không bị bó buộc công nghệ (Independent of Database/LLM/Framework)**: Dự án có thể chuyển từ chạy CLI sang chạy FastAPI Web Server, chuyển từ Diskcache sang Redis, hoặc đổi từ Groq sang OpenAI chỉ trong vòng "1 nốt nhạc" bằng cách thay đổi cấu hình adapter ở Infrastructure Layer.
3. **Làm việc nhóm song song**: Đội ngũ phát triển Backend API có thể thiết kế controller, đội ngũ làm Agent AI tập trung viết Use Case/Domain mà không bị chồng chéo code lên nhau.
