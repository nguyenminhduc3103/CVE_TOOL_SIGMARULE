# BÁO CÁO LUỒNG INPUT / OUTPUT — STEP 1 (TRIAGE)

> Phạm vi: toàn bộ pipeline thuộc `src/usecases/step_1_triage/`, mọi stage được gọi bởi `TriageOrchestrator.orchestrate(cve_id)`.
> Đầu vào duy nhất của toàn Step 1: **một chuỗi `cve_id`** (vd. `CVE-2023-22515`).
> Đầu ra cuối: **`EnrichedCVEContext`** — đối tượng Pydantic chứa `core`, `triage`, `analysis`, `attack`, `intel`, `metadata`, v.v.

---

## 1. Tổng quan một hành trình

```
cve_id (str)
   │
   ▼
[TriageOrchestrator.orchestrate] ── fan-out ──► 5 providers (NVD, KEV, EPSS, OTX, PoC)
                                              │
                                              └─► 1 nuclei crawl (song song)
   │
   ├─► core_stage      → chuẩn hoá NVD payload
   ├─► epss_stage      → giữ nguyên EPSS payload
   ├─► kev_stage       → giữ nguyên KEV payload
   ├─► poc_stage       → giữ nguyên PoC payload
   ├─► exposure_stage  → { internet_exposure: None }
   ├─► _build_core_context  → CoreCVEData (fallback OTX)
   ├─► resolve_poc_context  → bool + list[str]
   ├─► PriorityEngine       → (priority_label, score)
   ├─► CapabilityChecker    → CapabilityClassification
   └─► DecisionEngine       → decision + decision_reason
   ▼
EnrichedCVEContext (return)
```

---

## 2. INPUT — Đầu vào của Step 1

| # | Tên field | Kiểu | Nguồn | Mô tả |
|---|-----------|------|-------|-------|
| 1 | `cve_id` | `str` | Đối số truyền vào `TriageOrchestrator.orchestrate(cve_id)` | Mã CVE định danh duy nhất (vd. `CVE-2023-22515`). Toàn bộ payload khác sinh ra từ chuỗi này. |

Đây là **input duy nhất** mà CLI/API gọi controller truyền xuống. Mọi trường của `CoreCVEData`, `TriageContext`, `EnrichedCVEContext` được sinh nội bộ từ chuỗi này.

---

## 3. Fan-out song song — 6 nguồn dữ liệu thô

Ngay khi `orchestrate(cve_id)` chạy, 6 task được bắn đồng thời (`asyncio.gather`):

| Task | Provider / Stage | Raw output (dict) | Thực sự dùng tại field nào? |
|------|------------------|-------------------|------------------------------|
| `nvd` | `NVDProvider.fetch` | `nvd_core_raw` | `core.*` (description, cvss_*, cwe_ids, references, cpes, affected_products, published_at, modified_at) |
| `kev` | `KEVProvider.fetch` | `kev_stage_raw` | `triage.in_kev`, `triage.kev_added_date`, `triage.ransomware_usage`, fallback `core.cwe_ids` |
| `epss` | `EPSSProvider.fetch` | `epss_stage_raw` | `triage.epss_score`, `triage.epss_percentile` |
| `otx` | `OTXProvider.fetch` | `otx_raw` | `triage.threat_actors`, fallback khi NVD thiếu (`_build_core_context`) |
| `poc` | `PoCProvider.fetch` | `poc_stage_raw` | `triage.public_poc`, `triage.poc_references`, `enriched.intel.poc_references`, `enriched.intel.poc_credibility` |
| nuclei | `run_nuclei_crawl_stage` | `nuclei_raw` | merge vào `core.references`, `enriched.nuclei_evidence`, `enriched.intel.nuclei_templates`, `poc_description`, `poc_network_payloads` |

### 3.1 Các stage function (pass-through hiện tại)

| Stage fn | Hiện trạng | Vai trò |
|----------|------------|---------|
| `run_core_stage` | `return raw_nvd` | Chuẩn hoá NVD payload (placeholder) |
| `run_kev_stage` | `return kev_raw` | Pass-through |
| `run_epss_stage` | `return epss_raw` | Pass-through |
| `run_poc_stage` | `return poc_raw` | Pass-through |
| `run_exposure_stage` | `return {"internet_exposure": None}` | Chưa tích hợp nguồn internet-wide scan |
| `run_nuclei_crawl_stage` | crawl trực tiếp `tools.crawl_evidence.crawl` | Lấy YAML templates cho PoC |

> Thực tế mọi logic chuẩn hoá nằm trong `_build_core_context` (orchestrator) + `resolve_poc_context` (shared parser). Các stage chỉ là điểm đánh dấu để mở rộng sau.

---

## 4. OUTPUT — Từng trường của `EnrichedCVEContext` lấy từ đâu?

Trả lời đúng câu hỏi **"mỗi trường trong Step 1 sẽ nhận lấy từ đâu"** — bảng dưới liệt kê từng field của `core`, `triage`, `intel`, `metadata`, các thuộc tính lũy (`providers_used`, `partial_enrichment`, …), và nguồn gốc của nó.

### 4.1 `core: CoreCVEData`

| Field | Nguồn dữ liệu | Đường vào | Ghi chú |
|-------|---------------|-----------|---------|
| `cve_id` | `nvd_core_raw["cve_id"]` hoặc tham số truyền vào | `_build_core_context` | Nếu NVD lỗi, dùng chính `cve_id` |
| `description` | NVD → fallback OTX (`description` / `base_indicator.description`) | `_build_core_context` | Ưu tiên NVD |
| `cvss_score` | NVD → fallback OTX (`cvssv3.cvssV3.baseScore` → `cvss.Score`) | `_build_core_context` | Ép `float` và dừng ở giá trị đầu tìm được |
| `cvss_vector` | NVD → fallback OTX (`cvssv3.cvssV3.vectorString` → `cvss.vectorString`) | `_build_core_context` | |
| `severity` | NVD → fallback OTX (`cvssv3.cvssV3.baseSeverity` → tự tính từ CVSS) | `_build_core_context` | Tự tính: ≥9 CRITICAL, ≥7 HIGH, ≥4 MEDIUM, >0 LOW |
| `cwe_ids` | NVD → fallback OTX (`cwe`) → fallback KEV (`cwes`) | `_build_core_context` + orchestrator | Nếu `["NVD-CWE-noinfo"]` thì thay bằng KEV `cwes` |
| `references` | NVD → fallback OTX (`references`) + merge `nuclei_raw["references"]` | `_build_core_context` + `_merge_references` | Dedup theo URL |
| `cpes` | NVD → fallback OTX (`products` lọc prefix `cpe:`) | `_build_core_context` | |
| `affected_products` | NVD → fallback OTX (qua `parse_cpe`) | `_build_core_context` | Tag `[APP]/[OS]/[HW]` |
| `published_at` | NVD → fallback OTX (`date_created`) | `_build_core_context` | `datetime.fromisoformat` |
| `modified_at` | NVD → fallback OTX (`date_modified`) | `_build_core_context` | `datetime.fromisoformat` |

### 4.2 `triage: TriageContext`

| Field | Nguồn | Đường vào |
|-------|-------|-----------|
| `in_kev` | `kev_stage_raw["in_kev"]` | Orchestrator `_get_optional_bool` |
| `kev_added_date` | `kev_stage_raw["kev_added_date"]` | Orchestrator `_get_optional_datetime` |
| `ransomware_usage` | `kev_stage_raw["known_ransomware_campaign_use"]` | Orchestrator |
| `observed_in_the_wild` | `in_kev` (mirror) | Orchestrator |
| `epss_score` | `epss_stage_raw["epss_score"]` | Orchestrator `_get_optional_float` |
| `epss_percentile` | `epss_stage_raw["epss_percentile"]` | Orchestrator `_get_optional_float` |
| `internet_exposure` | `exposure_raw["internet_exposure"]` | Orchestrator (hiện `None`) |
| `threat_actors` | `otx_raw["threat_actors"]` | Orchestrator |
| `public_poc` | `resolve_poc_context()` (gộp NVD refs + nomi-sec `poc_references`) | Orchestrator |
| `poc_references` | `resolve_poc_context()` | Orchestrator |
| `priority` | `PriorityEngine.assess` | Orchestrator |
| `priority_score` | `PriorityEngine.assess` | Orchestrator |
| `capability_assessment` | `CapabilityChecker.assess` (string) | Orchestrator |
| `decision` | `DecisionEngine.evaluate` | Orchestrator |
| `decision_reason` | `DecisionEngine.evaluate` | Orchestrator |
| `telemetry_blocked` | Reserved (Step 1.4) | chưa cập nhật |

### 4.3 `enriched.analysis` & `enriched.attack`

Trong Step 1 **chưa được điền**. Hai field này do Step 2 (`run_analysis_stage`) gán sau.
Orchestrator chỉ chuẩn bị payload đầu vào cho Step 2 (`enriched.intel`, `enriched.nuclei_evidence`).

### 4.4 `enriched.intel: PoCSummary`

| Field | Nguồn |
|-------|-------|
| `public_poc` | `bool(public_poc)` |
| `poc_references` | `poc_references` (resolve_poc_context) |
| `poc_credibility` | `poc_stage_raw["credibility"]` |
| `nuclei_templates` | `nuclei_raw["evidence"]` |
| `exposure` | `exposure_raw` (dict hoặc None) |
| `poc_description` | `_poc_details_from_nuclei()` lấy YAML `evidence[].request` (type `documentation`) |
| `poc_network_payloads` | `_poc_details_from_nuclei()` lấy YAML `evidence[].request_info` (type `network`) |

### 4.5 `enriched.metadata: EnrichmentMetadata`

| Field | Nguồn |
|-------|-------|
| `enriched_at` | `datetime.now(timezone.utc)` |
| `pipeline_version` | `PIPELINE_VERSION` constant |
| `enrichment_duration_ms` | `perf_counter` đo toàn pipeline |
| `providers_used` | `[name for status==success]` |
| `partial_enrichment` | `any status != success` hoặc `stage_partial` |
| `provider_durations_ms` | Mapping duration (ms) từng provider |
| `references_truncated` | `nvd.parser.last_truncation['references_truncated']` |
| `cpes_truncated` | `nvd.parser.last_truncation['cpes_truncated']` |
| `ai_steps_used` | `self._ai_steps_used` (chưa khai thác trong Step 1) |
| `ai_total_cost_usd` | `self._ai_total_cost_usd` (chưa khai thác trong Step 1) |

### 4.6 Thuộc tính phụ

| Field | Nguồn |
|-------|-------|
| `enriched.provider_status` | dict `provider → status` (`success` / `failed` / `timeout`) |
| `enriched.provider_errors` | dict `provider → error message` |
| `enriched.nuclei_evidence` | `nuclei_raw` gán qua `object.__setattr__` |

### 4.7 Các trường **luôn `None`** ngay Step 1

`analysis`, `attack`, `coverage`, `telemetry`, `telemetry_discovery`, `telemetry_assessment`, `threat_intelligence`, `attack_mapping`, `detections`, `ai_features` — sẽ được các step sau (Step 2, 3, 4, 5, 6) bổ sung.

---

## 5. Quyết định GO / NO-GO — Decision Engine

`DecisionEngine.evaluate(core, triage, capability_classification)` ánh xạ 5 trường hợp:

| # | KEV | PoC | CVSS≥8.0 hoặc EPSS≥0.3 | Quyết định | Mức ưu tiên |
|---|-----|-----|------------------------|------------|-------------|
| 1 | ✓ | ✓ | ✓ | **GO** | Khẩn cấp |
| 2 | ✗ | ✓ | ✓ | **GO** | Cao |
| 3 | ✓ | ✗ | ✓ | **NO-GO** | Trung bình |
| 4 | ✓ | ✓ | ✗ | **GO** | Trung bình |
| 5 | còn lại | | | **NO-GO** | Thấp |

Ngoài ra, nếu `CapabilityClassification.value != "in_scope"` (firmware, crypto, hardware, side-channel) → ép **NO-GO** với lý do "out of scope".

---

## 6. Priority & Capability

**PriorityEngine** (deterministic):
```
total = min(100, cvss_score*10 + epss_score*100 + (15 nếu in_kev))
≥90 critical | ≥70 high | ≥40 medium | còn lại low
```

**CapabilityChecker** phân loại scope bằng keyword trên `cve_id + description + cwe_ids`:
- `firmware/uefi/bios/bootloader/microcode/embedded` → `out_of_scope_firmware`
- `crypto/cipher/tls/ssl/signature` → `out_of_scope_crypto`
- `hardware/side-channel/spectre/meltdown/rowhammer` → `out_of_scope_hardware`
- không match → `in_scope` (default)

`Out-of-scope` sẽ nhân `confidence_modifier` < 1.0 vào `analysis.confidence` ở Step 2.

---

## 7. Sơ đồ Object cuối của Step 1

```python
EnrichedCVEContext(
    core=CoreCVEData(...),           # NVD + OTX fallback + nuclei_evidence refs
    triage=TriageContext(
        in_kev, kev_added_date, ransomware_usage, observed_in_the_wild,
        epss_score, epss_percentile,
        internet_exposure, threat_actors,
        public_poc, poc_references,
        priority, priority_score, capability_assessment,
        decision, decision_reason,
    ),
    analysis=None,                   # Step 2
    attack=None,                     # Step 2
    coverage=None,                   # Step 3
    telemetry=None,                  # Step 4
    intel=PoCSummary(...),           # build từ PoC + nuclei evidence
    telemetry_discovery=None,        # Step 1.3
    telemetry_assessment=None,       # Step 1.4
    threat_intelligence=None,        # Phase 2
    attack_mapping=None,             # Phase 2
    detections=None,                 # Phase 2
    ai_features=None,                # Phase 2
    provider_status={...},
    provider_errors={...},
    metadata=EnrichmentMetadata(...),
)
nuclei_evidence = {...}              # gắn qua object.__setattr__
```

---

## 8. Tóm tắt một câu

> **Input:** `cve_id` (chuỗi).
> **Output Step 1:** `EnrichedCVEContext` đã gán `core` (NVD + OTX fallback + nuclei), `triage` (KEV + EPSS + PoC + capabilities + decision), `intel` (PoC summary), `metadata` (timing, providers) — còn `analysis`, `attack`, `telemetry`, `coverage` chờ Step 2 → 3 → 4.

---

## 9. STEP 2 — TECHNICAL ANALYSIS & ATT&CK MAPPING

Step 2 hiện được gọi từ CLI controller sau khi Step 1 đã trả về `enriched` context. Luồng thực thi chính là `run_step2_tech_analysis(...)` → `AIBehaviorService.fetch_attack_mapping(...)` → `AIPhase2BService.reason_chain(...)`.

### 9.1 Input của Step 2

#### 9.1.1 Input ở call site thực tế

Khi `src/adapters/controllers/cli/triage_controller.py` gọi Step 2, nó truyền các field sau từ `enriched.core`:

| Field | Nguồn cấp | Ghi chú |
|---|---|---|
| `cve_id` | `enriched.core.cve_id` | Bắt buộc |
| `description` | `enriched.core.description` | `or ""` nếu rỗng |
| `cvss_score` | `enriched.core.cvss_score` | `or 0.0` nếu thiếu |
| `cvss_vector` | `enriched.core.cvss_vector` | `or ""` nếu thiếu |
| `cwe_ids` | `enriched.core.cwe_ids` | `or []` nếu thiếu |

Hai tham số PoC có trong chữ ký `run_step2_tech_analysis(...)` và hiện call site CLI đã truyền vào từ `enriched.intel` nên runtime nhận giá trị thật:

| Field | Nguồn cấp | Trạng thái hiện tại |
|---|---|---|
| `poc_description` | optional arg | lấy từ `enriched.intel.poc_description` |
| `poc_request_info` | optional arg | lấy từ phần tử đầu tiên của `enriched.intel.poc_network_payloads` |

#### 9.1.2 Input nội bộ của từng phase

| Phase | Payload prompt gửi vào LLM | Nguồn cấp chính |
|---|---|---|
| Phase 1 | `cve_id`, `description`, `cvss_score`, `cvss_vector`, `cwe_ids`, `poc_description`, `poc_request_info` | Từ Step 1 core + PoC optional args |
| Phase 2A | `cve_id`, `description`, `exec_surface`, `delivery_vector`, `mandatory_behaviors`, `reasoning`, `poc_documentation`, `poc_evidence`, `poc_request_info` | `phase1_output` + `description` |
| Phase 2B | `cve_id`, `description`, `reasoning`, `poc_documentation`, `poc_evidence`, `poc_request_info`, `tactics`, `techniques`, `subtechniques` | `step1_output` tối giản + `phase1_output` + `phase2a_output` |

### 9.2 Prompt đi qua đâu

Step 2 dùng 3 system prompt và 1 user prompt dùng chung:

| Phase | System prompt | User prompt | Vai trò |
|---|---|---|---|
| Phase 1 | `src/usecases/step_2_analysis/prompts/analyze_behavior_phase1.system.txt` | `src/usecases/step_2_analysis/prompts/analyze_behavior.user.txt` | Trích xuất behavior facts |
| Phase 2A | `src/usecases/step_2_analysis/prompts/analyze_behavior_phase2.system.txt` | `src/usecases/step_2_analysis/prompts/analyze_behavior.user.txt` | Map ATT&CK tactics / techniques / subtechniques |
| Phase 2B | `src/usecases/step_2_analysis/prompts/analyze_behavior_phase2b.system.txt` | `src/usecases/step_2_analysis/prompts/analyze_behavior.user.txt` | Reason chain, confidence, attack chain |

Riêng Phase 1 còn được inject thêm ontology primitive behaviors từ `mandatory_behavior_ontology.json` vào system prompt trước khi gọi LLM.

### 9.3 Output của Step 2

Hàm `run_step2_tech_analysis(...)` trả về tuple:

```python
(TechnicalAnalysis | None, AttackMapping | None, dict[str, Any])
```

#### 9.3.1 `TechnicalAnalysis`

| Field | Nguồn cấp | Cách lấy |
|---|---|---|
| `exploit_vector` | rule-based CVSS parser | `classify_exploit_vector(cvss_vector)` |
| `pre_auth` | rule-based CVSS parser | `classify_exploit_vector(cvss_vector)` |
| `remote_exploitable` | rule-based CVSS parser | `classify_exploit_vector(cvss_vector)` |
| `exploit_complexity` | rule-based CVSS parser | `classify_exploit_vector(cvss_vector)` |
| `user_interaction_required` | rule-based CVSS parser | `classify_exploit_vector(cvss_vector)` |
| `confidence` | Phase 1 AI | `Phase1LLMResponse.confidence`, fallback `0.85` |
| `mandatory_behaviors` | Phase 1 AI | Chỉ lấy token canonical từ ontology inject vào prompt |
| `evasive_indicators` | Phase 1 AI | Từ Phase 1 LLM |
| `exploit_requirements` | Phase 1 AI | Từ Phase 1 LLM |
| `reasoning` | Phase 1 AI | Từ Phase 1 LLM |
| `execution_surface` | Phase 1 AI | Từ Phase 1 LLM |
| `delivery_vector` | Phase 1 AI | Từ Phase 1 LLM |
| `ai_used` | orchestrator | Gán `True` khi AI path chạy |
| `ai_model` | orchestrator | Model của Phase 2 client |
| `ai_models_used` | orchestrator | Gộp model của Phase 1, Phase 2A, Phase 2B |

#### 9.3.2 `AttackMapping`

| Field | Nguồn cấp | Cách lấy |
|---|---|---|
| `tactics` | Phase 2A AI | `Phase2LLMResponse.tactics` |
| `techniques` | Phase 2A AI | `Phase2LLMResponse.techniques` |
| `subtechniques` | Phase 2A AI | `Phase2LLMResponse.subtechniques` |
| `mapping_reasons` | Phase 2B AI | `mapping_reasoning` hoặc `mapping_reasons` |
| `is_attack_chain` | Phase 2B AI | `AIPhase2BService.reason_chain()` |
| `attack_chain` | Phase 2B AI | `AIPhase2BService.reason_chain()` |
| `chain_reasoning` | Phase 2B AI | `AIPhase2BService.reason_chain()` |
| `confidence_level` | Phase 2B AI | `confidence` của phase 2B |
| `ai_used` | orchestrator | Gán `True` khi AI path chạy |
| `ai_model` | orchestrator | Model của Phase 2 client |
| `ai_models_used` | orchestrator | Gộp model của Phase 1, Phase 2A, Phase 2B |

#### 9.3.3 Metadata nội bộ trả về cùng Step 2

| Field | Nguồn cấp |
|---|---|
| `validation.valid` | kết quả wrapper hợp lệ của luồng 3 pha |
| `verdict` | hằng `PASS_THREE_PHASE` |
| `phase1_execution_surface` | `phase1_dict["execution_surface"]` |
| `phase1_delivery_vector` | `phase1_dict["delivery_vector"]` |
| `invalid_ttps` | `validate_attack_mapping(...)` |

### 9.4 Nguồn dữ liệu sau khi Step 2 gán vào context cuối

Khi CLI nhận tuple từ Step 2, nó gán trực tiếp:

| Context field | Giá trị nhận |
|---|---|
| `enriched.analysis` | `TechnicalAnalysis` |
| `enriched.attack` | `AttackMapping` |

Nếu Step 2 fail, hai field này vẫn là `None` và pipeline dừng trước Step 4 / Step 6.

### 9.5 Tóm tắt một câu

> **Input Step 2:** `cve_id`, `description`, `cvss_score`, `cvss_vector`, `cwe_ids` từ Step 1 core; PoC fields được lấy từ `enriched.intel` và truyền vào Step 2.
> **Prompt route:** Phase 1 dùng `analyze_behavior_phase1.system.txt` + `analyze_behavior.user.txt`, Phase 2A dùng `analyze_behavior_phase2.system.txt` + `analyze_behavior.user.txt`, Phase 2B dùng `analyze_behavior_phase2b.system.txt` + `analyze_behavior.user.txt`.
> **Output Step 2:** `TechnicalAnalysis` + `AttackMapping` gán vào `enriched.analysis` và `enriched.attack`, còn dict metadata nội bộ trả thêm trạng thái validate / verdict / invalid TTPs.
