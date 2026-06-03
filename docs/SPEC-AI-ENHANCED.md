# CVE-TI Platform: Đặc Tả Kỹ Thuật
## Quy Trình Từ CVE Đến Sigma Rule (AI-Enhanced)

> **Phiên bản**: 1.0  
> **Base**: CVE-2-Sigma Runbook  
> **Modified**: Bỏ bước 5 (Lab), bước 8 (Validate/Convert) — AI thay hard-coded if-else ở bước 2, 4, 6, 7

---

## 1. Pipeline Tổng Quan (6 Bước)

```
┌─────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐  ┌──────────┐  ┌──────────┐
│1.Triage │─▶│2.Analysis│─▶│3.Coverage│─▶│4.Telemetry │─▶│6.Write   │─▶│7.Noise   │
│  CVE    │  │ + ATT&CK │  │  / Gap   │  │ + logsource│  │  Rule    │  │ + Complex│
└─────────┘  └────┬─────┘  └────┬─────┘  └──────┬─────┘  └────┬─────┘  └─────┬─────┘
                  │ AI           │               │ AI          │ AI          │ AI
                  └─────────────┘               └─────────────┘└─────────────┘
```

| Bước | Câu hỏi | AI Role |
|------|---------|---------|
| 1 | CVE là gì, đáng làm rule không? | Không (rule-based) |
| 2 | Khai thác hoạt động ra sao? Map hành vi + ATT&CK? | **YES** (thay hard-coded graphs) |
| 3 | Đã có rule nào cover chưa? | Không (similarity engine) |
| 4 | Dấu vết ở logsource nào? | **YES** (thay hard-coded axis_map) |
| 6 | Viết Sigma rule thế nào? | **YES** (thay template-only) |
| 7 | Bao nhiêu alert/ngày? Query nặng không? | **YES** (thay placeholder) |

---

## 2. File Structure Mục Tiêu

```
cve-ti-platform/
├── app/
│   ├── services/
│   │   └── ai/                              # AI SERVICE LAYER
│   │       ├── __init__.py
│   │       ├── analyzer.py                  # Bước 2: AI Behavior + ATT&CK
│   │       ├── telemetry_selector.py        # Bước 4: AI Telemetry + Logsource
│   │       ├── rule_writer.py               # Bước 6: AI Sigma Writer
│   │       ├── noise_estimator.py           # Bước 7: AI Noise Estimation
│   │       └── prompts/                     # Prompt templates
│   │           ├── __init__.py
│   │           ├── analyze_behavior.txt
│   │           ├── select_telemetry.txt
│   │           ├── write_sigma_rule.txt
│   │           └── estimate_noise.txt
│   │
│   ├── analysis/                             # Giữ nguyên, refactor để dùng AI
│   │   ├── attack_mapper.py                 # Fallback khi AI fail
│   │   ├── behavior_analyzer.py             # Fallback khi AI fail
│   │   └── cwe_mapper.py                    # Giữ nguyên
│   │
│   ├── telemetry/                            # Giữ nguyên, refactor để dùng AI
│   │   ├── telemetry_selector.py            # Fallback khi AI fail
│   │   ├── logsource_mapper.py              # Giữ nguyên
│   │   └── field_mapper.py                  # Giữ nguyên
│   │
│   ├── sigma_generator/                     # Giữ nguyên, thêm AI writer
│   │   ├── services/
│   │   │   └── sigma_rule_generator.py      # Cần update gọi AI
│   │   ├── family_detection/
│   │   │   ├── base.py                      # Fallback DetectionTemplate
│   │   │   ├── registry.py                  # Registry cho templates
│   │   │   └── builder.py
│   │   ├── models/
│   │   │   └── sigma_rule.py                # Model đầu ra
│   │   └── serializers/
│   │       └── yaml_serializer.py          # Giữ nguyên
│   │
│   └── sigma_validation/                    # Giữ nguyên, thêm noise estimator
│       ├── validator.py                     # L1+L2 validation
│       ├── quality_scorer.py                # Giữ nguyên
│       └── noise_estimator.py               # MỚI: NoiseEstimator (AI-powered)
│
├── .env                                     # Cần thêm ANTHROPIC_API_KEY
└── pyproject.toml                           # Cần thêm anthropic SDK
```

---

## 3. Bước 2 — Phân Tích + ATT&CK (AI)

### 3.1 Mục Tiêu
Thay hard-coded `BEHAVIOR_ATTACK_GRAPH` và `VULNERABILITY_CLASS_ATTACK_GRAPH` bằng AI inference.

### 3.2 AI Prompt Template

```text
## System Prompt
You are a security researcher specializing in vulnerability analysis.
Analyze CVEs and map to observable behaviors + MITRE ATT&CK.

Principles:
1. Focus on OBSERVABLE BEHAVIORS during exploitation
2. Identify MANDATORY behaviors (hard to evade)
3. Distinguish OPTIONAL/EVASIVE behaviors (easy to bypass)
4. Use Sigma taxonomy + MITRE ATT&CK correctly

## User Prompt
Analyze CVE for detection engineering:

**CVE ID**: {cve_id}
**Description**: {description}
**CWE IDs**: {cwe_ids}
**CVSS Vector**: {cvss_vector}
**References**: {references}

Output JSON:
{
  "vulnerability_class": "DESERIALIZATION|COMMAND_INJECTION|...",
  "vulnerability_type": "one-line description",
  "mandatory_behaviors": ["process_creation", "network_callback"],
  "optional_behaviors": ["file_write"],
  "evasive_indicators": ["obfuscation", "encoding"],
  "tactics": ["TA0001", "TA0002"],
  "techniques": ["T1190", "T1059"],
  "subtechniques": ["T1059.004"],
  "exploit_requirements": ["reachable_service"],
  "confidence": 0.85,
  "reasoning": ["reason1", "reason2"]
}
```

### 3.3 Output Schema

```python
class TechnicalAnalysis(BaseModel):
    cve_id: str
    signature: str | None
    vulnerability_type: str
    vulnerability_class: VulnerabilityClass
    
    cwe_metadata: dict[str, str | float | None]
    attack_flow: dict[str, str | list[str]]
    
    likely_outcome: str
    mandatory_behaviors: list[str]
    optional_behaviors: list[str]
    evasive_indicators: list[str]
    exploit_requirements: list[str]
    
    analysis_confidence: float
    classification_reason: list[str]
    
    # AI metadata
    ai_used: bool = False
    ai_fallback_used: bool = False


class AttackMapping(BaseModel):
    tactics: list[str]
    techniques: list[str]
    subtechniques: list[str]
    mapping_reasons: list[str]
    confidence: float
```

### 3.4 Fallback Behavior

Khi AI fail, dùng rule-based graphs trong `attack_mapper.py`:
```python
BEHAVIOR_ATTACK_GRAPH = {
    "process_creation": {"tactics": ("TA0002",), "techniques": ("T1059",)},
    # ...
}
VULNERABILITY_CLASS_ATTACK_GRAPH = {
    VulnerabilityClass.DESERIALIZATION: ("T1059", "T1190"),
    # ...
}
```

### 3.5 Service Interface

```python
# app/services/ai/analyzer.py
class AIBehaviorAnalyzer:
    def __init__(self, anthropic_client, fallback: BehaviorAnalyzer):
        self.client = anthropic_client
        self.fallback = fallback
    
    async def analyze(self, cve_id, description, cwe_ids, cvss_vector, references) -> TechnicalAnalysis:
        try:
            return await self._ai_analyze(...)
        except AIError:
            return await self._fallback_analyze(...)
```

---

## 4. Bước 4 — Telemetry + Logsource (AI)

### 4.1 Mục Tiêu
Thay hard-coded `axis_map` trong `telemetry_selector.py` bằng AI inference.

### 4.2 AI Prompt Template

```text
## System Prompt
You are a detection engineer with deep Sigma expertise.
Recommend telemetry sources and logsource categories.

Principles:
1. Prioritize POST-EXPLOITATION over pre-exploitation
2. Use exact Sigma logsource categories
3. Consider telemetry availability
4. Identify gaps preventing detection

## User Prompt
Recommend telemetry for detecting this vulnerability:

**Behaviors**: {behaviors}
**ATT&CK Techniques**: {techniques}
**Attack Flow**: {attack_flow}

Output JSON:
{
  "detection_axis": ["pre-exploit", "post-exploit"],
  "primary_axis": "post-exploit",
  "logsource": {"category": "process_creation", "product": "windows"},
  "required_fields": ["ParentImage", "Image", "CommandLine"],
  "sysmon_eids": [1],
  "telemetry_gaps": [],
  "confidence": 0.88
}
```

### 4.3 Output Schema

```python
class TelemetryAssessment(BaseModel):
    detection_axis: list[str]
    primary_axis: str
    axis_confidence: float
    
    logsource: dict[str, str | None]
    alternative_logsource: list[dict] | None
    
    required_fields: list[str]
    recommended_fields: list[str]
    
    sysmon_eids: list[int] | None
    telemetry_requirements: str
    telemetry_gaps: list[str]
    gap_severity: str
    
    detection_strategy: str
    confidence: float
    
    # AI metadata
    ai_used: bool = False
```

### 4.4 Fallback Behavior

```python
# Hard-coded axis_map trong telemetry_selector.py
axis_map = {
    "pre_exploit": "pre-exploit",
    "post_exploit": "post-exploit",
    "process_creation": "process",
    "webserver": "web",
    "network_connection": "network",
    # ...
}
```

### 4.5 Service Interface

```python
# app/services/ai/telemetry_selector.py
class AITelemetrySelector:
    async def select(self, behaviors, techniques, attack_flow) -> TelemetryAssessment:
        try:
            return await self._ai_select(...)
        except AIError:
            return self.fallback.select(...)
```

---

## 5. Bước 6 — Viết Sigma Rule (AI)

### 5.1 Mục Tiêu
AI viết complete Sigma rule thay vì chỉ dùng DetectionTemplate.

### 5.2 AI Prompt Template

```text
## System Prompt
You are a detection engineer specializing in Sigma rules.
Write complete, valid Sigma rules following SigmaHQ convention.

Rules:
1. Title Case for title
2. Unique UUID v4 for id
3. ALL required metadata fields
4. Sigma field names (NOT SIEM-specific)
5. Precise detection logic (avoid over-fitting)
6. Realistic falsepositives (never "None" or "Pentest")
7. Level based on severity + noise

## User Prompt
Write Sigma rule for:

**CVE ID**: {cve_id}
**Vulnerability Type**: {vulnerability_type}
**ATT&CK**: {tactics}, {techniques}, {subtechniques}
**Behaviors**: {mandatory_behaviors}
**Telemetry**: {logsource}, {required_fields}
**Coverage**: {coverage_decision}

Output complete YAML rule:
```yaml
title:
id: (UUID v4)
name:
status: experimental
description: |
    Detects ...
references:
    - https://nvd.nist.gov/vuln/detail/{cve_id}
author: CVE-TI Platform
date: {today}
tags:
    - attack.<tactic>
    - attack.t<number>
    - cve.<year>.<number>
logsource:
    category:
    product:
detection:
    selection:
        field1:
        field2:
    condition: selection
falsepositives:
    -
level:
```
```

### 5.3 Output Schema

```python
class SigmaRule(BaseModel):
    metadata: SigmaMetadata
    logsource: dict[str, str | None]
    detection: SigmaDetection
    related: list[dict] | None
    
    # Validation
    validation_result: ValidationResult | None
    
    # YAML
    yaml_content: str | None
    
    # AI metadata
    ai_used: bool = False
    ai_confidence: float | None


class SigmaMetadata(BaseModel):
    title: str
    id: str  # UUID v4
    name: str | None
    status: str = "experimental"
    description: str
    references: list[str]
    author: str = "CVE-TI Platform"
    date: str  # YYYY-MM-DD
    modified: str | None
    tags: list[str]
    falsepositives: list[str]
    level: str


class SigmaDetection(BaseModel):
    selections: dict[str, dict[str, list[str]]]
    condition: str
```

### 5.4 Fallback Behavior

```python
# Dùng DetectionTemplate khi AI fail
class DetectionTemplate(ABC):
    def supports(self, family, signature) -> bool: ...
    def build_detection(self, analysis, attack, telemetry) -> SigmaDetection: ...
```

### 5.5 Service Interface

```python
# app/services/ai/rule_writer.py
class AISigmaRuleWriter:
    async def write_rule(
        self,
        cve_id: str,
        analysis: TechnicalAnalysis,
        attack: AttackMapping,
        telemetry: TelemetryAssessment,
        coverage: CoverageAssessment,
    ) -> SigmaRule:
        try:
            return await self._ai_write_rule(...)
        except AIError:
            return self._template_write_rule(...)
```

---

## 6. Bước 7 — Noise Estimation (AI)

### 6.1 Mục Tiêu
Thay placeholder bằng AI-powered noise + complexity estimation.

### 6.2 AI Prompt Template

```text
## System Prompt
You are a detection engineer analyzing Sigma rule noise.
Estimate alert rate and query complexity.

Reference Environment:
- 10,000 Windows endpoints
- Web tier with average traffic
- Sysmon EID 1 enabled

## User Prompt
Analyze noise for:

**Detection Logic**:
{detection_yaml}

**Logsource**: {logsource}

Output JSON:
{
  "events_per_day": "low|medium|high|very_high",
  "estimated_count": "<100|100-1k|1k-10k|>10k",
  "complexity_class": "low|medium|high",
  "noise_factors": ["factor1", "factor2"],
  "likely_false_positives": ["fp1", "fp2"],
  "recommended_filters": ["filter1"],
  "level_adjustment": "downgrade from critical to high|null",
  "reasoning": "explanation"
}
```

### 6.3 Output Schema

```python
class NoiseEstimate(BaseModel):
    events_per_day: str  # low/medium/high/very_high
    estimated_count: str  # e.g., "<100", "100-1k"
    complexity_class: str  # low/medium/high
    
    noise_factors: list[str]
    likely_false_positives: list[str]
    recommended_filters: list[str]
    
    level_adjustment: str | None
    reasoning: str
    
    confidence: float
    ai_used: bool = False
```

### 6.4 Integration

```python
# app/sigma_validation/noise_estimator.py
class NoiseEstimator:
    def __init__(self, anthropic_client):
        self.client = anthropic_client
    
    async def estimate(self, rule: SigmaRule) -> NoiseEstimate:
        # Gọi AI
        # Parse response
        # Fallback về conservative estimate nếu AI fail
```

### 6.5 Fallback Behavior

```python
# Conservative defaults khi AI fail
def conservative_estimate(rule: SigmaRule) -> NoiseEstimate:
    return NoiseEstimate(
        events_per_day="medium",
        estimated_count="100-1k",
        complexity_class="medium",
        noise_factors=["conservative_default"],
        level_adjustment="consider_downgrade",
        reasoning="AI unavailable, using conservative estimate"
    )
```

---

## 7. AI Service Base Class

### 7.1 Abstract Base

```python
# app/services/ai/base.py
from abc import ABC, abstractmethod
from typing import TypeVar, Generic

T = TypeVar('T')

class AIServiceError(Exception):
    """Raised when AI call fails."""
    pass

class AIService(ABC, Generic[T]):
    def __init__(self, client: Anthropic):
        self.client = client
    
    @abstractmethod
    async def _build_prompt(self, *args, **kwargs) -> str:
        raise NotImplementedError
    
    @abstractmethod
    async def _parse_response(self, response: str) -> T:
        raise NotImplementedError
    
    async def execute(self, *args, **kwargs) -> T:
        try:
            prompt = await self._build_prompt(*args, **kwargs)
            response = await self._call_ai(prompt)
            return await self._parse_response(response)
        except Exception as e:
            raise AIServiceError(f"AI execution failed: {e}") from e
    
    async def _call_ai(self, prompt: str) -> str:
        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text
```

### 7.2 Prompt Templates

```python
# app/services/ai/prompts/__init__.py
PROMPTS = {
    "analyze_behavior": "path/to/analyze_behavior.txt",
    "select_telemetry": "path/to/select_telemetry.txt",
    "write_sigma_rule": "path/to/write_sigma_rule.txt",
    "estimate_noise": "path/to/estimate_noise.txt",
}

def load_prompt(name: str, **kwargs) -> str:
    template = Path(PROMPTS[name]).read_text()
    return template.format(**kwargs)
```

---

## 8. Configuration

### 8.1 Environment Variables

```bash
# .env
ANTHROPIC_API_KEY=sk-ant-...          # REQUIRED for AI features
ANTHROPIC_MODEL=claude-sonnet-4-20250514  # Default model

# Fallback settings
AI_FALLBACK_ENABLED=true               # Use rule-based when AI fails
AI_TIMEOUT_MS=30000                    # AI call timeout
AI_RETRY_COUNT=2                       # Retry count on failure
```

### 8.2 Dependencies

```toml
# pyproject.toml
[project.dependencies]
anthropic = ">=0.20.0"
pydantic = ">=2.0"
# ... existing deps
```

---

## 9. Orchestrator Integration

### 9.1 Updated TriageOrchestrator

```python
# app/triage/orchestrator.py (pseudocode)
class TriageOrchestrator:
    def __init__(self):
        # AI Services
        self.ai_analyzer = AIBehaviorAnalyzer(
            anthropic_client=Anthropic(),
            fallback=BehaviorAnalyzer()  # Current behavior_analyzer.py
        )
        self.ai_telemetry = AITelemetrySelector(
            anthropic_client=Anthropic(),
            fallback=TelemetrySelector()  # Current telemetry_selector.py
        )
        self.ai_rule_writer = AISigmaRuleWriter(
            anthropic_client=Anthropic(),
            fallback=DetectionTemplateBuilder()
        )
        self.noise_estimator = NoiseEstimator(
            anthropic_client=Anthropic()
        )
    
    async def orchestrate(self, cve_id: str) -> EnrichedCVEContext:
        # Step 1: Triage (unchanged)
        core, triage = await self.run_triage_stages(cve_id)
        
        # Step 2: Analysis + ATT&CK (AI)
        analysis = await self.ai_analyzer.analyze(
            cve_id=cve_id,
            description=core.description,
            cwe_ids=core.cwe_ids,
            cvss_vector=core.cvss_vector,
            references=core.references,
        )
        attack = await self._map_attack(analysis)  # Có thể cũng AI
        
        # Step 3: Coverage (unchanged)
        coverage = await self._analyze_coverage(analysis, attack, telemetry)
        
        # Step 4: Telemetry (AI)
        telemetry = await self.ai_telemetry.select(
            behaviors=analysis.mandatory_behaviors,
            techniques=attack.techniques,
            attack_flow=analysis.attack_flow,
        )
        
        # Step 6: Write Sigma Rule (AI)
        sigma_rule = await self.ai_rule_writer.write_rule(
            cve_id=cve_id,
            analysis=analysis,
            attack=attack,
            telemetry=telemetry,
            coverage=coverage,
        )
        
        # Step 7: Noise Estimation (AI)
        noise = await self.noise_estimator.estimate(sigma_rule)
        sigma_rule.metadata.level = self._adjust_level(sigma_rule.metadata.level, noise)
        
        return EnrichedCVEContext(...)
```

---

## 10. Data Flow Summary

```
CVE Input
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 1: Triage (Rule-based)                                 │
│ - NVD, EPSS, KEV, Exposure                                  │
│ Output: CoreCVEData, TriageContext, Priority                │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 2: Analysis + ATT&CK (AI Primary, Fallback: graphs)    │
│ - AI: analyze_behavior prompt                                │
│ - Fallback: BEHAVIOR_ATTACK_GRAPH, VULNERABILITY_CLASS_*    │
│ Output: TechnicalAnalysis, AttackMapping                     │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 3: Coverage/Gap Analysis (Rule-based similarity)        │
│ - Search existing Sigma rules                                │
│ - Calculate similarity scores                                │
│ Output: CoverageAssessment, Related rules                   │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 4: Telemetry + Logsource (AI Primary, Fallback: map)   │
│ - AI: select_telemetry prompt                                │
│ - Fallback: axis_map hard-coded                             │
│ Output: TelemetryAssessment                                 │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 6: Write Sigma Rule (AI Primary, Fallback: templates)  │
│ - AI: write_sigma_rule prompt                                │
│ - Fallback: DetectionTemplate                               │
│ Output: SigmaRule (YAML)                                    │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 7: Noise Estimation (AI Primary, Fallback: conservative)│
│ - AI: estimate_noise prompt                                  │
│ - Fallback: conservative defaults                           │
│ Output: NoiseEstimate, Level adjustment                      │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
Final Output: EnrichedCVEContext + SigmaRule
```

---

## 11. Checklist Implementation

### Phase 1: Foundation
- [ ] Add `anthropic` SDK to dependencies
- [ ] Add `ANTHROPIC_API_KEY` to `.env`
- [ ] Create `app/services/ai/__init__.py`
- [ ] Create `app/services/ai/base.py` (AIService base class)
- [ ] Create `app/services/ai/prompts/` directory

### Phase 2: Bước 2 — AI Analysis
- [ ] Create `app/services/ai/analyzer.py`
- [ ] Create `app/services/ai/prompts/analyze_behavior.txt`
- [ ] Create `app/sigma_validation/noise_estimator.py` (reuse for all steps)

### Phase 3: Bước 4 — AI Telemetry
- [ ] Create `app/services/ai/telemetry_selector.py`
- [ ] Create `app/services/ai/prompts/select_telemetry.txt`

### Phase 4: Bước 6 — AI Rule Writer
- [ ] Create `app/services/ai/rule_writer.py`
- [ ] Create `app/services/ai/prompts/write_sigma_rule.txt`

### Phase 5: Bước 7 — AI Noise Estimation
- [ ] Complete `app/sigma_validation/noise_estimator.py`
- [ ] Create `app/services/ai/prompts/estimate_noise.txt`

### Phase 6: Integration
- [ ] Update `app/triage/orchestrator.py` to use AI services
- [ ] Add `ai_used`, `ai_fallback_used` flags to output models
- [ ] Add logging for AI prompts/responses

### Phase 7: Testing
- [ ] Test AI flow end-to-end
- [ ] Test fallback when AI fails
- [ ] Validate output against runbook expectations

---

## 12. Error Handling Strategy

```python
class AIFailureStrategy:
    """
    Strategy khi AI fail:
    1. Log error với context đầy đủ
    2. Return fallback result
    3. Set flag ai_used=False, ai_fallback_used=True
    4. Continue pipeline (không throw exception)
    """
    
    @staticmethod
    def handle_ai_error(error: Exception, context: dict) -> None:
        logger.warning(f"AI failed, using fallback: {error}", extra=context)
```

---

## 13. Testing Strategy

| Test Case | Expected Behavior |
|-----------|-------------------|
| AI available, success | Full AI output, ai_used=True |
| AI available, parse error | Fallback output, ai_used=True, log warning |
| AI unavailable (no API key) | Fallback output, ai_fallback_used=True |
| AI timeout | Fallback output, ai_fallback_used=True |
| AI rate limit | Fallback output, ai_fallback_used=True |

---

## 14. Monitoring

```python
# Metrics to track:
- ai_call_count: int
- ai_success_count: int
- ai_failure_count: int
- ai_fallback_count: int
- ai_average_latency_ms: float
- ai_cost_per_cve: float
```

---