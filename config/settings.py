from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    env: str = "development"
    nvd_api_url: str = "https://services.nvd.nist.gov"
    nvd_api_key: str | None = None
    kev_api_url: str = "https://www.cisa.gov/known-exploited-vulnerabilities"
    epss_api_url: str = "https://epss.example"

    # OpenCTI Integration
    opencti_url: str = "http://localhost:8080"
    opencti_cookie: str | None = None
    opencti_token: str | None = None
    opencti_taxii_collection_id: str | None = None
    opencti_username: str | None = None
    opencti_password: str | None = None

    # AlienVault OTX Integration
    otx_api_url: str = "https://otx.alienvault.com"
    otx_api_key: str | None = None

    # --- AI service (V1: OpenAI-compatible: Groq / Anthropic / Ollama) ---
    ai_enabled: bool = False
    ai_api_key: str | None = None
    # New: comma-separated list of keys for round-robin rotation (Groq free tier).
    # If set (non-empty), takes precedence over ai_api_key. Falls back otherwise.
    ai_api_keys: str | None = None
    ai_base_url: str | None = None

    # --- Response cache (NVD / KEV / EPSS, 24h TTL) ---
    # Stdlib-only file cache; can be disabled per-process via CVE_TI_CACHE=0.
    cache_enabled: bool = True
    cache_ttl_seconds: int = 86400  # 24h
    cache_dir: str = ".cache/cve_responses"
    # Primary (Phase 2 analyze) model name. Backed by env ANALYZE_AI_MODEL.
    # Falls back to the legacy `ai_model` field if a caller still sets the old key.
    ai_model: str = "llama-3.3-70b-versatile"
    analyze_ai_model: str | None = None

    # --- Two-phase Step 2 (Phase 1 + Phase 2) ---
    # Step 2 chạy 2-phase flow: Phase 1 (behavior classification) → Phase 2
    # (ATT&CK mapping). Phase 1 là CLASSIFICATION task: extract
    # `execution_surface`, `delivery_vector`, `user_interaction_required`
    # từ CVE description. Reasoning vừa đủ - không cần model 70B. Dùng
    # OpenRouter free model (Llama 3.3 70B free, Qwen, DeepSeek, Mistral)
    # hoặc Google AI Studio free tier để tiết kiệm cost. Falls back to
    # analyze_ai_model nếu không set (backward compat).
    phase1_ai_model: str | None = None
    phase1_ai_base_url: str | None = None
    phase1_ai_api_key: str | None = None
    phase1_ai_keys: str | None = None  # comma-separated cho round-robin
    # Phase 2 (ATT&CK mapping) uses analyze_ai_model (default Groq llama-3.3-70b).
    # Phase 2 là REASONING task quan trọng nhất - giữ model mạnh.

    # --- Step 4 (Telemetry Selector) ---
    # Step 4 chọn Sigma logsource + fields + detection_features cho Step 6.
    # Step 4 là CLASSIFICATION + constrained emission task (chọn từ whitelist
    # Sigma taxonomy). Output gồm:
    #   - AI emit (loose): candidate_logsources, candidate_fields, detection_axis,
    #     rule_strategy, telemetry_gaps, observable_detection_features.
    #   - Code layer (deterministic): sigma_logsources, required_fields,
    #     telemetry_feasibility_score (rule-based).
    # RECOMMEND: Gemini 2.5 Flash (1M TPM free tier) — quota rộng, JSON mode
    # native, taxonomy adherence tốt. Backward compat: fallback về Phase 1
    # model nếu không set (vì cùng provider Gemini trong default config).
    step4_ai_model: str | None = None
    step4_ai_base_url: str | None = None
    step4_ai_api_key: str | None = None
    step4_ai_keys: str | None = None  # comma-separated cho round-robin

    # --- Step 6 (Sigma Rule Generation) ---
    # Step 6 Detection Logic Planner (AI). Mirror pattern Step 4:
    # AI emits semantic intent only; codes layer handles Sigma emission.
    # RECOMMEND: same provider as Step 4 (Gemini 2.5 Flash) for consistency.
    step6_ai_model: str | None = None
    step6_ai_base_url: str | None = None
    step6_ai_api_key: str | None = None
    step6_ai_keys: str | None = None
    # Enable/disable AI path for Step 6. When False, orchestrator always uses
    # rule-based fallback planner. Default True.
    step6_ai_enabled: bool = True

    # --- Telemetry Discovery (Step 1.3) ---
    # Enable/disable telemetry discovery stage
    telemetry_discovery_enabled: bool = True
    # Timeout per source in seconds
    telemetry_discovery_timeout: int = 30
    # Cache TTL for raw log samples (7 days)
    telemetry_cache_ttl_seconds: int = 604800
    # Minimum sources required to proceed (default: 1)
    telemetry_gate_min_sources: int = 1
    # Block pipeline when no sufficient telemetry (default: True per user decision)
    telemetry_gate_blocking: bool = True

    # --- MITRE STIX cache (7-day TTL, dynamic ATT&CK whitelist) ---
    # Path to the directory where the MITRE ATT&CK STIX bundle is cached.
    # The file `enterprise-attack.json` is downloaded by
    # `src.shared.mitre.fetch_stix` and consumed by `loader.py`.
    # Cache is per-host; safe to delete to force a refresh.
    mitre_cache_dir: str = ".cache/mitre_attack"
    # 7 days (604800s). STIX bundle is updated ~quarterly by MITRE; 7 days
    # gives a comfortable margin without thrashing on every run.
    mitre_cache_ttl_seconds: int = 604800
    # Disable network + dynamic STIX load; force use of the hardcoded
    # baseline whitelist (14 tactics / 99 techniques / 110 subtechniques)
    # in attack_validator.py. Useful for air-gapped envs and tests.
    mitre_offline: bool = False

    def get_analyze_model(self) -> str:
        """Resolve the model name used for the primary analyze call.

        Priority: ANALYZE_AI_MODEL > legacy AI_MODEL field.
        """
        if self.analyze_ai_model and self.analyze_ai_model.strip():
            return self.analyze_ai_model.strip()
        return self.ai_model

    def get_phase1_model(self) -> str:
        """Resolve model name for Phase 1 (behavior classification).

        Priority: PHASE1_AI_MODEL > ANALYZE_AI_MODEL > legacy AI_MODEL.
        Default không set riêng → dùng cùng model với Phase 2.
        Khi muốn tiết kiệm cost: set PHASE1_AI_MODEL=openrouter free model.
        """
        if self.phase1_ai_model and self.phase1_ai_model.strip():
            return self.phase1_ai_model.strip()
        return self.get_analyze_model()

    def get_phase1_api_keys(self) -> list[str]:
        """Return ordered list of API keys for Phase 1 AI client.

        Priority:
          1. PHASE1_AI_KEYS env var (comma-separated, round-robin)
          2. PHASE1_AI_API_KEY env var (single)
          3. Fall back to main AI keys (AI_API_KEYS / AI_API_KEY) nếu không set
        """
        raw_keys: list[str] = []
        if self.phase1_ai_keys:
            raw_keys = [k.strip() for k in self.phase1_ai_keys.split(",") if k.strip()]
        if not raw_keys and self.phase1_ai_api_key:
            stripped = self.phase1_ai_api_key.strip()
            if stripped:
                raw_keys = [stripped]
        # Fall back to main AI keys (backward compat)
        if not raw_keys:
            return self.get_api_keys()
        return raw_keys

    def get_phase1_base_url(self) -> str | None:
        """Resolve base URL for Phase 1 AI client.

        Priority: PHASE1_AI_BASE_URL > AI_BASE_URL (main).
        Khi dùng OpenRouter, set PHASE1_AI_BASE_URL=https://openrouter.ai/api/v1.
        Khi dùng Google AI Studio, set https://generativelanguage.googleapis.com/v1beta/openai/.
        """
        if self.phase1_ai_base_url and self.phase1_ai_base_url.strip():
            return self.phase1_ai_base_url.strip()
        return self.ai_base_url

    # ------------------------------------------------------------------
    # Step 4 (Telemetry Selector) — pattern mirror Phase 1.
    # ------------------------------------------------------------------

    def get_step4_model(self) -> str:
        """Resolve model name for Step 4 (telemetry selection).

        Priority: STEP4_AI_MODEL > PHASE1_AI_MODEL > ANALYZE_AI_MODEL.
        Backward compat: nếu STEP4 không set → dùng Phase 1 model
        (cùng provider Gemini 2.5 Flash trong default config).
        """
        if self.step4_ai_model and self.step4_ai_model.strip():
            return self.step4_ai_model.strip()
        return self.get_phase1_model()

    def get_step4_api_keys(self) -> list[str]:
        """Return ordered list of API keys for Step 4 AI client.

        Priority:
          1. STEP4_AI_KEYS env var (comma-separated, round-robin)
          2. STEP4_AI_API_KEY env var (single)
          3. Fall back to Phase 1 keys (PHASE1_AI_KEYS / PHASE1_AI_API_KEY)
          4. Fall back to main AI keys (AI_API_KEYS / AI_API_KEY)
        """
        raw_keys: list[str] = []
        if self.step4_ai_keys:
            raw_keys = [k.strip() for k in self.step4_ai_keys.split(",") if k.strip()]
        if not raw_keys and self.step4_ai_api_key:
            stripped = self.step4_ai_api_key.strip()
            if stripped:
                raw_keys = [stripped]
        if not raw_keys:
            # Backward compat: chia sẻ Phase 1 keys (thường cùng Gemini project).
            phase1_keys = self.get_phase1_api_keys()
            if phase1_keys:
                return phase1_keys
            return self.get_api_keys()
        return raw_keys

    def get_step4_base_url(self) -> str | None:
        """Resolve base URL for Step 4 AI client.

        Priority: STEP4_AI_BASE_URL > PHASE1_AI_BASE_URL > AI_BASE_URL (main).
        Khi dùng Google AI Studio cho Step 4, set
        STEP4_AI_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai.
        """
        if self.step4_ai_base_url and self.step4_ai_base_url.strip():
            return self.step4_ai_base_url.strip()
        phase1_url = self.get_phase1_base_url()
        if phase1_url:
            return phase1_url
        return self.ai_base_url

    def get_step6_model(self) -> str:
        """Resolve model name for Step 6 Detection Logic Planner.

        Priority: STEP6_AI_MODEL > STEP4_AI_MODEL > ANALYZE_AI_MODEL > legacy AI_MODEL.
        RECOMMEND: same provider as Step 4 (Gemini 2.0 Flash Lite) for consistency.
        Default: gemini-2.0-flash-lite.
        """
        if self.step6_ai_model and self.step6_ai_model.strip():
            return self.step6_ai_model.strip()
        step4_model = self.get_step4_model()
        if step4_model:
            return step4_model
        return self.ai_model or "gemini-2.0-flash-lite"

    def get_step6_api_keys(self) -> list[str]:
        """Resolve API keys for Step 6 AI client.

        Priority: STEP6_AI_KEYS > STEP6_AI_API_KEY > STEP4 keys > PHASE1 keys > main.
        """
        raw_keys: list[str] = []
        if self.step6_ai_keys:
            raw_keys = [k.strip() for k in self.step6_ai_keys.split(",") if k.strip()]
        if not raw_keys and self.step6_ai_api_key:
            stripped = self.step6_ai_api_key.strip()
            if stripped:
                raw_keys = [stripped]
        if not raw_keys:
            step4_keys = self.get_step4_api_keys()
            if step4_keys:
                raw_keys = step4_keys
            else:
                raw_keys = self.get_api_keys()
        return raw_keys

    def get_step6_base_url(self) -> str | None:
        """Resolve base URL for Step 6 AI client.

        Priority: STEP6_AI_BASE_URL > STEP4_AI_BASE_URL > PHASE1_AI_BASE_URL > AI_BASE_URL.
        """
        if self.step6_ai_base_url and self.step6_ai_base_url.strip():
            return self.step6_ai_base_url.strip()
        step4_url = self.get_step4_base_url()
        if step4_url:
            return step4_url
        return self.ai_base_url

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    def get_api_keys(self) -> list[str]:
        """Return ordered list of AI API keys for round-robin rotation.

        Priority:
        1. AI_API_KEYS env var (comma-separated, new format)
        2. AI_API_KEY env var (single, backward-compat)

        Returns:
            list[str]: non-empty keys in priority order. Empty if neither set.
        """
        raw_keys: list[str] = []
        if self.ai_api_keys:
            raw_keys = [k.strip() for k in self.ai_api_keys.split(",") if k.strip()]
        if not raw_keys and self.ai_api_key:
            stripped = self.ai_api_key.strip()
            if stripped:
                raw_keys = [stripped]
        return raw_keys


settings = Settings()