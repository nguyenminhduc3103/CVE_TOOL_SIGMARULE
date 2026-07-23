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
    # Retry path override: use a different provider (e.g. Gemini 1M TPM) to
    # avoid Groq's 6K TPM ceiling. If RETRY_AI_API_KEY is empty, retries fall
    # back to the primary ai_api_key/ai_base_url.
    retry_ai_api_key: str | None = None
    retry_ai_base_url: str | None = None

    # --- Response cache (NVD / KEV / EPSS, 24h TTL) ---
    # Stdlib-only file cache; can be disabled per-process via CVE_TI_CACHE=0.
    cache_enabled: bool = True
    cache_ttl_seconds: int = 86400  # 24h
    cache_dir: str = ".cache/cve_responses"
    # Primary (analyze) model name. Backed by env ANALYZE_AI_MODEL. Falls back
    # to the legacy `ai_model` field if a caller still sets the old key.
    ai_model: str = "llama-3.3-70b-versatile"
    analyze_ai_model: str | None = None
    # Retry model name. Backed by env RETRY_AI_MODEL. Used for the partial-fill
    # retry path; falls back to `analyze_ai_model` (or `ai_model`) if unset.
    retry_ai_model: str | None = None

    # --- Two-phase refactor (Step 2) ---
    # Enable 2-phase flow: Phase 1 (behavior classification) → Phase 2
    # (ATT&CK mapping) instead of legacy 1-shot. Default False (backward
    # compat). Set CVE_TI_STEP2_TWO_PHASE=1 in .env to enable.
    cve_ti_step2_two_phase: bool = False
    # Phase 1 (behavior analysis) is a CLASSIFICATION task: extract
    # `execution_surface`, `delivery_vector`, `user_interaction_required`
    # from CVE description. Reasoning vừa đủ - không cần model 70B.
    # Dùng OpenRouter free model (nhiều lựa chọn: Llama 3.3 70B free, Qwen,
    # DeepSeek, Mistral) hoặc Google AI Studio free tier.
    # Falls back to analyze_ai_model nếu không set (backward compat).
    phase1_ai_model: str | None = None
    phase1_ai_base_url: str | None = None
    phase1_ai_api_key: str | None = None
    phase1_ai_keys: str | None = None  # comma-separated cho round-robin
    # Phase 2 (ATT&CK mapping) uses analyze_ai_model (default Groq llama-3.3-70b).
    # Phase 2 là REASONING task quan trọng nhất - giữ model mạnh.

    # --- MITRE STIX + CAPEC cache (7-day TTL, dynamic ATT&CK whitelist) ---
    # Path to the directory where MITRE STIX + CAPEC bundles are cached.
    # Files inside (enterprise-attack.json, capec_stix.json) are downloaded
    # by `app.shared.mitre.fetch_stix` and consumed by `loader.py` /
    # `capec_hint.py`. Cache is per-host; safe to delete to force a refresh.
    # Note: the capec_stix.json file is kept for `capec_hint` (CWE→CAPEC
    # inspiration queries), NOT for ground-truth validation. Old
    # ground_truth_sources/ directory (4.3MB CAPEC + 34KB CTID + script)
    # was removed in Phase 4 since compute_ground_truth/coverage is gone.
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

    def get_retry_model(self) -> str:
        """Resolve the model name used for the retry call.

        Priority: RETRY_AI_MODEL > ANALYZE_AI_MODEL > legacy AI_MODEL field.
        """
        if self.retry_ai_model and self.retry_ai_model.strip():
            return self.retry_ai_model.strip()
        return self.get_analyze_model()

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

    def get_two_phase_enabled(self) -> bool:
        """Whether the 2-phase Step 2 flow is enabled (CVE_TI_STEP2_TWO_PHASE).

        Reads from the Settings field (pydantic-settings parses "1"/"true"/"yes"
        as True automatically for bool). Use this instead of os.getenv() — env
        vars are NOT auto-injected into os.environ by pydantic-settings.
        """
        return bool(self.cve_ti_step2_two_phase)

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
