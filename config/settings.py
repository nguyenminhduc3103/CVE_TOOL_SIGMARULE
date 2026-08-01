from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    env: str = "development"
    nvd_api_url: str = "https://services.nvd.nist.gov"
    nvd_api_key: str | None = None
    kev_api_url: str = "https://www.cisa.gov/known-exploited-vulnerabilities"
    epss_api_url: str = "https://epss.example"

    # --- OpenCTI Integration ---
    opencti_url: str = "http://localhost:8080"
    opencti_cookie: str | None = None
    opencti_token: str | None = None
    opencti_taxii_collection_id: str | None = None
    opencti_username: str | None = None
    opencti_password: str | None = None

    # --- AlienVault OTX Integration ---
    otx_api_url: str = "https://otx.alienvault.com"
    otx_api_key: str | None = None

    # --- AI service (V1: OpenAI-compatible: Groq / Anthropic / Ollama) ---
    ai_enabled: bool = False
    ai_api_key: str | None = None
    # Comma-separated keys for round-robin; takes precedence over ai_api_key
    ai_api_keys: str | None = None
    ai_base_url: str | None = None

    # --- Response cache (NVD/KEV/EPSS, 24h TTL; disable via CVE_TI_CACHE=0) ---
    cache_enabled: bool = True
    cache_ttl_seconds: int = 86400  # 24h
    cache_dir: str = ".cache/cve_responses"

    # --- Phase 2 analyze model (env ANALYZE_AI_MODEL; legacy AI_MODEL fallback) ---
    ai_model: str = "llama-3.3-70b-versatile"
    analyze_ai_model: str | None = None

    # --- Phase 2 ATT&CK Mapping (separate from Phase 1) ---
    phase2_ai_model: str | None = None
    phase2_ai_base_url: str | None = None
    phase2_ai_api_key: str | None = None
    phase2_ai_keys: str | None = None

    # --- Two-phase Step 2 (Phase 1: classification; Phase 2: ATT&CK mapping) ---
    # Phase 1 extracts execution_surface / delivery_vector / user_interaction_required.
    # Phase 2 (ATT&CK) reuses analyze_ai_model — strong reasoning required.
    phase1_ai_model: str | None = None
    phase1_ai_base_url: str | None = None
    phase1_ai_api_key: str | None = None
    phase1_ai_keys: str | None = None  # comma-separated for round-robin

    # --- Step 4 (Telemetry Selector) — Gemini 2.5 Flash recommended ---
    # CLASSIFICATION + constrained emission: choose from Sigma taxonomy whitelist.
    step4_ai_model: str | None = None
    step4_ai_base_url: str | None = None
    step4_ai_api_key: str | None = None
    step4_ai_keys: str | None = None  # comma-separated

    # --- Step 6 (Sigma Rule Generation) — mirror Step 4 pattern ---
    # AI emits semantic intent; code layer handles Sigma emission.
    step6_ai_model: str | None = None
    step6_ai_base_url: str | None = None
    step6_ai_api_key: str | None = None
    step6_ai_keys: str | None = None
    # False → orchestrator uses rule-based fallback planner
    step6_ai_enabled: bool = True

    # --- Telemetry Discovery (Step 1.3) ---
    telemetry_discovery_enabled: bool = True
    telemetry_discovery_timeout: int = 30  # per source
    telemetry_cache_ttl_seconds: int = 604800  # 7 days
    telemetry_gate_min_sources: int = 1
    # True → block pipeline when insufficient telemetry
    telemetry_gate_blocking: bool = True

    # --- Nuclei evidence crawl (Step 1 ingestion) ---
    nuclei_crawl_enabled: bool = True
    nuclei_evidence_cache_dir: str = ".cache/nuclei_evidence"
    nuclei_crawl_max_evidence: int = 50
    # Timeout owned by tools.crawl_evidence.crawl() — no setting needed

    # --- MITRE STIX cache (7-day TTL, dynamic ATT&CK whitelist) ---
    # `enterprise-attack.json` downloaded by src.shared.mitre.fetch_stix;
    # used by loader.py. Delete to force refresh.
    mitre_cache_dir: str = ".cache/mitre_attack"
    # 7d — STIX bundle updates ~quarterly
    mitre_cache_ttl_seconds: int = 604800
    # True → skip network STIX; use hardcoded baseline whitelist in attack_validator
    mitre_offline: bool = False

    def get_analyze_model(self) -> str:
        """Resolve the model name used for the primary analyze call.

        Priority: ANALYZE_AI_MODEL > legacy AI_MODEL field.
        """
        if self.analyze_ai_model and self.analyze_ai_model.strip():
            return self.analyze_ai_model.strip()
        return self.ai_model

    def get_phase2_model(self) -> str:
        """Resolve model name for Phase 2 ATT&CK mapping.

        Priority: PHASE2_AI_MODEL > ANALYZE_AI_MODEL > legacy AI_MODEL.
        """
        if self.phase2_ai_model and self.phase2_ai_model.strip():
            return self.phase2_ai_model.strip()
        return self.get_analyze_model()

    def get_phase2_api_keys(self) -> list[str]:
        """Return ordered list of API keys for Phase 2 AI client."""
        raw_keys: list[str] = []
        if self.phase2_ai_keys:
            raw_keys = [k.strip() for k in self.phase2_ai_keys.split(",") if k.strip()]
        if not raw_keys and self.phase2_ai_api_key:
            stripped = self.phase2_ai_api_key.strip()
            if stripped:
                raw_keys = [stripped]
        if not raw_keys:
            return self.get_api_keys()
        return raw_keys

    def get_phase2_base_url(self) -> str | None:
        """Resolve base URL for Phase 2 AI client."""
        if self.phase2_ai_base_url and self.phase2_ai_base_url.strip():
            return self.phase2_ai_base_url.strip()
        return self.ai_base_url

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