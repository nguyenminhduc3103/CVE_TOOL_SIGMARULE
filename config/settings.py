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
    ai_model: str = "llama-3.3-70b-versatile"

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
