from pydantic import BaseSettings


class Settings(BaseSettings):
    env: str = "development"
    nvd_api_url: str = "https://services.nvd.nist.gov"
    kev_api_url: str = "https://www.cisa.gov/known-exploited-vulnerabilities"
    epss_api_url: str = "https://epss.example"

    # --- AI service (V1: OpenAI-compatible: Groq / Anthropic / Ollama) ---
    ai_enabled: bool = False
    ai_api_key: str | None = None
    ai_base_url: str | None = None

    class Config:
        env_file = ".env"


settings = Settings()
