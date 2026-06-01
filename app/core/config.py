from pydantic import BaseSettings


class Settings(BaseSettings):
    env: str = "development"
    nvd_api_url: str = "https://services.nvd.nist.gov"
    kev_api_url: str = "https://www.cisa.gov/known-exploited-vulnerabilities"
    epss_api_url: str = "https://epss.example"

    class Config:
        env_file = ".env"


settings = Settings()
