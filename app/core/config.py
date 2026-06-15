from pydantic.v1 import BaseSettings


class Settings(BaseSettings):
    env: str = "development"
    nvd_api_url: str = "https://services.nvd.nist.gov"
    kev_api_url: str = "https://www.cisa.gov/known-exploited-vulnerabilities"
    epss_api_url: str = "https://epss.example"

    # OpenCTI Integration
    opencti_url: str = "http://localhost:8080"
    opencti_cookie: str | None = None
    opencti_token: str | None = None
    opencti_taxii_collection_id: str | None = None
    opencti_username: str | None = None
    opencti_password: str | None = None

    class Config:
        env_file = ".env"


settings = Settings()
