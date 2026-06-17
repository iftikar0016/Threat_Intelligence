from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_extra="ignore", env_file_encoding="utf-8")

    vt_api_key: str = ""
    otx_api_key: str = ""
    redis_url: str = "redis://localhost:6379/0"
    cache_ttl_seconds: int = 3600  # 1 hour by default
    allowed_origins: str = "*"


settings = Settings()
