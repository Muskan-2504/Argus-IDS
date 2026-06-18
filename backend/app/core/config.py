"""Application configuration, loaded from environment / `.env`."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "Argus IDS"
    environment: str = "development"
    debug: bool = True

    # Security
    secret_key: str = "change-me-in-production"
    access_token_expire_minutes: int = 60
    jwt_algorithm: str = "HS256"

    # Persistence / cache
    database_url: str = "postgresql+psycopg://argus:argus@localhost:5432/argus"
    redis_url: str = "redis://localhost:6379/0"

    # CORS
    cors_origins: list[str] = ["http://localhost:5173"]

    # Optional enrichment integrations
    abuseipdb_api_key: str | None = None
    geoip_db_path: str | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
