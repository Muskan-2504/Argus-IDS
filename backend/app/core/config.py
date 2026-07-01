"""Application configuration, loaded from environment / `.env`."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# Resolve .env by absolute path (backend/.env) so it is found no matter which
# directory the process is launched from — otherwise a stray CWD silently falls
# back to the production Postgres default below. Missing file is fine; ignored.
_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=_ENV_FILE, env_file_encoding="utf-8", extra="ignore")

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

    # Optional enrichment integrations (all graceful — null when unconfigured)
    abuseipdb_api_key: str | None = None
    geoip_db_path: str | None = None  # path to a MaxMind GeoLite2-City .mmdb
    geoip_use_ipapi: bool = False  # opt-in free, key-less geo via ip-api.com


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
