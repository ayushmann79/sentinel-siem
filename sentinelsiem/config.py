"""Application settings — all values sourced from environment / .env file."""

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Application
    app_name: str = "SentinelSIEM"
    app_version: str = "2.0.0"
    app_env: str = "development"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    debug: bool = False

    # Security
    secret_key: str = "insecure-dev-key-change-in-production"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # CORS
    allowed_origins: list[str] = ["http://localhost:8000", "http://localhost:3000"]

    # Database
    duckdb_path: str = "./data/sentinel.duckdb"
    duckdb_memory_limit: str = "4GB"
    duckdb_threads: int = 4

    # Ingestion
    max_batch_size: int = 10_000
    ingest_queue_size: int = 50_000
    syslog_port: int = 514

    # Correlation
    rules_path: str = "./config/correlation_rules.yaml"
    correlation_window_seconds: int = 300

    # Alerting
    alert_dedup_window_seconds: int = 300
    webhook_url: str = ""
    webhook_secret: str = ""

    # Admin (created on first boot)
    admin_username: str = "admin"
    admin_password: str = "SentinelAdmin@2024"
    admin_email: str = "admin@sentinel.local"

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
