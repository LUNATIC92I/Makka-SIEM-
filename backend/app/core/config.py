"""Application configuration.

All settings can be overridden with environment variables prefixed with
``MAKKADI_`` or through a ``.env`` file located in the working directory or in
the data directory. Secrets (API keys, tokens) are never read from this file
for connectors: they are stored encrypted with the master key (see
``app.security.secrets``).
"""

from __future__ import annotations

import ipaddress
import os
import sys
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

APP_VERSION = "0.1.0"


def _default_data_dir() -> Path:
    """Per-user data directory (``%APPDATA%\\MAKKADi`` on Windows)."""
    if sys.platform == "win32" and os.environ.get("APPDATA"):
        return Path(os.environ["APPDATA"]) / "MAKKADi"
    return Path.home() / ".makkadi"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="MAKKADI_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- Branding -----------------------------------------------------------------
    app_name: str = "MAKKADi"
    app_tagline: str = "OSINT Intelligence for SOC analysts"

    # --- Runtime ------------------------------------------------------------------
    environment: Literal["development", "production", "test"] = "production"
    host: str = "127.0.0.1"
    port: int = 8765
    allow_remote_bind: bool = False
    data_dir: Path = Field(default_factory=_default_data_dir)
    database_url: str | None = None  # default: sqlite file in data_dir
    static_dir: Path | None = None  # built frontend (served at /)
    log_level: str = "INFO"
    cors_origins: list[str] = []

    # --- Security -----------------------------------------------------------------
    jwt_secret: str | None = None  # default: generated and persisted in data_dir
    master_key: str | None = None  # Fernet key for connector secrets
    access_token_ttl_minutes: int = 60
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    rate_limit_per_minute: int = 240
    login_rate_limit_per_minute: int = 10
    webhook_max_skew_seconds: int = 300
    # Outbound connections to private/internal networks are refused unless the
    # destination host is explicitly listed here (e.g. an on-premise SIEM).
    outbound_allowed_hosts: list[str] = []
    outbound_allowed_cidrs: list[str] = []

    # --- Features -----------------------------------------------------------------
    demo_mode: bool = True
    worker_enabled: bool = True
    worker_poll_seconds: float = 1.0
    scheduler_tick_seconds: float = 15.0
    http_timeout_seconds: float = 20.0
    auto_investigate_min_severity: Literal["info", "low", "medium", "high", "critical"] = "low"

    # Active (non-passive) checks: disabled by default, restricted to allow-listed CIDRs.
    active_checks_enabled: bool = False
    active_checks_allowed_cidrs: list[str] = []
    active_checks_allowed_ports: list[int] = [22, 80, 443, 3389]

    # --- AI -----------------------------------------------------------------------
    ai_provider: Literal["none", "deterministic", "anthropic", "openai_compatible"] = "deterministic"
    ai_model: str | None = None
    ai_base_url: str | None = None  # openai_compatible endpoint (e.g. local Ollama/vLLM)
    # Investigation data may only be sent to a non-local AI provider when this
    # is explicitly set to true (data processing policy acknowledged).
    ai_external_processing_allowed: bool = False
    ai_pseudonymize: bool = True
    ai_timeout_seconds: float = 120.0

    # --- Data retention -----------------------------------------------------------
    retention_days: int = 365
    raw_payload_max_bytes: int = 200_000

    @field_validator("data_dir", mode="before")
    @classmethod
    def _expand(cls, v: object) -> object:
        if isinstance(v, str):
            return Path(os.path.expandvars(os.path.expanduser(v)))
        return v

    @field_validator("outbound_allowed_cidrs", "active_checks_allowed_cidrs")
    @classmethod
    def _valid_cidrs(cls, v: list[str]) -> list[str]:
        for cidr in v:
            ipaddress.ip_network(cidr, strict=False)
        return v

    @property
    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite:///{(self.data_dir / 'makkadi.db').as_posix()}"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def check_bind_address(self) -> None:
        """Refuse to listen on a non-loopback interface unless explicitly allowed."""
        try:
            is_loopback = ipaddress.ip_address(self.host).is_loopback
        except ValueError:
            is_loopback = self.host == "localhost"
        if not is_loopback and not self.allow_remote_bind:
            raise RuntimeError(
                f"Refusing to bind to {self.host}: set MAKKADI_ALLOW_REMOTE_BIND=true "
                "to expose the server beyond the local machine."
            )


@lru_cache
def get_settings() -> Settings:
    """Settings from environment, ``./.env`` and ``<data_dir>/.env`` (environment wins)."""
    base = Settings()
    data_env = base.data_dir / ".env"
    if data_env.is_file():
        return Settings(_env_file=(data_env, ".env"))  # type: ignore[call-arg]
    return base
