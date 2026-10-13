"""Configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import find_dotenv, load_dotenv

load_dotenv(find_dotenv(usecwd=True))


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True)
class Config:
    api_key: str
    default_org_id: str
    base_url: str
    timeout: float
    log_level: str
    http_host: str
    http_port: int

    @classmethod
    def from_env(cls) -> Config:
        api_key = os.getenv("THREATLOCKER_API_KEY", "").strip()
        if not api_key:
            raise ConfigError(
                "THREATLOCKER_API_KEY is required. Set it in your environment or .env file."
            )

        default_org_id = os.getenv("THREATLOCKER_ORG_ID", "").strip()
        if not default_org_id:
            raise ConfigError("THREATLOCKER_ORG_ID is required (your default organization GUID).")

        base_url = (
            os.getenv("THREATLOCKER_BASE_URL", "https://portalapi.g.threatlocker.com")
            .strip()
            .rstrip("/")
        )
        if not base_url.startswith(("http://", "https://")):
            raise ConfigError(
                f"THREATLOCKER_BASE_URL must start with http:// or https:// (got {base_url!r})"
            )

        try:
            timeout = float(os.getenv("THREATLOCKER_TIMEOUT", "30"))
        except ValueError as e:
            raise ConfigError(f"THREATLOCKER_TIMEOUT must be a number: {e}") from e

        log_level = os.getenv("LOG_LEVEL", "INFO").upper()

        http_host = os.getenv("MCP_HTTP_HOST", "127.0.0.1")
        try:
            http_port = int(os.getenv("MCP_HTTP_PORT", "8765"))
        except ValueError as e:
            raise ConfigError(f"MCP_HTTP_PORT must be an integer: {e}") from e

        return cls(
            api_key=api_key,
            default_org_id=default_org_id,
            base_url=base_url,
            timeout=timeout,
            log_level=log_level,
            http_host=http_host,
            http_port=http_port,
        )


_config: Config | None = None


def get_config() -> Config:
    """Return the lazily-loaded global config."""
    global _config
    if _config is None:
        _config = Config.from_env()
    return _config
