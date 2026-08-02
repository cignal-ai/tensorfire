"""Runtime configuration, sourced from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


@dataclass(frozen=True)
class Settings:
    host: str = os.environ.get("TENSORFIRE_HOST", "0.0.0.0")
    port: int = _int("TENSORFIRE_PORT", 8000)
    # "streamable-http" (server-over-network, the container default) or "stdio"
    # for local single-client use.
    transport: str = os.environ.get("TENSORFIRE_TRANSPORT", "streamable-http")
    mount_path: str = os.environ.get("TENSORFIRE_MOUNT_PATH", "/mcp")
    log_level: str = os.environ.get("TENSORFIRE_LOG_LEVEL", "INFO")


settings = Settings()
