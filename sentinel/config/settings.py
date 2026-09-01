"""Configuration module for Sentinel."""
from pathlib import Path
import os
from pydantic import BaseModel, Field


class SentinelSettings(BaseModel):
    """Central settings for Sentinel runtime and data paths."""
    app_name: str = "sentinel"
    base_dir: Path = Field(default_factory=lambda: Path(os.environ.get("SENTINEL_DATA_DIR", Path.home() / ".sentinel")))
    pbkdf2_iterations: int = 600_000
    lock_timeout_seconds: float = 3.0
    presence_token_ttl_seconds: int = 300  # 5 minutes

    @property
    def auth_dir(self) -> Path:
        p = self.base_dir / "auth"
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def vault_dir(self) -> Path:
        p = self.base_dir / "vault"
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def audit_dir(self) -> Path:
        p = self.base_dir / "audit"
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def watchdog_dir(self) -> Path:
        p = self.base_dir / "watchdog"
        p.mkdir(parents=True, exist_ok=True)
        return p


# Singleton / default settings instance
default_settings = SentinelSettings()
