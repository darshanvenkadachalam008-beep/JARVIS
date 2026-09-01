"""Data models for Sentinel Vault metadata and configuration."""

from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class SecretMetadata(BaseModel):
    """Metadata describing a vault secret entry without revealing its contents."""
    key: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    content_type: str = "text/plain"
    custom_metadata: Dict[str, Any] = Field(default_factory=dict)
