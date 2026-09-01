"""Pydantic data models and canonical hashing for the Audit Logger."""

import json
import hmac
import hashlib
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


GENESIS_HASH = "0" * 64


class AuditEntry(BaseModel):
    """
    Immutable, hash-chained, HMAC-signed audit log record.
    """
    index: int = Field(..., ge=0, description="Monotonically increasing sequence number")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp")
    event_type: str = Field(..., description="Classification of the security event")
    actor: str = Field(default="system", description="User, process, or agent responsible")
    tier: Optional[str] = Field(default=None, description="Security tier or clearance context")
    details: Dict[str, Any] = Field(default_factory=dict, description="Structured event payload")
    prev_hash: str = Field(..., description="SHA-256 hex hash of the preceding entry in the chain")
    key_version: int = Field(default=1, ge=1, description="Version of HMAC key used to sign this record")
    entry_hmac: str = Field(..., description="HMAC-SHA256 signature of canonical payload")

    def canonical_bytes(self) -> bytes:
        """
        Produces deterministic canonical bytes of the entry payload (excluding entry_hmac).
        Uses sorted keys and compact separators to ensure cross-platform hash reproducibility.
        """
        payload = {
            "index": self.index,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "actor": self.actor,
            "tier": self.tier,
            "details": self.details,
            "prev_hash": self.prev_hash,
            "key_version": self.key_version,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def compute_sha256(self) -> str:
        """Calculates SHA-256 hash over the full entry including its HMAC signature."""
        full_payload = self.model_dump()
        canonical = json.dumps(full_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    @classmethod
    def create(
        cls,
        index: int,
        timestamp: str,
        event_type: str,
        actor: str,
        tier: Optional[str],
        details: Dict[str, Any],
        prev_hash: str,
        hmac_key: bytes,
        key_version: int = 1,
    ) -> "AuditEntry":
        """Factory method that calculates the HMAC signature and instantiates an AuditEntry."""
        temp_entry = cls(
            index=index,
            timestamp=timestamp,
            event_type=event_type,
            actor=actor,
            tier=tier,
            details=details,
            prev_hash=prev_hash,
            key_version=key_version,
            entry_hmac="",
        )
        canonical = temp_entry.canonical_bytes()
        calculated_hmac = hmac.new(hmac_key, canonical, hashlib.sha256).hexdigest()
        return cls(
            index=index,
            timestamp=timestamp,
            event_type=event_type,
            actor=actor,
            tier=tier,
            details=details,
            prev_hash=prev_hash,
            key_version=key_version,
            entry_hmac=calculated_hmac,
        )

    def verify_hmac(self, hmac_key: bytes) -> bool:
        """Verifies that entry_hmac matches the canonical payload re-signed with hmac_key."""
        canonical = self.canonical_bytes()
        expected = hmac.new(hmac_key, canonical, hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.entry_hmac, expected)
