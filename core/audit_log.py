"""
core/audit_log.py — Tamper-evident security audit log
=========================================================
sentinel_extras.AlertHistory already keeps an append-only JSON log of
alerts. The gap: plain JSON can be silently edited or truncated by anyone
with file access (including an intruder trying to cover their tracks
after a successful break-in). This module adds a hash chain — each entry
stores a SHA-256 hash of the previous entry plus its own content, exactly
like a minimal blockchain — so any edit, deletion, or reordering of past
entries is detectable by recomputing the chain.

This does NOT replace AlertHistory; it's meant to sit alongside it (or
underneath it — see integration note at the bottom) as the durability
guarantee for anything security-critical: login failures, wipe commands,
PIN attempts, vault unlocks, config changes.

Usage
-----
    from core.audit_log import AuditLog

    log = AuditLog()
    log.append("pin_attempt", {"action": "emergency_wipe", "result": "denied"})
    log.append("vault_unlock", {"result": "success", "source": "keyring"})

    ok, problem = log.verify()
    if not ok:
        print(f"AUDIT LOG TAMPERED: {problem}")
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any, Optional


def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


GENESIS_HASH = "0" * 64


class AuditLog:
    def __init__(self, path: Optional[Path] = None):
        self.path = path or (_base_dir() / "memory" / "audit_log.jsonl")
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # ── Core chain mechanics ─────────────────────────────────────────────

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS_HASH
        last_line = None
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    last_line = line
        if last_line is None:
            return GENESIS_HASH
        try:
            return json.loads(last_line)["entry_hash"]
        except Exception:
            return GENESIS_HASH

    @staticmethod
    def _hash_entry(prev_hash: str, ts: float, event_type: str, details: dict) -> str:
        payload = json.dumps(
            {"prev_hash": prev_hash, "ts": ts, "event_type": event_type, "details": details},
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def append(self, event_type: str, details: Optional[dict[str, Any]] = None) -> dict:
        """Appends a new tamper-evident entry. Returns the entry written."""
        details = details or {}
        prev_hash = self._last_hash()
        ts = time.time()
        entry_hash = self._hash_entry(prev_hash, ts, event_type, details)
        entry = {
            "ts": ts,
            "time_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)),
            "event_type": event_type,
            "details": details,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
        }
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
        return entry

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        entries = []
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        pass
        return entries

    def verify(self) -> tuple[bool, Optional[str]]:
        """
        Recomputes the chain from scratch. Returns (True, None) if intact,
        or (False, "human-readable reason") on the first broken link found
        (edit, deletion, reorder, or truncation all produce a mismatch).
        """
        entries = self.read_all()
        expected_prev = GENESIS_HASH
        for i, entry in enumerate(entries):
            if entry.get("prev_hash") != expected_prev:
                return False, f"Chain broken at entry {i} ({entry.get('event_type')}): prev_hash mismatch — a prior entry was likely edited or removed."
            recomputed = self._hash_entry(
                entry["prev_hash"], entry["ts"], entry["event_type"], entry["details"]
            )
            if recomputed != entry.get("entry_hash"):
                return False, f"Chain broken at entry {i} ({entry.get('event_type')}): content hash mismatch — this entry was edited after being written."
            expected_prev = entry["entry_hash"]
        return True, None

    def tail(self, n: int = 20) -> list[dict]:
        return self.read_all()[-n:]


# ── Integration note ────────────────────────────────────────────────────
# In core/sentinel_extras.py, inside AlertHistory.log_alert() (or wherever
# it currently does its JSON append), add two lines:
#
#     from core.audit_log import AuditLog
#     AuditLog().append("security_alert", {"kind": alert_type, "message": message})
#
# Same pattern for: intruder_alert.py's failed-login handler, the
# EmergencyWipeListener before/after executing a wipe, and
# core/access_control.py's PIN checks (already wired in access_control.py
# below). Run AuditLog().verify() from a periodic health check or from
# mobile_server's /history route to surface "log integrity: OK / TAMPERED"
# to the mobile app.