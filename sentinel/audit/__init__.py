"""Sentinel Audit package: tamper-evident hash-chained audit logging."""

from sentinel.audit.models import AuditEntry, GENESIS_HASH
from sentinel.audit.sinks import AuditSink, LocalFileSink, WebhookMirrorSink, MultiSink
from sentinel.audit.chain import AuditLogger, AuditError, ChainIntegrityError

__all__ = [
    "AuditEntry",
    "GENESIS_HASH",
    "AuditSink",
    "LocalFileSink",
    "WebhookMirrorSink",
    "MultiSink",
    "AuditLogger",
    "AuditError",
    "ChainIntegrityError",
]
