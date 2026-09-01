"""Audit event sinks for local disk logging and off-device remote mirroring."""

import os
import json
import queue
import time
import threading
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional, Dict, Any, Callable

from sentinel.audit.models import AuditEntry
from sentinel.audit.security_utils import apply_owner_only_dacl

logger = logging.getLogger(__name__)


class SinkError(Exception):
    """Base exception for audit sink failures."""
    pass


class LocalSinkError(SinkError):
    """Raised when the primary local audit file sink fails to write to disk."""
    pass


class AuditSink(ABC):
    """Abstract sink destination for audit log entries."""

    @abstractmethod
    def emit(self, entry: AuditEntry) -> None:
        """Sends or writes a single audit entry to the sink destination."""
        pass

    def flush(self) -> None:
        """Flushes any buffered entries."""
        pass

    def close(self) -> None:
        """Cleans up resources and closes connections."""
        pass


class LocalFileSink(AuditSink):
    """
    Appends audit log records as JSON lines to a local file with strict filesystem permissions.
    """

    def __init__(self, log_file: Path):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_file_permissions()

    def _ensure_file_permissions(self) -> None:
        """Applies restrictive permissions (0600 / Windows protected DACL)."""
        if not self.log_file.exists():
            flags = os.O_CREAT | os.O_WRONLY | os.O_APPEND
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY
            fd = os.open(self.log_file, flags, 0o600)
            os.close(fd)

        apply_owner_only_dacl(self.log_file)

    def emit(self, entry: AuditEntry) -> None:
        try:
            line = json.dumps(entry.model_dump(), separators=(",", ":")) + "\n"
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
        except Exception as e:
            logger.critical("LOCAL AUDIT LOG FAILURE: Could not write entry %d to %s: %s", entry.index, self.log_file, e)
            raise LocalSinkError(f"Failed to write to local audit log: {e}") from e


class WebhookMirrorSink(AuditSink):
    """
    Off-device audit mirror sink that forwards audit records to a remote webhook or logging endpoint.
    Includes:
    - Bounded queue to decouple network latency from core application threads.
    - Automatic exponential retries (up to max_retries).
    - Failure alerting callback (`on_failure`) so mirroring errors are logged and surfaced.
    """

    def __init__(
        self,
        endpoint_url: str,
        auth_header: Optional[str] = None,
        timeout_seconds: float = 3.0,
        max_queue_size: int = 1000,
        max_retries: int = 3,
        on_failure: Optional[Callable[[AuditEntry, Exception], None]] = None,
        on_success: Optional[Callable[[AuditEntry], None]] = None,
    ):
        self.endpoint_url = endpoint_url
        self.auth_header = auth_header
        self.timeout = timeout_seconds
        self.max_retries = max_retries
        self.on_failure = on_failure
        self.on_success = on_success
        self.queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self._stop_event = threading.Event()
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()

    def _send_payload(self, entry: AuditEntry) -> None:
        import urllib.request
        import urllib.error

        data = json.dumps(entry.model_dump(), separators=(",", ":")).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "X-Sentinel-HMAC": entry.entry_hmac,
            "X-Sentinel-Index": str(entry.index),
            "User-Agent": "Sentinel-Audit-Mirror/1.0",
        }
        if self.auth_header:
            headers["Authorization"] = self.auth_header

        last_err: Optional[Exception] = None
        for attempt in range(1, self.max_retries + 1):
            req = urllib.request.Request(self.endpoint_url, data=data, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    if 200 <= resp.status < 300:
                        if self.on_success:
                            try:
                                self.on_success(entry)
                            except Exception:
                                pass
                        return
                    else:
                        raise RuntimeError(f"Remote mirror returned HTTP {resp.status}")
            except Exception as e:
                last_err = e
                logger.warning(
                    "Audit mirror delivery attempt %d/%d for entry %d failed: %s",
                    attempt,
                    self.max_retries,
                    entry.index,
                    e,
                )
                if attempt < self.max_retries:
                    time.sleep(0.05 * (2 ** (attempt - 1)))

        logger.error(
            "CRITICAL: Off-device audit mirroring exhausted %d retries for entry %d (url: %s): %s",
            self.max_retries,
            entry.index,
            self.endpoint_url,
            last_err,
        )
        if self.on_failure and last_err:
            try:
                self.on_failure(entry, last_err)
            except Exception:
                pass

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                entry = self.queue.get(timeout=0.2)
            except queue.Empty:
                continue

            try:
                self._send_payload(entry)
            except Exception as e:
                logger.warning("Error in audit mirror worker loop: %s", e)
            finally:
                self.queue.task_done()

    def emit(self, entry: AuditEntry) -> None:
        try:
            self.queue.put_nowait(entry)
        except queue.Full:
            err = RuntimeError("Audit mirror worker queue is full; dropping oldest / cannot enqueue")
            logger.error("Audit mirror queue full; dropping off-device mirror for entry %d", entry.index)
            if self.on_failure:
                self.on_failure(entry, err)

    def flush(self) -> None:
        self.queue.join()

    def close(self) -> None:
        self.flush()
        self._stop_event.set()
        self._worker_thread.join(timeout=1.0)


class MultiSink(AuditSink):
    """
    Multiplexing sink that dispatches audit entries across primary local and secondary mirror sinks.
    Policy:
    - If a LocalFileSink raises LocalSinkError, it is re-raised immediately so local audit failure is never silent.
    - If a secondary remote/mirror sink fails, it is logged and alerted without halting local execution.
    """

    def __init__(self, sinks: List[AuditSink]):
        self.sinks = list(sinks)

    def emit(self, entry: AuditEntry) -> None:
        for sink in self.sinks:
            try:
                sink.emit(entry)
            except LocalSinkError:
                # Never swallow local audit storage failure
                raise
            except Exception as e:
                logger.error("Error emitting to secondary audit sink %s: %s", type(sink).__name__, e)

    def flush(self) -> None:
        for sink in self.sinks:
            try:
                sink.flush()
            except Exception as e:
                logger.error("Error flushing sink %s: %s", type(sink).__name__, e)

    def close(self) -> None:
        for sink in self.sinks:
            try:
                sink.close()
            except Exception as e:
                logger.error("Error closing sink %s: %s", type(sink).__name__, e)
