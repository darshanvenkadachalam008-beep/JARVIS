"""
core/proactive_bridge.py — Unified Proactive Push Engine
=========================================================
Coordinates proactive triggers (Calendar, Briefing, Security, Habits)
across voice, UI, mobile, telegram, and audit log channels.

Features:
  1. Priority-based gating: CRITICAL (security/duress), HIGH (calendar),
     NORMAL (scheduled briefing), LOW (ambient glance/habits).
  2. Loop-independent out-of-band delivery: CRITICAL events fan out to
     Audit, Telegram, Mobile, and UI in dedicated background threads
     without waiting on or blocking the main asyncio event loop.
  3. Reuses Phase 2 _interrupt_playback for CRITICAL voice delivery.
  4. State-aware queueing with TTL expiration: queues HIGH/NORMAL events
     when JARVIS is speaking/thinking and drains them when speech finishes.
  5. Bounded, TTL-evicted deduplication cache to prevent duplicate alerts.
"""

from __future__ import annotations

import enum
import heapq
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("JARVIS.ProactiveBridge")


class ProactivePriority(enum.IntEnum):
    CRITICAL = 10   # Immediate security alarm, duress, unauthorized tamper
    HIGH     = 20   # Time-sensitive calendar meeting reminder (10m out)
    NORMAL   = 30   # Scheduled daily briefing, weather warnings
    LOW      = 40   # Ambient vision glance, background habit suggestion


@dataclass(order=True)
class PrioritizedQueueItem:
    priority: int
    created_at: float
    event: "ProactiveEvent" = field(compare=False)


@dataclass
class ProactiveEvent:
    category: str                                       # "calendar", "security", "briefing", "habit"
    title: str                                          # Short summary / subject
    message: str                                        # Full human-readable text
    priority: ProactivePriority = ProactivePriority.NORMAL
    data: Dict[str, Any] = field(default_factory=dict)
    ttl_seconds: float = 600.0                          # Bounded lifetime before expiring if queued
    dedup_key: Optional[str] = None                     # Distinct key for deduplication
    channels: Set[str] = field(default_factory=lambda: {"voice", "ui"})
    created_at: float = field(default_factory=time.time)

    def is_expired(self, now: Optional[float] = None) -> bool:
        t = now if now is not None else time.time()
        return (t - self.created_at) > self.ttl_seconds


class BoundedDedupCache:
    """Thread-safe bounded deduplication cache with TTL-based eviction."""

    def __init__(self, max_size: int = 500):
        self._max_size = max_size
        self._entries: Dict[str, float] = {}  # key -> expiry_timestamp
        self._lock = threading.Lock()

    def check_and_add(self, key: str, ttl_seconds: float) -> bool:
        """
        Returns True if the key is new (and records it with expiry).
        Returns False if an active, unexpired entry for key already exists.
        """
        now = time.time()
        with self._lock:
            # 1. Prune expired entries
            expired_keys = [k for k, exp in self._entries.items() if now > exp]
            for k in expired_keys:
                del self._entries[k]

            # 2. Check if key is already active
            if key in self._entries:
                return False

            # 3. Enforce size cap (FIFO eviction if over capacity)
            if len(self._entries) >= self._max_size:
                oldest_key = min(self._entries, key=self._entries.get)
                del self._entries[oldest_key]

            # 4. Insert new entry
            self._entries[key] = now + ttl_seconds
            return True

    def clear(self):
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


class ProactiveBridge:
    """
    Central dispatcher coordinating proactive push events to voice, UI,
    mobile companion, telegram, and hash-chained audit sinks.
    """

    def __init__(
        self,
        get_state: Optional[Callable[[], str]] = None,
        voice_sink: Optional[Callable[[str], None]] = None,
        ui_sink: Optional[Callable[[str], None]] = None,
        mobile_sink: Optional[Callable[[str, Optional[bytes]], None]] = None,
        telegram_sink: Optional[Callable[[str, Optional[bytes]], None]] = None,
        audit_sink: Optional[Callable[[str, str, Dict[str, Any]], None]] = None,
        interrupt_sink: Optional[Callable[[], None]] = None,
        dedup_max_size: int = 500,
    ):
        self._get_state = get_state or (lambda: "LISTENING")
        self._voice_sink = voice_sink
        self._ui_sink = ui_sink
        self._mobile_sink = mobile_sink
        self._telegram_sink = telegram_sink
        self._audit_sink = audit_sink
        self._interrupt_sink = interrupt_sink

        self._dedup = BoundedDedupCache(max_size=dedup_max_size)
        self._queue: List[PrioritizedQueueItem] = []
        self._queue_lock = threading.RLock()

    # ── Channel Setters ───────────────────────────────────────────────────────

    def set_voice_sink(self, sink: Callable[[str], None]):
        self._voice_sink = sink

    def set_ui_sink(self, sink: Callable[[str], None]):
        self._ui_sink = sink

    def set_mobile_sink(self, sink: Callable[[str, Optional[bytes]], None]):
        self._mobile_sink = sink

    def set_telegram_sink(self, sink: Callable[[str, Optional[bytes]], None]):
        self._telegram_sink = sink

    def set_audit_sink(self, sink: Callable[[str, str, Dict[str, Any]], None]):
        self._audit_sink = sink

    def set_interrupt_sink(self, sink: Callable[[], None]):
        self._interrupt_sink = sink

    def set_state_fn(self, fn: Callable[[], str]):
        self._get_state = fn

    # ── Dispatching ───────────────────────────────────────────────────────────

    def dispatch(self, event: ProactiveEvent) -> bool:
        """
        Dispatches a proactive event across configured channels.
        Returns True if dispatched or queued; False if dropped as duplicate or expired.
        """
        if event.is_expired():
            logger.info("Proactive event '%s' expired before dispatch; dropping", event.title)
            return False

        dedup_key = event.dedup_key or f"{event.category}:{event.title}:{event.message}"
        if not self._dedup.check_and_add(dedup_key, event.ttl_seconds):
            logger.debug("Proactive event '%s' dropped by dedup cache", dedup_key)
            return False

        # ── 1. Loop-Independent Out-of-Band Delivery (Audit, Mobile, Telegram, UI) ──
        # CRITICAL and out-of-band notifications are fanned out in dedicated worker
        # threads so they NEVER block on or wait for the main asyncio event loop.
        if "audit" in event.channels and self._audit_sink:
            self._dispatch_async_audit(event)

        if "telegram" in event.channels and self._telegram_sink:
            self._dispatch_async_telegram(event)

        if "mobile" in event.channels and self._mobile_sink:
            self._dispatch_async_mobile(event)

        if "ui" in event.channels and self._ui_sink:
            try:
                self._ui_sink(f"PROACTIVE: [{event.category.upper()}] {event.message}")
            except Exception as e:
                logger.error("UI sink error: %s", e)

        # ── 2. Voice Delivery & State-Gated Queueing ───────────────────────────
        if "voice" in event.channels and self._voice_sink:
            self._dispatch_voice(event)

        return True

    def _dispatch_voice(self, event: ProactiveEvent):
        """Routes voice injection based on priority and conversational state."""
        state = (self._get_state() or "LISTENING").upper()
        is_busy = state in ("SPEAKING", "THINKING")

        if event.priority == ProactivePriority.CRITICAL:
            # Immediate interruption of ongoing playback using Phase 2 interrupt
            if self._interrupt_sink:
                try:
                    self._interrupt_sink()
                except Exception as e:
                    logger.error("Interrupt sink error on critical dispatch: %s", e)
            try:
                self._voice_sink(event.message)
            except Exception as e:
                logger.error("Voice sink error on critical dispatch: %s", e)

        elif event.priority == ProactivePriority.HIGH:
            if is_busy:
                # Queue with bounded TTL; flush when speech finishes
                with self._queue_lock:
                    heapq.heappush(self._queue, PrioritizedQueueItem(event.priority, event.created_at, event))
                if self._ui_sink:
                    self._ui_sink(f"SYS: Proactive reminder ({event.title}) deferred — speech in progress")
            else:
                try:
                    self._voice_sink(event.message)
                except Exception as e:
                    logger.error("Voice sink error on high-priority dispatch: %s", e)

        elif event.priority == ProactivePriority.NORMAL:
            if is_busy:
                with self._queue_lock:
                    heapq.heappush(self._queue, PrioritizedQueueItem(event.priority, event.created_at, event))
            else:
                try:
                    self._voice_sink(event.message)
                except Exception as e:
                    logger.error("Voice sink error on normal-priority dispatch: %s", e)

        elif event.priority == ProactivePriority.LOW:
            if not is_busy:
                try:
                    self._voice_sink(event.message)
                except Exception as e:
                    logger.error("Voice sink error on low-priority dispatch: %s", e)
            # Low priority is dropped rather than queued if busy to prevent stale clutter

    # ── State Transition & Queue Draining ─────────────────────────────────────

    def on_state_change(self, new_state: str):
        """
        Called when JARVIS transitions state (e.g. from SPEAKING to LISTENING).
        Drains pending queued events in priority order if the new state is idle.
        """
        state = (new_state or "").upper()
        if state not in ("LISTENING", "SLEEPING"):
            return

        with self._queue_lock:
            now = time.time()
            while self._queue:
                item = heapq.heappop(self._queue)
                event = item.event
                if event.is_expired(now):
                    logger.info("Queued proactive event '%s' expired in queue; dropping", event.title)
                    continue

                # Deliver the top valid queued item
                if self._voice_sink:
                    try:
                        self._voice_sink(event.message)
                    except Exception as e:
                        logger.error("Voice sink error while draining proactive queue: %s", e)
                break  # Drain one event per state transition to prevent speech flooding

    # ── Loop-Independent Out-of-Band Worker Threads ───────────────────────────

    def _dispatch_async_audit(self, event: ProactiveEvent):
        def _worker():
            try:
                self._audit_sink(
                    event.category,
                    "proactive_bridge",
                    {"title": event.title, "message": event.message, "priority": int(event.priority), **event.data},
                )
            except Exception as e:
                logger.error("Async audit dispatch error: %s", e)
        threading.Thread(target=_worker, name="ProactiveAuditWorker", daemon=True).start()

    def _dispatch_async_telegram(self, event: ProactiveEvent):
        def _worker():
            try:
                jpeg = event.data.get("jpeg_bytes")
                self._telegram_sink(event.message, jpeg)
            except Exception as e:
                logger.error("Async telegram dispatch error: %s", e)
        threading.Thread(target=_worker, name="ProactiveTelegramWorker", daemon=True).start()

    def _dispatch_async_mobile(self, event: ProactiveEvent):
        def _worker():
            try:
                jpeg = event.data.get("jpeg_bytes")
                self._mobile_sink(event.message, jpeg)
            except Exception as e:
                logger.error("Async mobile dispatch error: %s", e)
        threading.Thread(target=_worker, name="ProactiveMobileWorker", daemon=True).start()
