"""
tests/test_proactive_bridge.py — Comprehensive Test Suite for Proactive Bridge
==============================================================================
Verifies:
1. Priority routing across CRITICAL, HIGH, NORMAL, and LOW priorities.
2. Interruption reuse: CRITICAL priority calls _interrupt_playback sink.
3. Loop-independent out-of-band delivery (Audit, Telegram, Mobile, UI).
4. State-aware queueing: HIGH events queue during SPEAKING/THINKING and drain on transition to LISTENING.
5. Bounded dedup cache: deduplication, max size cap enforcement, and TTL eviction.
6. TTL expiration: expired events are dropped rather than spoken late.
7. CalendarReminder natural event window integration with ProactiveBridge.
"""

import time
import threading
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from core.proactive_bridge import (
    ProactiveBridge,
    ProactiveEvent,
    ProactivePriority,
    BoundedDedupCache,
)
from core.calendar_intel import CalendarReminder


# ── 1. BoundedDedupCache Unit Tests ──────────────────────────────────────────

def test_dedup_cache_records_and_rejects_duplicates():
    cache = BoundedDedupCache(max_size=10)
    assert cache.check_and_add("key1", ttl_seconds=60.0) is True
    assert cache.check_and_add("key1", ttl_seconds=60.0) is False
    assert cache.check_and_add("key2", ttl_seconds=60.0) is True
    assert len(cache) == 2


def test_dedup_cache_ttl_eviction():
    cache = BoundedDedupCache(max_size=10)
    assert cache.check_and_add("short_lived", ttl_seconds=0.05) is True
    assert cache.check_and_add("short_lived", ttl_seconds=0.05) is False
    time.sleep(0.08)
    # After TTL, key should be pruned and accepted again
    assert cache.check_and_add("short_lived", ttl_seconds=60.0) is True


def test_dedup_cache_max_size_cap_eviction():
    cache = BoundedDedupCache(max_size=3)
    assert cache.check_and_add("k1", ttl_seconds=100.0) is True
    time.sleep(0.01)
    assert cache.check_and_add("k2", ttl_seconds=200.0) is True
    time.sleep(0.01)
    assert cache.check_and_add("k3", ttl_seconds=300.0) is True
    assert len(cache) == 3

    # Adding 4th item should evict oldest (k1)
    assert cache.check_and_add("k4", ttl_seconds=400.0) is True
    assert len(cache) == 3
    # k1 was evicted, so it can be added again
    assert cache.check_and_add("k1", ttl_seconds=100.0) is True


# ── 2. ProactiveBridge Priority & Interruption Tests ─────────────────────────

def test_bridge_critical_priority_triggers_interrupt_and_immediate_voice():
    interrupted = []
    spoken = []
    bridge = ProactiveBridge(
        get_state=lambda: "SPEAKING",  # JARVIS is busy speaking
        voice_sink=lambda msg: spoken.append(msg),
        interrupt_sink=lambda: interrupted.append(True),
    )

    ev = ProactiveEvent(
        category="security",
        title="Intruder Alert",
        message="Intruder detected in room!",
        priority=ProactivePriority.CRITICAL,
    )

    success = bridge.dispatch(ev)
    assert success is True
    assert len(interrupted) == 1       # Verified: called Phase 2 interrupt sink
    assert spoken == ["Intruder detected in room!"]


def test_bridge_high_priority_queues_when_speaking_and_drains_on_listening():
    spoken = []
    ui_logs = []
    state = ["SPEAKING"]

    bridge = ProactiveBridge(
        get_state=lambda: state[0],
        voice_sink=lambda msg: spoken.append(msg),
        ui_sink=lambda txt: ui_logs.append(txt),
    )

    ev = ProactiveEvent(
        category="calendar",
        title="Team Standup",
        message="Standup in 10 minutes",
        priority=ProactivePriority.HIGH,
    )

    # 1. Dispatch while speaking -> queued, not spoken
    assert bridge.dispatch(ev) is True
    assert len(spoken) == 0
    assert any("deferred" in log for log in ui_logs)

    # 2. State transition to LISTENING -> drains queue
    state[0] = "LISTENING"
    bridge.on_state_change("LISTENING")
    assert spoken == ["Standup in 10 minutes"]


def test_bridge_high_priority_speaks_immediately_when_idle():
    spoken = []
    bridge = ProactiveBridge(
        get_state=lambda: "LISTENING",
        voice_sink=lambda msg: spoken.append(msg),
    )

    ev = ProactiveEvent(
        category="calendar",
        title="Dentist",
        message="Dentist appointment in 10 minutes",
        priority=ProactivePriority.HIGH,
    )

    assert bridge.dispatch(ev) is True
    assert spoken == ["Dentist appointment in 10 minutes"]


def test_bridge_queued_event_expires_if_speech_exceeds_ttl():
    spoken = []
    state = ["SPEAKING"]

    bridge = ProactiveBridge(
        get_state=lambda: state[0],
        voice_sink=lambda msg: spoken.append(msg),
    )

    ev = ProactiveEvent(
        category="calendar",
        title="Quick Reminder",
        message="Quick reminder",
        priority=ProactivePriority.HIGH,
        ttl_seconds=0.05,  # Very short TTL
    )

    assert bridge.dispatch(ev) is True
    assert len(spoken) == 0

    # Wait for TTL to expire while still speaking
    time.sleep(0.08)

    # State transitions to LISTENING -> event should be discarded as expired
    state[0] = "LISTENING"
    bridge.on_state_change("LISTENING")
    assert len(spoken) == 0


def test_bridge_low_priority_dropped_when_busy():
    spoken = []
    bridge = ProactiveBridge(
        get_state=lambda: "SPEAKING",
        voice_sink=lambda msg: spoken.append(msg),
    )

    ev = ProactiveEvent(
        category="habit",
        title="Ambient glance",
        message="Ambient glance tip",
        priority=ProactivePriority.LOW,
    )

    assert bridge.dispatch(ev) is True
    assert len(spoken) == 0

    # State transitions to LISTENING -> LOW priority was dropped, not queued
    bridge.on_state_change("LISTENING")
    assert len(spoken) == 0


# ── 3. Loop-Independent Out-of-Band Dispatch Tests ────────────────────────────

def test_bridge_loop_independent_out_of_band_delivery():
    audit_events = []
    telegram_messages = []
    mobile_messages = []
    ui_messages = []

    bridge = ProactiveBridge(
        get_state=lambda: "LISTENING",
        audit_sink=lambda cat, actor, d: audit_events.append((cat, actor, d)),
        telegram_sink=lambda msg, img: telegram_messages.append((msg, img)),
        mobile_sink=lambda msg, img: mobile_messages.append((msg, img)),
        ui_sink=lambda txt: ui_messages.append(txt),
    )

    ev = ProactiveEvent(
        category="security",
        title="Duress Log In",
        message="Duress login detected on local machine",
        priority=ProactivePriority.CRITICAL,
        channels={"audit", "telegram", "mobile", "ui"},
        data={"user": "darshan", "jpeg_bytes": b"fake_jpeg"},
    )

    assert bridge.dispatch(ev) is True
    # UI is synchronous
    assert len(ui_messages) == 1

    # Audit, Telegram, Mobile are asynchronous loop-independent workers; wait up to 1s
    t0 = time.time()
    while (len(audit_events) == 0 or len(telegram_messages) == 0 or len(mobile_messages) == 0) and time.time() - t0 < 1.0:
        time.sleep(0.02)

    assert len(audit_events) == 1
    assert audit_events[0][0] == "security"
    assert audit_events[0][2]["user"] == "darshan"

    assert len(telegram_messages) == 1
    assert telegram_messages[0] == ("Duress login detected on local machine", b"fake_jpeg")

    assert len(mobile_messages) == 1
    assert mobile_messages[0] == ("Duress login detected on local machine", b"fake_jpeg")


# ── 4. CalendarReminder Natural Event Window Integration Test ─────────────────

def test_calendar_reminder_dispatches_high_priority_event_to_bridge():
    dispatched_events = []
    spoken_fallback = []

    bridge = ProactiveBridge(
        get_state=lambda: "LISTENING",
        voice_sink=lambda msg: dispatched_events.append(msg),
    )

    # Mock an event starting 8 minutes from now (inside the 10-minute window)
    now_utc = datetime.now(timezone.utc)
    meeting_start = now_utc + timedelta(minutes=8)
    fake_events = [
        {
            "title": "Architecture Review",
            "start": meeting_start,
            "end": meeting_start + timedelta(minutes=30),
            "location": "Boardroom A",
            "description": "Discuss Phase 4",
            "all_day": False,
        }
    ]

    with patch("core.calendar_intel.get_events", return_value=fake_events):
        reminder = CalendarReminder(
            inject_fn=lambda msg: spoken_fallback.append(msg),
            remind_minutes=10,
            bridge=bridge,
        )
        # Execute check
        reminder._check()

    assert len(dispatched_events) == 1
    assert "Architecture Review" in dispatched_events[0]
    assert "Boardroom A" in dispatched_events[0]
    assert len(spoken_fallback) == 0  # Fallback was not needed since bridge succeeded


# ── 5. BriefingScheduler Natural Event Window & Bridge Integration Tests ──────

def test_briefing_scheduler_dispatches_normal_priority_event_to_bridge():
    dispatched_events = []
    spoken_fallback = []
    state = ["SPEAKING"]

    bridge = ProactiveBridge(
        get_state=lambda: state[0],
        voice_sink=lambda msg: dispatched_events.append(msg),
    )

    from main import BriefingScheduler

    now = datetime.now()
    fake_slot = [{"hour": now.hour, "minute": now.minute, "label": "morning"}]
    mock_state = {}

    with patch.object(BriefingScheduler, "_get_times", return_value=fake_slot), \
         patch("main._load_briefing_state", return_value=mock_state), \
         patch("main._save_briefing_state", side_effect=lambda s: mock_state.update(s)):

        scheduler = BriefingScheduler(
            on_briefing=lambda label: spoken_fallback.append(label),
            bridge=bridge,
        )

        # 1. Trigger check while speaking -> queued, not spoken
        scheduler._check()
        assert len(dispatched_events) == 0
        assert len(spoken_fallback) == 0

        # 2. State transition to LISTENING -> drains queue and speaks
        state[0] = "LISTENING"
        bridge.on_state_change("LISTENING")
        assert len(dispatched_events) == 1
        assert "morning briefing" in dispatched_events[0]


def test_briefing_scheduler_dedup_daily_state():
    dispatched_events = []
    bridge = ProactiveBridge(
        get_state=lambda: "LISTENING",
        voice_sink=lambda msg: dispatched_events.append(msg),
    )

    from main import BriefingScheduler

    now = datetime.now()
    fake_slot = [{"hour": now.hour, "minute": now.minute, "label": "evening"}]
    mock_state = {}

    with patch.object(BriefingScheduler, "_get_times", return_value=fake_slot), \
         patch("main._load_briefing_state", return_value=mock_state), \
         patch("main._save_briefing_state", side_effect=lambda s: mock_state.update(s)):

        scheduler = BriefingScheduler(bridge=bridge)

        # First check fires
        scheduler._check()
        assert len(dispatched_events) == 1

        # Second check skips (already fired today)
        scheduler._check()
        assert len(dispatched_events) == 1


# ── 6. Intruder Alert & CRITICAL Security Priority Bridge Tests ───────────────

def test_bridge_critical_security_dispatch_synchronous_audit_before_voice_and_interrupt():
    """
    Verifies that for CRITICAL priority events, the audit hash-chain entry is
    written synchronously BEFORE voice interruption and delivery, ensuring that
    a crash or exception in voice playback cannot prevent audit logging.
    """
    call_order = []

    def mock_audit(cat, actor, details):
        call_order.append("audit")

    def mock_interrupt():
        call_order.append("interrupt")

    def mock_voice(msg):
        call_order.append("voice")
        raise RuntimeError("Simulated crash in TTS engine")

    bridge = ProactiveBridge(
        get_state=lambda: "SPEAKING",
        voice_sink=mock_voice,
        interrupt_sink=mock_interrupt,
        audit_sink=mock_audit,
    )

    ev = ProactiveEvent(
        category="security",
        title="Intruder Alert",
        message="Unauthorized logon attempt detected",
        priority=ProactivePriority.CRITICAL,
        channels={"audit", "voice"},
    )

    assert bridge.dispatch(ev) is True
    # Audit must be executed first, before interrupt and voice
    assert call_order == ["audit", "interrupt", "voice"]


def test_bridge_critical_security_dispatch_works_with_blocked_event_loop():
    """
    Verifies that CRITICAL proactive dispatch works completely independently
    even when the main asyncio event loop is fully blocked (frozen).
    """
    import asyncio

    # Set up a dedicated asyncio loop and block it with a long synchronous sleep
    loop = asyncio.new_event_loop()
    loop_thread_started = threading.Event()
    loop_blocked = threading.Event()

    def _run_blocked_loop():
        asyncio.set_event_loop(loop)
        async def _blocker():
            loop_thread_started.set()
            loop_blocked.wait(timeout=2.0)  # Simulating a blocked event loop
        loop.run_until_complete(_blocker())

    t = threading.Thread(target=_run_blocked_loop, daemon=True)
    t.start()
    assert loop_thread_started.wait(timeout=1.0) is True

    audit_records = []
    interrupted = []
    spoken_messages = []
    ui_messages = []
    telegram_messages = []
    mobile_messages = []

    bridge = ProactiveBridge(
        get_state=lambda: "SPEAKING",
        voice_sink=lambda msg: spoken_messages.append(msg),
        interrupt_sink=lambda: interrupted.append(True),
        ui_sink=lambda msg: ui_messages.append(msg),
        audit_sink=lambda cat, actor, d: audit_records.append((cat, actor, d)),
        telegram_sink=lambda msg, jpeg: telegram_messages.append((msg, jpeg)),
        mobile_sink=lambda msg, jpeg: mobile_messages.append((msg, jpeg)),
    )

    ev = ProactiveEvent(
        category="security",
        title="Intruder Detected",
        message="Intruder alert on DESKTOP-MAIN: failed password",
        priority=ProactivePriority.CRITICAL,
        channels={"audit", "voice", "ui", "telegram", "mobile"},
        data={"hostname": "DESKTOP-MAIN", "jpeg_bytes": b"fake_intruder_face"},
    )

    # Dispatch while asyncio loop is 100% blocked
    t_start = time.time()
    assert bridge.dispatch(ev) is True
    dispatch_duration = time.time() - t_start

    # Dispatch itself returns almost instantly (does not wait on asyncio)
    assert dispatch_duration < 0.1
    assert len(audit_records) == 1
    assert len(interrupted) == 1
    assert len(spoken_messages) == 1
    assert len(ui_messages) == 1

    # Asynchronous workers for telegram and mobile finish in background threads
    t0 = time.time()
    while (len(telegram_messages) == 0 or len(mobile_messages) == 0) and time.time() - t0 < 1.0:
        time.sleep(0.01)

    assert len(telegram_messages) == 1
    assert len(mobile_messages) == 1

    # Clean up blocked loop
    loop_blocked.set()
    t.join(timeout=1.0)


def test_intruder_alert_watcher_decision_path_controlled_harness():
    """
    Controlled harness verifying that IntruderAlertWatcher's real detection
    decision path (_fire_alert) captures the frame, checks face identity,
    and dispatches a CRITICAL ProactiveEvent through ProactiveBridge.
    """
    from core.intruder_alert import IntruderAlertWatcher

    dispatched_events = []
    interrupted = []
    audit_events = []

    bridge = ProactiveBridge(
        get_state=lambda: "SPEAKING",
        voice_sink=lambda msg: dispatched_events.append(msg),
        interrupt_sink=lambda: interrupted.append(True),
        audit_sink=lambda cat, actor, d: audit_events.append((cat, actor, d)),
    )

    watcher = IntruderAlertWatcher(
        on_alert=lambda txt, jpeg: None,
        bridge=bridge,
    )

    with patch("core.intruder_alert._take_webcam_snapshot", return_value=b"jpeg_data"), \
         patch("core.face_verify.FaceVerifier.identify", return_value=None):

        # Exercise the real _fire_alert decision path for a failed login
        now_dt = datetime.now()
        watcher._fire_alert(
            when=now_dt,
            bypass_debounce=True,
            record_id=4625,
            event_type="failed_logon",
            actor="darshan",
            details={"message": "Failed logon at lockscreen", "record_id": 4625},
        )

    # 1. Audit logged synchronously
    assert len(audit_events) == 1
    assert audit_events[0][0] == "security"

    # 2. Ongoing playback interrupted
    assert len(interrupted) == 1

    # 3. Spoken voice alert delivered immediately
    assert len(dispatched_events) == 1
    assert "Failed login attempt" in dispatched_events[0]


# ── 7. Production Startup Wiring Verification ─────────────────────────────────

def test_production_startup_wires_proactive_bridge_static_audit():
    """
    Static call-site audit ensuring that all triggers
    (EmergencyWipeController, BriefingScheduler, CalendarReminder, IntruderAlertWatcher)
    are genuinely wired to the ProactiveBridge instance at production application startup.
    Fails if any bridge wiring call site is omitted or removed from main.py or jarvis_service.py.
    """
    from pathlib import Path

    repo_root = Path(__file__).resolve().parent.parent
    main_py = (repo_root / "main.py").read_text(encoding="utf-8")
    service_py = (repo_root / "jarvis_service.py").read_text(encoding="utf-8")

    # 1. EmergencyWipeController.get_instance().set_bridge(...) in main.py & jarvis_service.py
    assert "EmergencyWipeController.get_instance().set_bridge(self._proactive_bridge)" in main_py, (
        "EmergencyWipeController.set_bridge is missing from main.py startup!"
    )
    assert "EmergencyWipeController.get_instance().set_bridge(self._proactive_bridge)" in service_py, (
        "EmergencyWipeController.set_bridge is missing from jarvis_service.py startup!"
    )

    # 2. BriefingScheduler wired with bridge in main.py & jarvis_service.py
    assert "self._briefing_scheduler = BriefingScheduler(\n            on_briefing=self._on_scheduled_briefing,\n            bridge=self._proactive_bridge,\n        )" in main_py
    assert "self._briefing = BriefingScheduler(\n            on_briefing=self._trigger_briefing,\n            bridge=self._proactive_bridge,\n        )" in service_py

    # 3. CalendarReminder wired with bridge in main.py & jarvis_service.py
    assert 'self._calendar_reminder = CalendarReminder(\n                inject_fn=lambda msg: asyncio.run_coroutine_threadsafe(\n                    self._inject_text(msg), self._loop\n                ) if self._loop else None,\n                bridge=getattr(self, "_proactive_bridge", None),\n            )' in main_py
    assert 'self._calendar_reminder = CalendarReminder(\n                inject_fn=lambda msg: self.inject(msg),\n                bridge=getattr(self, "_proactive_bridge", None),\n            )' in service_py

    # 4. IntruderAlertWatcher wired with bridge in jarvis_service.py
    assert "self._intruder_alert = IntruderAlertWatcher(\n            on_alert = self._on_intruder_alert,\n            log_fn   = lambda msg: self._ui.write_log(msg) if self._ui else print(msg),\n            bridge   = self._proactive_bridge,\n        )" in service_py



def test_jarvis_session_startup_wires_real_bridge_to_emergency_wipe_singleton():
    """
    Live initialization test: Instantiates JarvisSession through production init path
    (with mocked UI/audio) and verifies that EmergencyWipeController.get_instance()._bridge
    is genuinely set to the real ProactiveBridge instance without manual test injection.
    """
    from core.sentinel_extras import EmergencyWipeController
    from jarvis_service import JarvisSession

    # Reset controller bridge before test
    controller = EmergencyWipeController.get_instance()
    controller.set_bridge(None)
    assert controller._bridge is None

    mock_ui = MagicMock()
    mock_ui.write_log = MagicMock()

    with patch("jarvis_service.ProactiveIntelligence"), \
         patch("core.voice_emotion.VoiceEmotionDetector"):
        session = JarvisSession(ui=mock_ui, wake_listener=None)


    # Verify that the session startup wired the real bridge into the singleton
    assert controller._bridge is not None
    assert controller._bridge is session._proactive_bridge
    assert isinstance(controller._bridge, ProactiveBridge)



