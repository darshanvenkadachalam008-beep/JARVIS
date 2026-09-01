"""
core/states.py — JARVIS State Machine
=======================================
Defines clear, mutually exclusive operating states for JARVIS and a
thread-safe StateManager that enforces valid transitions.

States
------
SLEEPING          — Fully at rest.  Only WakeWordEngine mic is active.
                    Gemini session is alive but audio is NOT streamed to it.
LISTENING         — Wake word received.  Mic audio streams to Gemini Live.
                    JARVIS is ready for a voice command.
ACTIVE_CONVERSATION — Mid-exchange: user is speaking or JARVIS is replying.
                    Must not be interrupted by proactive notifications.
SHUTDOWN          — User (or tool) requested a hard stop.
                    Mic stops, Gemini session closes, no auto-restart.

The UI receives state strings so it can update HUD colours/labels without
importing this module (avoids circular deps).  Use StateManager.set() from
anywhere; the UI callback is optional.
"""

from __future__ import annotations

import threading
from enum import Enum, auto
from typing import Callable, Optional


class JarvisState(Enum):
    SLEEPING              = auto()
    LISTENING             = auto()
    ACTIVE_CONVERSATION   = auto()
    SHUTDOWN              = auto()


# Map state → UI label string (keeps ui.py free of state knowledge)
_UI_LABEL: dict[JarvisState, str] = {
    JarvisState.SLEEPING:             "SLEEPING",
    JarvisState.LISTENING:            "LISTENING",
    JarvisState.ACTIVE_CONVERSATION:  "ACTIVE",
    JarvisState.SHUTDOWN:             "OFFLINE",
}

# Legal state transitions:  from_state → set of reachable states
_VALID_TRANSITIONS: dict[JarvisState, set[JarvisState]] = {
    JarvisState.SLEEPING: {
        JarvisState.LISTENING,
        JarvisState.SHUTDOWN,
    },
    JarvisState.LISTENING: {
        JarvisState.ACTIVE_CONVERSATION,
        JarvisState.SLEEPING,
        JarvisState.SHUTDOWN,
    },
    JarvisState.ACTIVE_CONVERSATION: {
        JarvisState.LISTENING,
        JarvisState.SLEEPING,
        JarvisState.SHUTDOWN,
    },
    JarvisState.SHUTDOWN: set(),   # terminal — no exits
}


class StateManager:
    """
    Thread-safe JARVIS state machine.

    Parameters
    ----------
    on_change : optional callback(new_state: JarvisState, ui_label: str)
        Called on every successful state transition (from any thread).
    initial : starting state (default SLEEPING)
    """

    def __init__(
        self,
        on_change: Optional[Callable[[JarvisState, str], None]] = None,
        initial: JarvisState = JarvisState.SLEEPING,
    ):
        self._state  = initial
        self._lock   = threading.Lock()
        self._on_change = on_change

    # ── read ──────────────────────────────────────────────────────────────

    @property
    def state(self) -> JarvisState:
        with self._lock:
            return self._state

    def is_shutdown(self) -> bool:
        return self.state is JarvisState.SHUTDOWN

    def is_sleeping(self) -> bool:
        return self.state is JarvisState.SLEEPING

    def is_active(self) -> bool:
        """True when a conversation is in progress (must not be interrupted)."""
        return self.state is JarvisState.ACTIVE_CONVERSATION

    def can_be_interrupted(self) -> bool:
        """Proactive notifications are only safe outside ACTIVE_CONVERSATION."""
        return self.state not in (
            JarvisState.ACTIVE_CONVERSATION,
            JarvisState.SHUTDOWN,
        )

    # ── write ─────────────────────────────────────────────────────────────

    def set(self, new_state: JarvisState, *, force: bool = False) -> bool:
        """
        Attempt a state transition.  Returns True if the transition
        succeeded, False if it was rejected (invalid or already in state).

        Set force=True only for SHUTDOWN (guarantees we always reach terminal
        state even from an unexpected current state).
        """
        with self._lock:
            current = self._state
            if current is new_state:
                return False   # no-op
            if not force and new_state not in _VALID_TRANSITIONS.get(current, set()):
                print(
                    f"[States] ⚠️  Rejected {current.name} → {new_state.name} "
                    f"(not in valid transitions)"
                )
                return False
            self._state = new_state

        label = _UI_LABEL[new_state]
        print(f"[States] 🔄 {current.name} → {new_state.name}")
        if self._on_change:
            try:
                self._on_change(new_state, label)
            except Exception as cb_err:
                print(f"[States] on_change callback error: {cb_err}")
        return True

    # Convenience shortcuts ────────────────────────────────────────────────

    def wake(self) -> bool:
        """SLEEPING/LISTENING → LISTENING"""
        # Allow LISTENING → LISTENING if already awake (idempotent wake)
        if self.state is JarvisState.LISTENING:
            return True
        return self.set(JarvisState.LISTENING)

    def begin_conversation(self) -> bool:
        return self.set(JarvisState.ACTIVE_CONVERSATION)

    def end_conversation(self) -> bool:
        """Return to LISTENING after a turn completes."""
        return self.set(JarvisState.LISTENING)

    def sleep(self) -> bool:
        """Return to SLEEPING after timeout or explicit request."""
        return self.set(JarvisState.SLEEPING)

    def shutdown(self) -> bool:
        """Force terminal SHUTDOWN from any state."""
        return self.set(JarvisState.SHUTDOWN, force=True)