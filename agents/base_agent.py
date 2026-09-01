"""
Base class for all JARVIS sub-agents (Tom, Scout, Ada, Nova).
Thin persona wrapper — delegates real execution to existing infrastructure.
"""
from __future__ import annotations

import time
from typing import Callable, Any


class BaseAgent:
    """Lightweight wrapper providing name, status, progress, and logs."""

    def __init__(self, name: str):
        self.agent_name:   str   = name
        self.status:       str   = "idle"       # idle | running | done | error
        self.current_task: str   = ""
        self.progress:     float = 0.0          # 0–100
        self.logs:         list[str] = []
        self._on_progress: Callable[[str, float], None] | None = None

    # ── Public API ──────────────────────────────────────────────────────────

    def set_progress_callback(self, cb: Callable[[str, float], None]) -> None:
        """Register callback(agent_name, pct) fired on progress updates."""
        self._on_progress = cb

    def is_busy(self) -> bool:
        return self.status == "running"

    def execute_task(self, task: str, **kwargs) -> str:
        """
        Override in subclass.
        Must call update_progress() and return a report string.
        """
        raise NotImplementedError

    def update_progress(self, pct: float, message: str = "") -> None:
        self.progress = max(0.0, min(100.0, pct))
        if message:
            self._log(message)
        if self._on_progress:
            try:
                self._on_progress(self.agent_name, self.progress)
            except Exception:
                pass

    def report_result(self, result: str) -> str:
        self.status   = "done"
        self.progress = 100.0
        self._log(f"[{self.agent_name}] ✅ Done")
        if self._on_progress:
            try:
                self._on_progress(self.agent_name, 100.0)
            except Exception:
                pass
        return result

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _log(self, message: str) -> None:
        entry = f"[{time.strftime('%H:%M:%S')}] {message}"
        self.logs.append(entry)
        print(entry)

    def _start(self, task: str) -> None:
        self.status       = "running"
        self.current_task = task
        self.progress     = 0.0
        self._log(f"[{self.agent_name}] ▶️ Starting: {task[:80]}")
        if self._on_progress:
            try:
                self._on_progress(self.agent_name, 0.0)
            except Exception:
                pass

    def _error(self, msg: str) -> str:
        self.status = "error"
        self._log(f"[{self.agent_name}] ❌ Error: {msg}")
        if self._on_progress:
            try:
                self._on_progress(self.agent_name, 0.0)
            except Exception:
                pass
        return f"[{self.agent_name}] Error: {msg}"