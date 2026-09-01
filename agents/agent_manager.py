"""
AgentManager — routes tasks to Tom / Scout / Ada / Nova.
Uses existing agent/task_queue.py — does NOT create a new queue.
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from typing import Callable

from agents.base_agent  import BaseAgent
from agents.tom_agent   import TomAgent
from agents.scout_agent import ScoutAgent
from agents.ada_agent   import AdaAgent
from agents.nova_agent  import NovaAgent


# Hard ceiling on a single persona task — protects against an LLM/API call
# (e.g. Gemini) that hangs and never returns. Tom (code generation) gets the
# longest budget since it may chain multiple model calls.
_DEFAULT_TIMEOUT_S = 90
_TIMEOUT_OVERRIDES: dict[str, int] = {
    "Tom": 120,
}


# Keyword sets used for intent-based routing
_ROUTING: dict[str, list[str]] = {
    "Tom":   ["code", "develop", "build", "create app", "project", "script",
               "debug", "fix bug", "programming", "python", "javascript"],
    "Scout": ["research", "search", "find info", "look up", "what is",
               "who is", "news", "latest", "information about"],
    "Ada":   ["caption", "post", "instagram", "twitter", "linkedin", "social",
               "content", "draft", "write a post", "social media"],
    "Nova":  ["analytics", "youtube", "views", "meta", "ads", "app store",
               "downloads", "metrics", "statistics", "performance"],
}


class AgentManager:
    """
    Singleton-friendly manager.
    Registers all four agents and routes tasks by keyword or explicit name.
    Reuses the existing TaskQueue for async dispatch.
    """

    def __init__(self):
        self._agents: dict[str, BaseAgent] = {}
        self._lock   = threading.Lock()
        self._progress_cb: Callable[[str, float], None] | None = None
        self._pool   = ThreadPoolExecutor(max_workers=4, thread_name_prefix="Agent")

        # Register all agents
        for agent in [TomAgent(), ScoutAgent(), AdaAgent(), NovaAgent()]:
            self.register(agent)

    # ── Registration ────────────────────────────────────────────────────────

    def register(self, agent: BaseAgent) -> None:
        agent.set_progress_callback(self._on_agent_progress)
        with self._lock:
            self._agents[agent.agent_name] = agent
        print(f"[AgentManager] ✅ Registered: {agent.agent_name}")

    def set_progress_callback(self, cb: Callable[[str, float], None]) -> None:
        """UI registers here to receive (agent_name, pct) updates."""
        self._progress_cb = cb
        with self._lock:
            for agent in self._agents.values():
                agent.set_progress_callback(self._on_agent_progress)

    # ── Task routing ────────────────────────────────────────────────────────

    def route(
        self,
        task:        str,
        agent_name:  str | None   = None,
        speak:       Callable | None = None,
        on_complete: Callable | None = None,
        **kwargs,
    ) -> str:
        """
        Route task to agent, run it via the shared pool, and ALSO register it
        with the existing TaskQueue purely for visibility/history — the queue
        does not re-execute the goal itself, since that work is already
        happening through the agent wrapper below. (Previously this method
        ran the task twice: once via TaskQueue's own executor and once via
        the agent thread — fixed.)
        """
        name  = agent_name or self._detect_agent(task)
        agent = self._get_agent(name)

        if agent.is_busy():
            msg = f"[{name}] is still working on a previous task — please wait for it to finish."
            print(f"[AgentManager] ⏳ {msg}")
            if on_complete:
                try:
                    on_complete("", msg)
                except Exception:
                    pass
            return ""

        print(f"[AgentManager] 🎯 Routing to {name}: {task[:60]}")

        future = self._pool.submit(self._execute_in_agent, agent, task, speak, kwargs)

        if on_complete:
            def _on_done(f):
                try:
                    result = f.result()
                except Exception as e:
                    result = f"[{name}] Error: {e}"
                try:
                    on_complete("", result)
                except Exception:
                    pass
            future.add_done_callback(_on_done)

        return name  # synchronous callers can use the agent name as a handle

    def route_direct(
        self,
        task:       str,
        agent_name: str | None   = None,
        speak:      Callable | None = None,
        **kwargs,
    ) -> str:
        """
        Execute synchronously (blocking the calling thread — callers should
        invoke this from a worker thread / executor, never the asyncio
        event loop or the Qt UI thread).

        Enforces a hard timeout so a hung downstream API call (e.g. Gemini)
        can never block forever — the agent is left to finish in the
        background, but this call returns a clear timeout message instead
        of hanging the caller indefinitely.
        """
        name  = agent_name or self._detect_agent(task)
        agent = self._get_agent(name)

        if agent.is_busy():
            msg = f"[{name}] is still working on a previous task, sir — please wait for it to finish before sending another."
            print(f"[AgentManager] ⏳ {msg}")
            return msg

        print(f"[AgentManager] 🎯 Direct route to {name}: {task[:60]}")
        timeout = _TIMEOUT_OVERRIDES.get(name, _DEFAULT_TIMEOUT_S)
        future  = self._pool.submit(self._execute_in_agent, agent, task, speak, kwargs)

        try:
            return future.result(timeout=timeout)
        except FutureTimeoutError:
            msg = (
                f"[{name}] is taking longer than expected ({timeout}s) and may still be "
                f"working in the background, sir. I'll let you know if it finishes."
            )
            print(f"[AgentManager] ⏱️ Timeout waiting on {name}: {task[:60]}")
            return msg

    # ── Status ──────────────────────────────────────────────────────────────

    def get_status(self) -> dict[str, dict]:
        with self._lock:
            return {
                name: {
                    "status":       a.status,
                    "progress":     a.progress,
                    "current_task": a.current_task,
                }
                for name, a in self._agents.items()
            }

    def get_agent_progress(self, name: str) -> float:
        with self._lock:
            agent = self._agents.get(name)
            return agent.progress if agent else 0.0

    # ── Internal ─────────────────────────────────────────────────────────────

    def _detect_agent(self, task: str) -> str:
        lower = task.lower()
        scores: dict[str, int] = {name: 0 for name in _ROUTING}
        for name, keywords in _ROUTING.items():
            for kw in keywords:
                if kw in lower:
                    scores[name] += 1
        best = max(scores, key=lambda k: scores[k])
        if scores[best] == 0:
            return "Scout"   # default fallback
        print(f"[AgentManager] 🔍 Auto-detected agent: {best}")
        return best

    def _get_agent(self, name: str) -> BaseAgent:
        with self._lock:
            agent = self._agents.get(name)
        if agent is None:
            # Fallback to Scout
            with self._lock:
                agent = self._agents["Scout"]
        return agent

    def _execute_in_agent(
        self, agent: BaseAgent, task: str, speak, kwargs: dict
    ) -> str:
        try:
            return agent.execute_task(task, speak=speak, **kwargs)
        except Exception as e:
            return agent._error(str(e))

    def _on_agent_progress(self, agent_name: str, pct: float) -> None:
        if self._progress_cb:
            try:
                self._progress_cb(agent_name, pct)
            except Exception:
                pass


# Module-level singleton
_manager: AgentManager | None = None
_mgr_lock = threading.Lock()


def get_manager() -> AgentManager:
    global _manager
    with _mgr_lock:
        if _manager is None:
            _manager = AgentManager()
    return _manager