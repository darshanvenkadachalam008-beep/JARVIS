"""
Scout — Research Agent
Wraps actions/web_search.py.
Collects information and saves reports to reports/scout/.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

from agents.base_agent import BaseAgent


def _get_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


class ScoutAgent(BaseAgent):

    def __init__(self):
        super().__init__("Scout")
        self._reports_dir = _get_base_dir() / "reports" / "scout"

    def execute_task(self, task: str, speak=None, **kwargs) -> str:
        self._start(task)
        try:
            self._reports_dir.mkdir(parents=True, exist_ok=True)

            self.update_progress(10, "Scout: Preparing search queries…")
            queries = self._build_queries(task)

            results = []
            for i, q in enumerate(queries):
                self.update_progress(20 + (50 * i // len(queries)), f"Scout: Searching '{q[:40]}'…")
                res = self._do_search(q)
                if res:
                    results.append((q, res))

            self.update_progress(75, "Scout: Compiling report…")
            report = self._format_report(task, results)

            self.update_progress(90, "Scout: Saving report…")
            self._save_report(task, report)

            return self.report_result(report)

        except Exception as e:
            return self._error(str(e))

    # ── Private ─────────────────────────────────────────────────────────────

    def _build_queries(self, task: str) -> list[str]:
        """Produce 1–2 targeted search queries from the task description."""
        base = task.strip().rstrip("?")
        return [base, f"{base} overview guide"][:2]

    def _do_search(self, query: str) -> str:
        from actions.web_search import web_search
        params = {"query": query, "mode": "search"}
        try:
            return web_search(parameters=params, player=None) or ""
        except Exception as e:
            self._log(f"Scout: search failed for '{query}': {e}")
            return ""

    def _format_report(self, topic: str, results: list[tuple[str, str]]) -> str:
        sources = "\n".join(f"  • {q}" for q, _ in results) or "  (none)"
        summaries = "\n\n".join(
            f"[Query: {q}]\n{r[:600]}" for q, r in results
        ) or "(no results)"

        # Extract key bullet points from first result
        first_text = results[0][1] if results else ""
        points = [l.strip() for l in first_text.splitlines() if len(l.strip()) > 40][:5]
        bullet_pts = "\n".join(f"  • {p[:120]}" for p in points) or "  (see summary)"

        return (
            f"═══════════════════════════════\n"
            f"  SCOUT REPORT\n"
            f"═══════════════════════════════\n"
            f"Topic           : {topic}\n"
            f"───────────────────────────────\n"
            f"Sources searched:\n{sources}\n"
            f"───────────────────────────────\n"
            f"Summary         :\n{summaries[:1200]}\n"
            f"───────────────────────────────\n"
            f"Important points:\n{bullet_pts}\n"
            f"═══════════════════════════════"
        )

    def _save_report(self, topic: str, report: str) -> None:
        safe = "".join(c if c.isalnum() or c in " _-" else "_" for c in topic)[:50]
        ts   = time.strftime("%Y%m%d_%H%M%S")
        path = self._reports_dir / f"scout_{safe}_{ts}.txt"
        path.write_text(report, encoding="utf-8")
        self._log(f"Scout: Report saved → {path}")