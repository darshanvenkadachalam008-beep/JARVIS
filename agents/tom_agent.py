"""
Tom — Development Agent
Wraps actions/dev_agent.py and actions/code_helper.py.
Receives coding tasks, calls existing dev tools, formats report.
"""
from __future__ import annotations

import time
from agents.base_agent import BaseAgent


class TomAgent(BaseAgent):

    def __init__(self):
        super().__init__("Tom")

    def execute_task(self, task: str, speak=None, **kwargs) -> str:
        self._start(task)
        try:
            self.update_progress(10, "Tom: Analysing task…")

            # Prefer dev_agent for full project requests, code_helper for snippets
            if any(kw in task.lower() for kw in ("project", "app", "create", "build", "develop")):
                result = self._run_dev_agent(task, speak)
            else:
                result = self._run_code_helper(task, speak)

            self.update_progress(90, "Tom: Formatting report…")
            report = self._format_report(task, result)
            return self.report_result(report)

        except Exception as e:
            return self._error(str(e))

    # ── Private ─────────────────────────────────────────────────────────────

    def _run_dev_agent(self, task: str, speak) -> str:
        from actions.dev_agent import dev_agent
        self.update_progress(30, "Tom: Running dev agent…")
        params = {"description": task, "language": "python"}
        result = dev_agent(parameters=params, player=None, speak=speak) or "Dev agent completed."
        self.update_progress(80, "Tom: Dev agent finished.")
        return result

    def _run_code_helper(self, task: str, speak) -> str:
        from actions.code_helper import code_helper
        self.update_progress(30, "Tom: Running code helper…")
        params = {"action": "write", "description": task}
        result = code_helper(parameters=params, player=None, speak=speak) or "Code helper completed."
        self.update_progress(80, "Tom: Code helper finished.")
        return result

    def _format_report(self, task: str, execution_result: str) -> str:
        lines = execution_result.splitlines() if execution_result else []
        files_changed = [l for l in lines if any(ext in l for ext in (".py", ".js", ".ts", ".json", ".txt", ".html"))]
        errors = [l for l in lines if any(kw in l.lower() for kw in ("error", "failed", "exception"))]

        report = (
            f"═══════════════════════════════\n"
            f"  TOM REPORT\n"
            f"═══════════════════════════════\n"
            f"Task        : {task}\n"
            f"Files       : {', '.join(files_changed[:5]) if files_changed else 'see output'}\n"
            f"Execution   : {'⚠️ errors detected' if errors else '✅ clean'}\n"
            f"Errors      : {errors[0][:120] if errors else 'none'}\n"
            f"───────────────────────────────\n"
            f"Solution    :\n{execution_result[:800]}\n"
            f"═══════════════════════════════"
        )
        return report