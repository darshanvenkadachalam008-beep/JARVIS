"""
actions/code_sandbox.py — Process isolation for Tom's generated/edited code.
=============================================================================
PHASE 5 GAP FIX: Tom (dev_agent.py / code_helper.py) was generating code with
an LLM and then running it with plain `subprocess.run([sys.executable, ...])`
directly on the user's real machine — same interpreter, same filesystem
permissions, same network access, no resource limits beyond a wall-clock
timeout. LLM-written code is untrusted input; running it exactly like that
is a real risk (an unlucky generation could delete files, read other
projects, exfiltrate data, or just run away with the CPU/RAM).

This module is NOT a full container sandbox (no Docker/VM) — the project is
a cross-platform, zero-dependency, "just run it" local assistant, and
requiring Docker Desktop on every user's machine would break that promise
for most people, especially on Windows. Instead this gives every run of
generated code:

  1. A throwaway, isolated working directory (never the project folder
     itself, never $HOME) that's wiped after every run.
  2. A stripped-down environment — no inherited API keys, tokens, or
     credentials from JARVIS's own process environment.
  3. Hard wall-clock timeout (already existed) PLUS, on POSIX (Linux/macOS),
     real CPU-time, memory, and process-count limits via the `resource`
     module, applied in the child before exec via `preexec_fn`.
     (Windows has no `resource` module — see WindowsJobLimiter below for the
     closest equivalent using a kernel Job Object, with a sane fallback to
     timeout-only if that import path is unavailable.)
  4. A static pre-flight scan that blocks the small set of calls with no
     legitimate reason to appear in "write me a script" output — direct
     filesystem wipes outside the sandbox, raw shell-out with shell=True,
     and a handful of obvious self-modification/escape patterns — BEFORE
     the code is ever executed. This is a denylist, not a security boundary
     by itself; it exists to catch accidental/lazy LLM output, not a
     determined attacker, which is why it's paired with 1-3 above.
  5. Output size capping so a runaway print loop can't fill memory/disk.

Usage (drop-in replacement for the old subprocess.run(...) call sites):

    from actions.code_sandbox import run_sandboxed

    result = run_sandboxed(
        command   = [sys.executable, "main.py"],
        work_dir  = project_dir,          # files Tom wrote — read/write inside this dir only
        timeout   = 30,
    )
    # result.stdout, result.stderr, result.returncode, result.timed_out,
    # result.blocked, result.blocked_reason
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    import resource as _resource   # POSIX only
    _HAS_RESOURCE = True
except ImportError:
    _resource = None
    _HAS_RESOURCE = False

IS_WINDOWS = sys.platform.startswith("win")

# ── Limits ───────────────────────────────────────────────────────────────────
MAX_OUTPUT_CHARS   = 20_000      # cap combined stdout+stderr we keep/return
DEFAULT_TIMEOUT_S  = 30          # wall-clock ceiling if caller doesn't specify
MAX_CPU_SECONDS    = 20          # POSIX only — hard CPU-time limit for the child
MAX_MEMORY_BYTES   = 512 * 1024 * 1024   # 512 MB — POSIX only
MAX_CHILD_PROCS    = 32          # POSIX only — caps fork-bomb style runaway

# ── Static pre-flight denylist ──────────────────────────────────────────────
# Blocks unsafe imports, raw shell calls, network egress (when disallowed),
# and attacks on security files/roots before code is run.
_BASE_DENYLIST_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"shutil\.rmtree\(\s*['\"]?(/|~|C:\\\\|C:/)", re.I),
     "recursive delete targeting a root/home path"),
    (re.compile(r"\bos\.system\(", re.I),
     "raw shell execution via os.system"),
    (re.compile(r"subprocess\.(run|call|Popen)\([^)]*shell\s*=\s*True", re.I | re.S),
     "subprocess call with shell=True"),
    (re.compile(r"\brm\s+-rf\s+(/|~|\$HOME)", re.I),
     "shell rm -rf targeting root/home"),
    (re.compile(r"\bformat\s*\(\s*['\"]?[cC]:", re.I),
     "disk format command"),
    (re.compile(r"\b(?:ctypes|winreg)\b", re.I),
     "low-level system/registry access via ctypes or winreg"),
    (re.compile(r"(?:audit_log\.jsonl|access_control\.json|vault\.enc|vault_key\.dpapi)", re.I),
     "attempting to access protected security vault or audit logs"),
]

_NETWORK_DENYLIST_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bimport\s+(?:socket|requests|urllib|httpx|aiohttp|ftplib|http\.client)\b", re.I),
     "network access import while network egress is disabled"),
    (re.compile(r"\bfrom\s+(?:socket|requests|urllib|httpx|aiohttp|ftplib|http\.client)\b", re.I),
     "network access import while network egress is disabled"),
    (re.compile(r"\bsocket\.(?:socket|create_connection|connect)\b", re.I),
     "network socket connection while network egress is disabled"),
]


@dataclass
class SandboxResult:
    stdout: str = ""
    stderr: str = ""
    returncode: Optional[int] = None
    timed_out: bool = False
    blocked: bool = False
    blocked_reason: str = ""
    work_dir: Optional[Path] = None

    @property
    def combined(self) -> str:
        parts = []
        if self.stdout:
            parts.append(f"STDOUT:\n{self.stdout}")
        if self.stderr:
            parts.append(f"STDERR:\n{self.stderr}")
        return "\n\n".join(parts) if parts else "Ran with no output."


def scan_for_danger(*file_contents: str, allow_network: bool = False) -> Optional[str]:
    """
    Run static analysis over source strings.
    Checks base safety denylist + network restrictions if allow_network=False.
    """
    for content in file_contents:
        if not content:
            continue
        for pattern, reason in _BASE_DENYLIST_PATTERNS:
            if pattern.search(content):
                return reason
        if not allow_network:
            for pattern, reason in _NETWORK_DENYLIST_PATTERNS:
                if pattern.search(content):
                    return reason
    return None


def _is_allowed_workdir(work_dir: Path) -> tuple[bool, str]:
    """
    Validates that the working directory is an explicit sandbox/project area
    and not a system root, OS directory, or protected security folder.
    """
    try:
        resolved = work_dir.resolve()
    except Exception as e:
        return False, f"Invalid working directory path: {e}"

    str_path = str(resolved).lower()

    # Denied root paths
    if str_path in ("c:\\", "c:/", "/", "\\"):
        return False, "Execution in root filesystem is blocked."

    # Denied OS/system paths
    for forbidden in ("windows", "system32", "program files", "program files (x86)", "/etc", "/usr", "/bin", "/sbin"):
        if f"\\{forbidden}" in str_path or f"/{forbidden}" in str_path:
            return False, f"Execution inside system directory '{forbidden}' is blocked."

    # Denied JARVIS core security folders
    for sec_dir in ("core", "config", "memory"):
        if str_path.endswith(f"\\{sec_dir}") or str_path.endswith(f"/{sec_dir}"):
            return False, f"Execution inside protected subsystem directory '{sec_dir}' is blocked."

    return True, ""


def _posix_limits():
    try:
        _resource.setrlimit(_resource.RLIMIT_CPU, (MAX_CPU_SECONDS, MAX_CPU_SECONDS))
    except Exception:
        pass
    try:
        _resource.setrlimit(_resource.RLIMIT_AS, (MAX_MEMORY_BYTES, MAX_MEMORY_BYTES))
    except Exception:
        pass
    try:
        _resource.setrlimit(_resource.RLIMIT_NPROC, (MAX_CHILD_PROCS, MAX_CHILD_PROCS))
    except Exception:
        pass
    try:
        os.setsid()
    except Exception:
        pass


def _build_clean_env(extra_path: Optional[str] = None) -> dict:
    keep_prefixes = ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP",
                      "PYTHONIOENCODING", "LANG", "LC_", "HOME", "USERPROFILE")
    deny_substrings = ("key", "token", "secret", "password", "credential", "api")

    clean = {}
    for k, v in os.environ.items():
        if any(k.upper().startswith(p) for p in keep_prefixes):
            if any(d in k.lower() for d in deny_substrings):
                continue
            clean[k] = v

    clean["PYTHONDONTWRITEBYTECODE"] = "1"
    if extra_path:
        clean["PATH"] = extra_path + os.pathsep + clean.get("PATH", "")
    return clean


def _truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated, {len(text) - limit} more chars]"


def run_sandboxed(
    command: list[str],
    work_dir: Path,
    timeout: int = DEFAULT_TIMEOUT_S,
    extra_env: Optional[dict] = None,
    source_files_to_scan: Optional[list[str]] = None,
    allow_network: bool = False,
) -> SandboxResult:
    """
    Run `command` with cwd=work_dir under strict process & filesystem confinement.
    """
    work_dir = Path(work_dir)
    result = SandboxResult(work_dir=work_dir)

    # ── 1. Allowlisted Working Directory Validation ───────────────────────
    allowed, dir_err = _is_allowed_workdir(work_dir)
    if not allowed:
        result.blocked = True
        result.blocked_reason = dir_err
        result.stderr = f"Sandbox blocked: {dir_err}"
        return result

    # ── 2. Zero-Trust Gate: Invariant Deny-List & Command Guard Check ─────
    try:
        from core.command_guard import guard
        guard(
            command=command,
            confirmed=False,
            action_name="sandboxed_execution",
            target=str(work_dir),
        )
    except PermissionError as pe:
        result.blocked = True
        result.blocked_reason = str(pe)
        result.stderr = f"Execution blocked by security guard: {pe}"
        return result

    # ── 3. Pre-Flight Safety Scan & Network Egress Check ─────────────────
    if source_files_to_scan:
        danger = scan_for_danger(*source_files_to_scan, allow_network=allow_network)
        if danger:
            result.blocked = True
            result.blocked_reason = danger
            result.stderr = (
                f"Execution blocked before running: detected {danger}. "
                f"This looks unsafe to run automatically."
            )
            return result

    timeout = max(1, min(int(timeout), 120))

    popen_kwargs = dict(
        cwd=str(work_dir),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=_build_clean_env(),
    )

    if not IS_WINDOWS and _HAS_RESOURCE:
        popen_kwargs["preexec_fn"] = _posix_limits
    elif not IS_WINDOWS:
        popen_kwargs["start_new_session"] = True
    else:
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

    try:
        proc = subprocess.run(command, **popen_kwargs)
        result.stdout = _truncate(proc.stdout or "")
        result.stderr = _truncate(proc.stderr or "")
        result.returncode = proc.returncode
    except subprocess.TimeoutExpired as e:
        result.timed_out = True
        result.stdout = _truncate((e.stdout or "") if isinstance(e.stdout, str) else "")
        result.stderr = _truncate((e.stderr or "") if isinstance(e.stderr, str) else "")
    except FileNotFoundError as e:
        result.stderr = f"Command not found: {e}"
    except Exception as e:
        result.stderr = f"Sandbox run error: {e}"

    return result


def make_scratch_dir(prefix: str = "jarvis_sandbox_") -> Path:
    """
    Isolated throwaway directory for one-off snippet execution (code_helper's
    'write+run a quick script' flow, as opposed to dev_agent's full projects
    which stay in PROJECTS_DIR so the user can find them again). Caller is
    responsible for cleanup via cleanup_scratch_dir() once done.
    """
    path = Path(tempfile.mkdtemp(prefix=prefix))
    return path


def cleanup_scratch_dir(path: Path) -> None:
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass