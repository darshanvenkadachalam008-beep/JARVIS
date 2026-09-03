"""
jarvis_watchdog.py — Self-healing watchdog for jarvis_service.pyw
====================================================================
Runs independently of jarvis_service.pyw (start it once, e.g. via a
Scheduled Task at logon, and leave it running). Every CHECK_INTERVAL_SECS
it checks memory/jarvis_heartbeat.json, written by jarvis_service.pyw
every ~10s while healthy. If the heartbeat goes stale (process hung) or
the file is simply missing (process died / never started), the watchdog:

  1. Kills any leftover process still holding ports 8080/8081, so a
     restart can never fight a zombie for the port (this was the single
     biggest source of trouble during initial setup — see log at bottom).
  2. Cleans up a stale single-instance lock file if present.
  3. Relaunches jarvis_service.pyw fresh.
  4. Logs every restart with a reason and timestamp to
     memory/watchdog.log, so you can see exactly what happened and when
     if you come back to a machine that restarted itself overnight.

USAGE:
  python jarvis_watchdog.py                  ← run in foreground (testing)
  pythonw jarvis_watchdog.py                 ← run silently in background

For permanent protection, set this to launch at logon via Task Scheduler
or a Startup-folder shortcut, same as jarvis_service.pyw itself.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

BASE_DIR         = Path(__file__).resolve().parent
VENV_PYTHONW     = BASE_DIR / "venv" / "Scripts" / "pythonw.exe"
JARVIS_SCRIPT    = BASE_DIR / "jarvis_service.py"
HEARTBEAT_PATH   = BASE_DIR / "memory" / "jarvis_heartbeat.json"
WATCHDOG_HEARTBEAT_PATH = BASE_DIR / "memory" / "watchdog_heartbeat.json"
LOCK_PATH        = BASE_DIR / "memory" / "jarvis_service.lock"
INTENTIONAL_EXIT_PATH = BASE_DIR / "memory" / "jarvis_intentional_exit.marker"
WATCHDOG_LOG     = BASE_DIR / "memory" / "watchdog.log"

CHECK_INTERVAL_SECS      = 15   # how often the watchdog checks health
HEARTBEAT_STALE_SECS     = 45   # if heartbeat is older than this, consider it hung
STARTUP_GRACE_SECS       = 60   # don't judge a freshly (re)started process for this long
PORTS_TO_CLEAR           = (8080, 8081)
RESTART_STORM_WINDOW_SECS = 300  # 5 minutes
RESTART_STORM_THRESHOLD   = 3    # 3 restarts within window triggers alert
_restart_history: list[float] = []


def _write_heartbeat():
    """Writes the watchdog's own heartbeat atomically so jarvis_service.pyw
    can monitor the watchdog process health (Layer 1 mutual heartbeat)."""
    try:
        WATCHDOG_HEARTBEAT_PATH.parent.mkdir(parents=True, exist_ok=True)
        temp_file = WATCHDOG_HEARTBEAT_PATH.with_suffix(".tmp")
        data = json.dumps({"pid": os.getpid(), "ts": time.time()})
        temp_file.write_text(data, encoding="utf-8")
        temp_file.replace(WATCHDOG_HEARTBEAT_PATH)
        try:
            from sentinel.security_utils import apply_owner_only_dacl
            apply_owner_only_dacl(WATCHDOG_HEARTBEAT_PATH)
        except Exception:
            pass
    except Exception as e:
        _log(f"⚠️ Could not write watchdog heartbeat: {e}")


def _alert_restart_storm(count: int, window_secs: int):
    msg = f"🚨 [WATCHDOG SECURITY ALERT] Rapid restart storm detected: {count} restarts within {window_secs // 60} minutes. Possible service crash loop or malicious tampering."
    _log(msg)
    try:
        from core.telegram_alerter import TelegramAlerter
        TelegramAlerter().send(msg)
    except Exception as e:
        _log(f"Could not send Telegram alert: {e}")
    try:
        from core.audit_log import AuditLog
        AuditLog().append("watchdog_restart_storm_alert", {"restarts_in_window": count, "window_secs": window_secs})
    except Exception:
        pass


def _log(msg: str):
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    try:
        WATCHDOG_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(WATCHDOG_LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def _kill_pids_on_ports(ports) -> None:
    """Finds and kills whatever's listening on the given ports, so a
    fresh launch never has to fight a leftover process for them —
    exactly the class of bug that caused repeated 'only one usage of
    each socket address' failures during initial setup."""
    try:
        result = subprocess.run(
            ["netstat", "-ano"], capture_output=True, text=True, timeout=10)
    except Exception as e:
        _log(f"⚠️ Could not run netstat: {e}")
        return

    pids_to_kill = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] != "TCP":
            continue
        local_addr = parts[1]
        state = parts[3]
        pid = parts[-1]
        for port in ports:
            if local_addr.endswith(f":{port}") and state == "LISTENING":
                if pid.isdigit() and int(pid) != os.getpid():
                    pids_to_kill.add(int(pid))

    for pid in pids_to_kill:
        try:
            subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                            capture_output=True, timeout=10)
            _log(f"🔪 Killed stray process PID {pid} holding a JARVIS port")
        except Exception as e:
            _log(f"⚠️ Failed to kill PID {pid}: {e}")


def _clear_stale_lock():
    if LOCK_PATH.exists():
        try:
            LOCK_PATH.unlink()
            _log("🧹 Removed stale single-instance lock file")
        except Exception as e:
            _log(f"⚠️ Could not remove lock file: {e}")


def _launch_jarvis():
    python_exe = VENV_PYTHONW if VENV_PYTHONW.exists() else Path(sys.executable)
    try:
        subprocess.Popen(
            [str(python_exe), str(JARVIS_SCRIPT)],
            cwd=str(BASE_DIR),
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        _log(f"🚀 Launched jarvis_service.pyw via {python_exe.name}")
    except Exception as e:
        _log(f"❌ Failed to launch jarvis_service.pyw: {e}")


def _read_heartbeat():
    if not HEARTBEAT_PATH.exists():
        return None
    try:
        data = json.loads(HEARTBEAT_PATH.read_text())
        return data.get("ts")
    except Exception:
        return None


def _restart(reason: str, alert_fn=None):
    global _restart_history
    now = time.time()
    _restart_history = [t for t in _restart_history if now - t <= RESTART_STORM_WINDOW_SECS]
    _restart_history.append(now)

    _log(f"🔁 Restarting JARVIS — reason: {reason}")
    try:
        from sentinel.anomaly.detector import AnomalyDetector
        AnomalyDetector().record_watchdog_restart(timestamp=now, reason=reason)
    except Exception as e:
        _log(f"Could not record watchdog restart in AnomalyDetector: {e}")


    if len(_restart_history) >= RESTART_STORM_THRESHOLD:
        if alert_fn:
            alert_fn(len(_restart_history), RESTART_STORM_WINDOW_SECS)
        else:
            _alert_restart_storm(len(_restart_history), RESTART_STORM_WINDOW_SECS)


    _kill_pids_on_ports(PORTS_TO_CLEAR)
    _clear_stale_lock()
    time.sleep(2)  # let the OS actually release the ports
    _launch_jarvis()


def main():
    _log("🐕 JARVIS watchdog started")
    last_restart_time = 0.0
    startup_deadline = time.time() + STARTUP_GRACE_SECS
    have_seen_first_heartbeat = False
    was_in_standby = False

    while True:
        _write_heartbeat()

        from core.watchdog_auth import verify_authenticated_exit_marker
        if verify_authenticated_exit_marker(INTENTIONAL_EXIT_PATH):
            if not was_in_standby:
                _log("😴 Authenticated intentional quit detected — standing down, will not auto-restart")
                was_in_standby = True
            time.sleep(CHECK_INTERVAL_SECS)
            continue
        elif was_in_standby:
            _log("👀 Intentional-exit marker cleared/expired — resuming normal monitoring")
            was_in_standby = False

        ts = _read_heartbeat()
        now = time.time()

        if ts is not None:
            have_seen_first_heartbeat = True
            age = now - ts
            if age > HEARTBEAT_STALE_SECS:
                if now - last_restart_time > STARTUP_GRACE_SECS:
                    _restart(f"heartbeat stale ({age:.0f}s old, limit {HEARTBEAT_STALE_SECS}s)")
                    last_restart_time = now
                    startup_deadline = now + STARTUP_GRACE_SECS
        else:
            # No heartbeat file at all. Only act once past the initial
            # grace period, so we don't restart-loop while it's simply
            # still booting for the first time.
            if not have_seen_first_heartbeat and now < startup_deadline:
                pass  # still within initial startup grace, be patient
            elif now - last_restart_time > STARTUP_GRACE_SECS:
                _restart("no heartbeat file found (process not running)")
                last_restart_time = now
                startup_deadline = now + STARTUP_GRACE_SECS
                have_seen_first_heartbeat = False

        time.sleep(CHECK_INTERVAL_SECS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        _log("🐕 JARVIS watchdog stopped by user")