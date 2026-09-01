"""
setup_watchdog_task.py — Configures Windows Task Scheduler for jarvis_watchdog.py (Layer 2)
===========================================================================================
Registers a persistent Windows Scheduled Task for jarvis_watchdog.py with:
1. Logon Trigger: Starts automatically upon user login.
2. RestartOnFailure: If the watchdog process is killed or crashes, Windows Task Scheduler
   automatically relaunches it after 1 minute (up to 3 restart attempts per cycle).
3. Unlimited Execution Time: Disables the default 72-hour Task Scheduler termination limit.

Usage:
    python setup_watchdog_task.py            ← Installs or updates the scheduled task
    python setup_watchdog_task.py --verify   ← Checks if the task is registered and healthy
    python setup_watchdog_task.py --uninstall← Removes the scheduled task
"""
from __future__ import annotations

import argparse
import getpass
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
WATCHDOG_SCRIPT = BASE_DIR / "jarvis_watchdog.py"
VENV_PYTHONW = BASE_DIR / "venv" / "Scripts" / "pythonw.exe"
TASK_NAME = "JARVIS_Watchdog"


def find_pythonw() -> Path:
    """Locates pythonw.exe (windowless python) to run watchdog silently."""
    candidates = [
        VENV_PYTHONW,
        Path(sys.executable).parent / "pythonw.exe",
    ]
    for c in candidates:
        if c.exists():
            return c
    found = shutil.which("pythonw")
    if found:
        return Path(found)
    return Path(sys.executable)


def build_task_xml(pythonw_path: Path, script_path: Path, working_dir: Path) -> str:
    """
    Constructs Task Scheduler XML schema definition with:
    - LogonTrigger (runs when user logs on)
    - RestartOnFailure (Interval 1 min, Count 3)
    - ExecutionTimeLimit PT0S (unlimited, preventing 72h default timeout)
    """
    user_name = getpass.getuser()
    xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>JARVIS Watchdog Self-Healing Supervisor</Description>
    <Author>{user_name}</Author>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{pythonw_path}</Command>
      <Arguments>"{script_path}"</Arguments>
      <WorkingDirectory>{working_dir}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""
    return xml


def is_task_installed(task_name: str = TASK_NAME) -> bool:
    """Checks whether the scheduled task is already registered."""
    try:
        res = subprocess.run(
            ["schtasks", "/Query", "/TN", task_name],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return res.returncode == 0
    except Exception:
        return False


def install_watchdog_task(task_name: str = TASK_NAME) -> bool:
    """Installs or updates the scheduled task idempotently via Task Scheduler XML."""
    pythonw = find_pythonw()
    xml_content = build_task_xml(pythonw, WATCHDOG_SCRIPT, BASE_DIR)

    already_exists = is_task_installed(task_name)
    action_label = "Updating existing" if already_exists else "Creating new"
    print(f"[*] {action_label} Task Scheduler entry: {task_name}")

    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False, encoding="utf-16") as f:
        f.write(xml_content)
        temp_xml = Path(f.name)

    try:
        res = subprocess.run(
            ["schtasks", "/Create", "/TN", task_name, "/XML", str(temp_xml), "/F"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if res.returncode == 0:
            print(f"[+] Successfully registered scheduled task '{task_name}' with RestartOnFailure protection.")
            return True
        else:
            print(f"[-] schtasks /XML import failed: {res.stderr.strip() or res.stdout.strip()}")
            # Fallback to command-line create
            fallback_cmd = [
                "schtasks", "/Create",
                "/TN", task_name,
                "/TR", f'"{pythonw}" "{WATCHDOG_SCRIPT}"',
                "/SC", "ONLOGON",
                "/F"
            ]
            fb_res = subprocess.run(fallback_cmd, capture_output=True, text=True, timeout=15)
            if fb_res.returncode == 0:
                print(f"[+] Fallback registered scheduled task '{task_name}' on logon.")
                return True
            else:
                print(f"[-] Fallback registration failed: {fb_res.stderr.strip()}")
                return False
    finally:
        try:
            if temp_xml.exists():
                temp_xml.unlink()
        except Exception:
            pass


def remove_watchdog_task(task_name: str = TASK_NAME) -> bool:
    """Removes the scheduled task."""
    if not is_task_installed(task_name):
        print(f"[i] Task '{task_name}' is not installed.")
        return True
    try:
        res = subprocess.run(
            ["schtasks", "/Delete", "/TN", task_name, "/F"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if res.returncode == 0:
            print(f"[+] Successfully removed scheduled task '{task_name}'.")
            return True
        else:
            print(f"[-] Failed to delete task: {res.stderr.strip()}")
            return False
    except Exception as e:
        print(f"[-] Error deleting task: {e}")
        return False


def verify_watchdog_task(task_name: str = TASK_NAME) -> bool:
    """Queries and displays detailed status for the scheduled task."""
    try:
        res = subprocess.run(
            ["schtasks", "/Query", "/TN", task_name, "/V", "/FO", "LIST"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if res.returncode == 0:
            print(f"[+] Task '{task_name}' is registered:")
            for line in res.stdout.splitlines():
                if any(k in line for k in ["TaskName:", "Status:", "Schedule Type:", "Restart:", "Task To Run:"]):
                    print(f"    {line.strip()}")
            return True
        else:
            print(f"[-] Task '{task_name}' is NOT registered.")
            return False
    except Exception as e:
        print(f"[-] Error querying task: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Configure Windows Task Scheduler for JARVIS Watchdog.")
    parser.add_argument("--verify", action="store_true", help="Verify current task registration status")
    parser.add_argument("--uninstall", action="store_true", help="Remove the watchdog scheduled task")
    args = parser.parse_args()

    if args.verify:
        verify_watchdog_task()
    elif args.uninstall:
        remove_watchdog_task()
    else:
        install_watchdog_task()


if __name__ == "__main__":
    main()
