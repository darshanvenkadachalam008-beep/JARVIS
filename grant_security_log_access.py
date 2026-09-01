"""
grant_security_log_access.py — ONE-TIME setup (run as Administrator)
========================================================================
Why this exists
----------------
JARVIS's intruder-alert watcher reads the Windows Security Event Log
to detect failed login attempts (event ID 4625). Reading that log
normally requires Administrator rights — that's why, earlier, JARVIS
only worked when you manually ran it from an elevated terminal.

But JARVIS's auto-start-on-boot (install_startup.py) registers itself
under HKCU...\\Run, which Windows launches at your normal login level —
NOT elevated. So without this fix, the moment JARVIS auto-starts on
boot, its Security-log read silently fails again, and the brand new
"boot catch-up" feature (which looks back for failed logons that
happened before JARVIS finished starting) can't do its job either.

What this script does
----------------------
Grants your current Windows user account permanent, non-elevated read
access to the Security log, using two methods together (some Windows
builds honor one better than the other):

  1. Adds your user to the built-in local "Event Log Readers" group.
  2. Directly edits the Security log's channel-access permissions
     (via wevtutil) to add an explicit read-allow entry for your user's
     SID, which is the documented fallback for cases where the
     Event Log Readers group alone doesn't cover the Security channel
     specifically.

This is a ONE-TIME setup. After running it once (and signing out/in,
or rebooting, so the new group membership takes effect), your normal
user-level JARVIS process can read the Security log forever — no
"Run as Administrator" ever again.

You only need to run this once per machine, and you DO need to run
THIS script itself as Administrator (right-click PowerShell/Terminal
-> "Run as Administrator"), since granting the permission is itself a
privileged operation. JARVIS itself will keep running as your normal
user afterward.

Run (from an elevated terminal):
    python grant_security_log_access.py

Then sign out and back in (or reboot) for the group membership to
take effect, and verify with:
    python grant_security_log_access.py --verify
"""
from __future__ import annotations

import argparse
import ctypes
import getpass
import subprocess
import sys


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run_ps(cmd: str, timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["powershell", "-NonInteractive", "-NoProfile", "-Command", cmd],
        capture_output=True, text=True, timeout=timeout,
    )


def _current_user() -> str:
    return getpass.getuser()


def add_to_event_log_readers(username: str) -> bool:
    print(f"[1/3] Adding '{username}' to local 'Event Log Readers' group...")
    result = subprocess.run(
        ["net", "localgroup", "Event Log Readers", username, "/add"],
        capture_output=True, text=True,
    )
    out = (result.stdout + result.stderr).strip()
    if result.returncode == 0:
        print("      Done.")
        return True
    if "already a member" in out.lower() or "1378" in out:
        print("      Already a member — fine, continuing.")
        return True
    print(f"      WARNING: {out or '(no output)'}")
    return False


def grant_security_channel_access(username: str) -> bool:
    """
    Fallback / belt-and-suspenders: directly grant read access on the
    Security channel's SDDL descriptor for this specific user's SID.
    Some Windows builds don't honor 'Event Log Readers' for the
    Security channel specifically, so this covers that case.
    """
    print(f"[2/3] Granting direct Security-log channel access to '{username}'...")
    sid_cmd = (
        f"(New-Object System.Security.Principal.NTAccount('{username}'))"
        f".Translate([System.Security.Principal.SecurityIdentifier]).Value"
    )
    sid_result = _run_ps(sid_cmd)
    sid = sid_result.stdout.strip()
    if not sid or not sid.startswith("S-1-"):
        print(f"      WARNING: Could not resolve SID for '{username}': {sid_result.stderr.strip()}")
        return False

    get_result = subprocess.run(
        ["wevtutil", "gl", "security"], capture_output=True, text=True
    )
    if get_result.returncode != 0:
        print(f"      WARNING: wevtutil gl security failed: {get_result.stderr.strip()}")
        return False

    current_ca = None
    for line in get_result.stdout.splitlines():
        line = line.strip()
        if line.lower().startswith("channelaccess:"):
            current_ca = line.split(":", 1)[1].strip()
            break

    if not current_ca:
        print("      WARNING: Could not read current channelAccess value.")
        return False

    read_entry = f"(A;;0x1;;;{sid})"
    if sid in current_ca:
        print("      User's SID already present in channel access — skipping.")
        return True

    new_ca = current_ca + read_entry
    set_result = subprocess.run(
        ["wevtutil", "sl", "security", f"/ca:{new_ca}"],
        capture_output=True, text=True,
    )
    if set_result.returncode == 0:
        print("      Done.")
        return True
    print(f"      WARNING: wevtutil sl failed: {set_result.stderr.strip()}")
    return False


def verify_access() -> bool:
    print("[3/3] Verifying non-elevated Security log read access...")
    cmd = (
        "Get-WinEvent -LogName Security -MaxEvents 1 "
        "-FilterXPath '*[System[EventID=4625]]' "
        "| Select-Object -ExpandProperty RecordId"
    )
    result = _run_ps(cmd)
    err = result.stderr.strip()
    if "unauthorized" in err.lower() or "access is denied" in err.lower():
        print("      Still denied. A sign-out/sign-in (or reboot) is usually")
        print("      needed for the new group membership to take effect.")
        return False
    if result.returncode == 0:
        print("      Success — Security log is now readable without elevation.")
        return True
    print(f"      Inconclusive (no failed logons may exist yet): {err or '(no error)'}")
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true", help="Only run the verification check")
    args = parser.parse_args()

    if args.verify:
        verify_access()
        return

    if not _is_admin():
        print("ERROR: This script must be run as Administrator (one-time only).")
        print("Right-click PowerShell/Terminal -> 'Run as Administrator', then re-run:")
        print("    python grant_security_log_access.py")
        sys.exit(1)

    username = _current_user()
    print(f"Granting Security-log read access to current user: {username}\n")

    ok1 = add_to_event_log_readers(username)
    ok2 = grant_security_channel_access(username)

    print()
    print("====================================================")
    if ok1 or ok2:
        print("Setup applied.")
        print("IMPORTANT: sign out and back in (or reboot) for this to take")
        print("effect, then verify with:")
        print("    python grant_security_log_access.py --verify")
        print()
        print("After that, JARVIS's failed-login watcher (including the boot")
        print("catch-up check) will work even when auto-started at login —")
        print("no more 'Could not read baseline' / no more needing to run")
        print("JARVIS as Administrator.")
    else:
        print("Both methods reported warnings above — Security log access may")
        print("still require running JARVIS elevated. See the warnings for detail.")
    print("====================================================")


if __name__ == "__main__":
    main()