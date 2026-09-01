"""
patch_boot_catchup.py — Phase 7.3: detect failed logons missed before JARVIS started
========================================================================================
Replaces core/intruder_alert.py with a version that, once on every JARVIS
startup, looks back over the last 10 minutes of the Windows Security Event
Log for any failed logon attempts (event 4625) that happened BEFORE the
watcher started — e.g. a wrong password typed at the lock screen during
the ~15-20s gap between Windows finishing login and JARVIS's watcher
actually starting. Those get alerted on (Telegram + phone notification)
exactly like a live detection, just slightly delayed.

A small state file (memory/intruder_alert_state.json) remembers the
highest RecordId already alerted on, so restarting JARVIS twice in a
row doesn't re-alert on the same already-handled event.

IMPORTANT — this alone is not enough if JARVIS auto-starts at login:
reading the Security log normally requires Administrator rights, and
the auto-start registry entry (from install_startup.py) runs at your
normal login level, not elevated. Run grant_security_log_access.py
(as Administrator, once) so your account can read the Security log
without elevation — otherwise this feature will silently do nothing
when JARVIS starts automatically at boot.

Run once from the project root:
    python patch_boot_catchup.py
"""
from __future__ import annotations
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
CORE_DIR = BASE_DIR / "core"


def backup(path: Path):
    if path.exists():
        bak = path.with_suffix(path.suffix + ".bak_catchup")
        if not bak.exists():
            bak.write_bytes(path.read_bytes())


def main():
    src = BASE_DIR / "_new_intruder_alert.py"
    dest = CORE_DIR / "intruder_alert.py"

    if not src.exists():
        print("[1] WARNING: _new_intruder_alert.py not found next to this script -- nothing applied")
        return

    backup(dest)
    dest.write_bytes(src.read_bytes())
    print("[1] core/intruder_alert.py replaced -- boot catch-up + state persistence added")

    print()
    print("====================================================")
    print("Boot catch-up patch applied.")
    print()
    print("NEXT, AND IMPORTANT:")
    print("  Run grant_security_log_access.py AS ADMINISTRATOR (one time)")
    print("  so JARVIS can read the Security log even when it auto-starts")
    print("  at login (not elevated). Without this, the catch-up feature")
    print("  will silently find nothing when JARVIS starts automatically.")
    print()
    print("  Right-click PowerShell/Terminal -> 'Run as Administrator', then:")
    print("    python grant_security_log_access.py")
    print("  Then sign out and back in (or reboot) once, then verify with:")
    print("    python grant_security_log_access.py --verify")
    print()
    print("After that:")
    print("  1. Restart JARVIS: python jarvis_service.pyw")
    print("  2. Look for one of these near startup:")
    print("       [IntruderAlert] Boot catch-up found N failed logon(s)...")
    print("       [IntruderAlert] Boot catch-up -- no missed failed logons found")
    print("  3. Test: lock your PC, type a wrong password, wait a bit before")
    print("     unlocking and starting JARVIS manually if you want to simulate")
    print("     the boot gap, or just reboot for the real test.")
    print("====================================================")


if __name__ == "__main__":
    main()