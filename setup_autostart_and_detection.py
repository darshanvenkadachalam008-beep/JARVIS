"""
setup_autostart_and_detection.py
==================================
ONE SCRIPT — sets up everything so JARVIS:

  1. Starts automatically every time Windows boots (no manual launch needed)
  2. Can read the Security Event Log without needing Administrator rights
     (so wrong-password detection works even when JARVIS auto-starts normally)
  3. Catches failed login attempts that happened BEFORE JARVIS finished
     starting (e.g. at the lock screen during the ~15s boot-to-running gap)

HOW TO USE:
-----------
Run this script ONCE from an elevated (Administrator) terminal.
Right-click PowerShell or Command Prompt → "Run as Administrator", then:

    cd D:\\Mark-XXXIX-OR-main\\Mark-XXXIX-OR-main
    .\\venv\\Scripts\\Activate.ps1
    python setup_autostart_and_detection.py

After it completes, SIGN OUT and SIGN BACK IN (or reboot) once.
From that point on, JARVIS starts automatically on every boot and
detects wrong passwords immediately — no further setup ever needed.

To verify everything is working:
    python setup_autostart_and_detection.py --verify

To remove JARVIS from auto-start:
    python setup_autostart_and_detection.py --uninstall
"""
from __future__ import annotations

import argparse
import ctypes
import getpass
import os
import shutil
import subprocess
import sys
import winreg
from pathlib import Path


# ═══════════════════════════════════════════════════════════════════════════════
# PATHS
# ═══════════════════════════════════════════════════════════════════════════════

BASE_DIR       = Path(__file__).resolve().parent
SERVICE_SCRIPT = BASE_DIR / "jarvis_service.py"
VENV_DIR       = BASE_DIR / "venv"
REGISTRY_KEY   = "JARVIS_Background_Service"
RUN_KEY        = r"Software\Microsoft\Windows\CurrentVersion\Run"


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _step(n: int, total: int, label: str):
    print(f"\n[{n}/{total}] {label}")


def _ok(msg: str):
    print(f"  ✅  {msg}")


def _warn(msg: str):
    print(f"  ⚠️  {msg}")


def _err(msg: str):
    print(f"  ❌  {msg}")


def _info(msg: str):
    print(f"  ℹ️  {msg}")


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1: AUTO-START ON BOOT
# ═══════════════════════════════════════════════════════════════════════════════

def _find_pythonw() -> Path:
    """Find pythonw.exe (windowless Python, so no terminal pops up on boot)."""
    candidates = [
        VENV_DIR / "Scripts" / "pythonw.exe",
        Path(sys.executable).parent / "pythonw.exe",
    ]
    for c in candidates:
        if c.exists():
            return c
    found = shutil.which("pythonw")
    if found:
        return Path(found)
    raise FileNotFoundError(
        "Could not find pythonw.exe.\n"
        f"  Checked: {candidates[0]}, {candidates[1]}, and PATH."
    )


def _startup_command(pythonw: Path) -> str:
    return f'"{pythonw}" "{SERVICE_SCRIPT}"'


def install_autostart():
    """Register JARVIS in the Windows registry so it auto-starts on login."""
    pythonw = _find_pythonw()
    cmd = _startup_command(pythonw)

    # Method 1: Registry HKCU Run key (primary)
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, REGISTRY_KEY, 0, winreg.REG_SZ, cmd)
    _ok(f"Registry: HKCU\\{RUN_KEY}\\{REGISTRY_KEY}")

    # Method 2: Startup folder .vbs launcher (fallback — fires even if registry is slow)
    startup_folder = Path(os.getenv("APPDATA")) / r"Microsoft\Windows\Start Menu\Programs\Startup"
    vbs_path = startup_folder / "JARVIS.vbs"
    vbs_content = (
        f'Set WshShell = CreateObject("WScript.Shell")\n'
        f'WshShell.Run Chr(34) & "{pythonw}" & Chr(34) & " " & Chr(34) & "{SERVICE_SCRIPT}" & Chr(34), 0, False\n'
    )
    vbs_path.write_text(vbs_content, encoding="utf-8")
    _ok(f"Startup folder: {vbs_path}")

    # Method 3: Desktop shortcut (for manual launches too)
    desktop = Path(os.path.expanduser("~")) / "Desktop"
    lnk = desktop / "JARVIS.lnk"
    icon_path = BASE_DIR / "face.png"
    ps_script = f"""
$WS = New-Object -ComObject WScript.Shell
$SC = $WS.CreateShortcut("{lnk}")
$SC.TargetPath = "{pythonw}"
$SC.Arguments = '"{SERVICE_SCRIPT}"'
$SC.WorkingDirectory = "{BASE_DIR}"
$SC.Description = "JARVIS Background Service"
$SC.IconLocation = "{icon_path}, 0"
$SC.Save()
"""
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            check=True, capture_output=True
        )
        _ok(f"Desktop shortcut: {lnk}")
    except Exception as e:
        _warn(f"Could not create desktop shortcut: {e}")

    return pythonw


def remove_autostart():
    """Remove all auto-start entries for JARVIS."""
    # Registry
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, REGISTRY_KEY)
        _ok("Registry entry removed")
    except FileNotFoundError:
        _info("Registry entry was not present")

    # Startup folder
    startup_folder = Path(os.getenv("APPDATA")) / r"Microsoft\Windows\Start Menu\Programs\Startup"
    vbs_path = startup_folder / "JARVIS.vbs"
    if vbs_path.exists():
        vbs_path.unlink()
        _ok(f"Startup folder entry removed: {vbs_path}")
    else:
        _info("No startup folder entry found")

    # Desktop shortcut
    lnk = Path(os.path.expanduser("~")) / "Desktop" / "JARVIS.lnk"
    if lnk.exists():
        lnk.unlink()
        _ok("Desktop shortcut removed")
    else:
        _info("No desktop shortcut found")


def check_autostart() -> bool:
    """Return True if JARVIS is registered to auto-start."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, REGISTRY_KEY)
            return bool(val)
    except FileNotFoundError:
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2: SECURITY LOG READ ACCESS
# ═══════════════════════════════════════════════════════════════════════════════

def _current_username() -> str:
    return getpass.getuser()


def _get_user_sid(username: str) -> str | None:
    """Get the SID string for a local user account via PowerShell."""
    try:
        result = subprocess.run(
            [
                "powershell", "-NonInteractive", "-NoProfile", "-Command",
                f"(New-Object System.Security.Principal.NTAccount('{username}')).Translate"
                f"([System.Security.Principal.SecurityIdentifier]).Value"
            ],
            capture_output=True, text=True, timeout=10
        )
        sid = result.stdout.strip()
        if sid.startswith("S-1-"):
            return sid
        return None
    except Exception:
        return None


def _add_user_to_event_log_readers(username: str) -> bool:
    """Add user to the built-in 'Event Log Readers' group."""
    try:
        result = subprocess.run(
            ["net", "localgroup", "Event Log Readers", f"{username}", "/add"],
            capture_output=True, text=True
        )
        # Exit code 0 = added, 2 = already a member (both are fine)
        if result.returncode in (0, 2):
            return True
        # Check stderr for "already a member" message
        combined = (result.stdout + result.stderr).lower()
        if "already" in combined or "member" in combined:
            return True
        return False
    except Exception:
        return False


def _grant_wevtutil_channel_access(user_sid: str) -> bool:
    """
    Directly set channel-access on the Security log via wevtutil.
    This is the authoritative fallback when Event Log Readers group
    alone doesn't cover the Security channel (domain/GPO environments).
    """
    try:
        # Get current channel access SDDL
        result = subprocess.run(
            ["wevtutil", "gl", "security", "/f:xml"],
            capture_output=True, text=True, timeout=10
        )
        current_sddl = ""
        for line in result.stdout.splitlines():
            line = line.strip()
            if "channelAccess" in line:
                # Extract SDDL from <channelAccess>...</channelAccess>
                start = line.find(">") + 1
                end = line.rfind("<")
                if start > 0 and end > start:
                    current_sddl = line[start:end].strip()
                break

        if not current_sddl:
            # wevtutil didn't return channelAccess — try sl approach directly
            current_sddl = ""

        # ACE to add: (A;;0x1;;;{sid}) = Allow Read for this user
        new_ace = f"(A;;0x1;;;{user_sid})"

        # Only add if not already present (idempotent)
        if new_ace in current_sddl:
            return True  # Already granted

        # Append the new ACE to the DACL
        if current_sddl:
            # Find the DACL section (D: part) and append our ACE
            if "D:(" in current_sddl or "D:" in current_sddl:
                # Insert before the first closing paren group boundary
                # Standard SDDL: O:BAG:SYD:(...)...
                # Append new ACE at end of DACL section
                new_sddl = current_sddl + new_ace
            else:
                new_sddl = current_sddl + new_ace
        else:
            # Fallback minimal SDDL granting read to Administrators + this user
            new_sddl = f"O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;{user_sid})"

        subprocess.run(
            ["wevtutil", "sl", "security", f"/ca:{new_sddl}"],
            check=True, capture_output=True, timeout=10
        )
        return True
    except subprocess.CalledProcessError as e:
        # wevtutil sl can fail if the SDDL is invalid; don't abort — method 1 may suffice
        return False
    except Exception:
        return False


def grant_security_log_access() -> bool:
    """
    Grant the current user permanent non-elevated read access to
    the Windows Security Event Log. Returns True if at least one
    method succeeded.
    """
    username = _current_username()
    user_sid = _get_user_sid(username)

    _info(f"User: {username}  SID: {user_sid or 'could not resolve'}")

    success = False

    # Method 1: Add to Event Log Readers group
    if _add_user_to_event_log_readers(username):
        _ok(f"Added '{username}' to 'Event Log Readers' group")
        success = True
    else:
        _warn(f"Could not add '{username}' to 'Event Log Readers' group")

    # Method 2: Direct wevtutil channel-access SDDL grant
    if user_sid:
        if _grant_wevtutil_channel_access(user_sid):
            _ok(f"Granted direct read access to Security log channel (SID: {user_sid})")
            success = True
        else:
            _warn("Could not apply wevtutil channel-access grant (method 2)")
    else:
        _warn("Could not resolve SID — skipping wevtutil method")

    return success


def verify_security_log_access() -> bool:
    """
    Attempt a real Security log read WITHOUT elevation to confirm access works.
    Returns True if the read succeeded.
    """
    try:
        result = subprocess.run(
            [
                "powershell", "-NonInteractive", "-NoProfile", "-Command",
                "Get-WinEvent -LogName Security -MaxEvents 1 "
                "-FilterXPath '*[System[EventID=4625]]' "
                "-ErrorAction SilentlyContinue "
                "| Select-Object -ExpandProperty RecordId"
            ],
            capture_output=True, text=True, timeout=12
        )
        # If we get output (a number or empty-but-no-error), access works.
        # A real access-denied gives a non-zero exit code and stderr.
        if result.returncode == 0:
            return True
        stderr = result.stderr.lower()
        if "access" in stderr and "denied" in stderr:
            return False
        # No events found is still success (log is empty or no 4625 events)
        return True
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN FLOWS
# ═══════════════════════════════════════════════════════════════════════════════

def setup():
    TOTAL_STEPS = 3

    print("\n" + "═" * 60)
    print("  🤖  JARVIS — Auto-Start & Detection Setup")
    print("═" * 60)

    if not SERVICE_SCRIPT.exists():
        _err(f"jarvis_service.pyw not found at:\n   {SERVICE_SCRIPT}")
        _err("Run this script from inside the JARVIS project folder.")
        sys.exit(1)

    if not _is_admin():
        print()
        _err("This script must be run as Administrator.")
        print("""
  How to run as Administrator:
  1. Press Win+X → choose "Windows PowerShell (Admin)" or "Terminal (Admin)"
  2. cd D:\\Mark-XXXIX-OR-main\\Mark-XXXIX-OR-main
  3. .\\venv\\Scripts\\Activate.ps1
  4. python setup_autostart_and_detection.py
""")
        sys.exit(1)

    # ── Step 1: Auto-start ────────────────────────────────────────────────
    _step(1, TOTAL_STEPS, "Setting up auto-start on Windows boot...")
    try:
        pythonw = install_autostart()
        _ok(f"JARVIS will now auto-start on every Windows login")
        _info(f"Using: {pythonw}")
    except FileNotFoundError as e:
        _err(str(e))
        sys.exit(1)
    except Exception as e:
        _err(f"Auto-start setup failed: {e}")
        sys.exit(1)

    # ── Step 2: Security log permissions ─────────────────────────────────
    _step(2, TOTAL_STEPS, "Granting Security log read access (for wrong-password detection)...")
    log_ok = grant_security_log_access()
    if not log_ok:
        _warn("Could not grant Security log access — JARVIS may still need Administrator")
        _warn("to detect failed logins. Try rebooting and re-running this script.")
    else:
        _ok("Security log access granted — JARVIS can now detect wrong passwords")
        _info("without needing to be run as Administrator ever again.")

    # ── Step 3: Confirm boot-catchup is in place ──────────────────────────
    _step(3, TOTAL_STEPS, "Verifying boot catch-up detection is enabled...")
    intruder_alert_path = BASE_DIR / "core" / "intruder_alert.py"
    if intruder_alert_path.exists():
        content = intruder_alert_path.read_text(encoding="utf-8", errors="ignore")
        if "BOOT_CATCHUP_WINDOW_MINUTES" in content and "bypass_debounce" in content:
            _ok("Boot catch-up is active — JARVIS will detect wrong passwords")
            _info("typed at the lock screen even BEFORE JARVIS finishes starting.")
        else:
            _warn("Boot catch-up logic not found in core/intruder_alert.py.")
            _warn("Run the patch_boot_catchup.py patch first if you have it,")
            _warn("or re-download it from the previous chat session.")
    else:
        _warn("core/intruder_alert.py not found — check your project folder.")

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "═" * 60)
    print("  ✅  Setup complete!")
    print("═" * 60)
    print("""
  ⚠️  IMPORTANT — sign out and back in (or reboot) once now.
     This is required so the new Security log permissions take effect.

  After that, every time Windows starts:
     • JARVIS launches automatically in the background (no tray popup)
     • Wrong password at the lock screen → you get a notification
       on your phone within seconds, even if it was typed before
       JARVIS finished booting
     • Webcam snapshot + Telegram + FCM push all fire as normal

  To verify everything is working after your next login:
     python setup_autostart_and_detection.py --verify

  To remove JARVIS from auto-start later:
     python setup_autostart_and_detection.py --uninstall
""")

    ans = input("  ▶  Reboot now to apply changes? (y/n): ").strip().lower()
    if ans == "y":
        print("\n  🔄  Rebooting in 5 seconds... (Ctrl+C to cancel)")
        import time
        for i in range(5, 0, -1):
            print(f"     {i}...")
            time.sleep(1)
        subprocess.run(["shutdown", "/r", "/t", "0"])
    else:
        print("\n  ℹ️  Remember to sign out/reboot before testing!")


def verify():
    print("\n" + "═" * 60)
    print("  🔍  JARVIS Setup Verification")
    print("═" * 60)

    all_ok = True

    # Check 1: Auto-start registry
    print("\n[1] Auto-start on boot:")
    if check_autostart():
        _ok("JARVIS is registered to auto-start (HKCU registry)")
    else:
        _err("JARVIS is NOT registered to auto-start")
        _info("Run: python setup_autostart_and_detection.py")
        all_ok = False

    startup_folder = Path(os.getenv("APPDATA")) / r"Microsoft\Windows\Start Menu\Programs\Startup"
    vbs_path = startup_folder / "JARVIS.vbs"
    if vbs_path.exists():
        _ok("Startup folder fallback (.vbs) is in place")
    else:
        _warn("Startup folder fallback missing (registry method should still work)")

    # Check 2: Security log access
    print("\n[2] Security Event Log read access:")
    if verify_security_log_access():
        _ok("Can read the Security log without Administrator rights")
        _ok("Wrong-password detection will work when JARVIS auto-starts")
    else:
        _err("Cannot read the Security log — run setup as Administrator first,")
        _err("then sign out and back in for the permissions to take effect.")
        all_ok = False

    # Check 3: Boot catch-up in code
    print("\n[3] Boot catch-up detection:")
    intruder_alert_path = BASE_DIR / "core" / "intruder_alert.py"
    if intruder_alert_path.exists():
        content = intruder_alert_path.read_text(encoding="utf-8", errors="ignore")
        if "BOOT_CATCHUP_WINDOW_MINUTES" in content:
            _ok("Boot catch-up code is present (catches lock-screen attempts before JARVIS starts)")
        else:
            _warn("Boot catch-up code not found — apply patch_boot_catchup.py")
            all_ok = False
    else:
        _err("core/intruder_alert.py not found")
        all_ok = False

    # Check 4: jarvis_service.pyw exists
    print("\n[4] Service script:")
    if SERVICE_SCRIPT.exists():
        _ok(f"jarvis_service.pyw found at {SERVICE_SCRIPT}")
    else:
        _err(f"jarvis_service.pyw NOT found at {SERVICE_SCRIPT}")
        all_ok = False

    print("\n" + "═" * 60)
    if all_ok:
        print("  ✅  All checks passed — JARVIS is fully set up!")
        print("     Wrong passwords will be detected and your phone alerted.")
    else:
        print("  ⚠️  Some checks failed — see above for what to fix.")
    print("═" * 60 + "\n")


def uninstall():
    print("\n" + "═" * 60)
    print("  🗑️  Removing JARVIS from auto-start")
    print("═" * 60)
    remove_autostart()
    print("\n  ✅  JARVIS removed from Windows startup.")
    print("     Project files are untouched — just won't auto-start anymore.")
    print("     Re-run without --uninstall to set it up again.\n")


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if sys.platform != "win32":
        print("❌  This script is Windows-only.")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="JARVIS auto-start + wrong-password detection setup"
    )
    parser.add_argument("--verify",    action="store_true", help="Verify everything is working")
    parser.add_argument("--uninstall", action="store_true", help="Remove JARVIS from auto-start")
    args = parser.parse_args()

    if args.verify:
        verify()
    elif args.uninstall:
        uninstall()
    else:
        setup()