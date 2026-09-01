"""
install_startup.py  —  Run this ONCE to install JARVIS as a Windows startup service.
=====================================================================================
What it does:
  1. Finds your pythonw.exe (runs Python with NO console window)
  2. Adds a registry key → HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
     so Windows launches jarvis_service.pyw automatically on every login
  3. Also creates a Desktop shortcut so you can launch manually anytime
  4. Optionally starts the service immediately after installing

Run:  python install_startup.py
To uninstall:  python install_startup.py --uninstall
"""

import argparse
import os
import shutil
import subprocess
import sys
import winreg
from pathlib import Path


# ── Paths ─────────────────────────────────────────────────────────────────────

BASE_DIR       = Path(__file__).resolve().parent
SERVICE_SCRIPT = BASE_DIR / "jarvis_service.pyw"
VENV_DIR       = BASE_DIR / "venv"
REGISTRY_KEY   = "JARVIS_Background_Service"


def find_pythonw() -> Path:
    """
    Find pythonw.exe — the windowless Python launcher.
    Checks venv first, then the current interpreter's folder.
    """
    # 1. venv in project folder
    venv_pw = VENV_DIR / "Scripts" / "pythonw.exe"
    if venv_pw.exists():
        return venv_pw

    # 2. Same folder as current python.exe
    py      = Path(sys.executable)
    sibling = py.parent / "pythonw.exe"
    if sibling.exists():
        return sibling

    # 3. System PATH
    found = shutil.which("pythonw")
    if found:
        return Path(found)

    raise FileNotFoundError(
        "Could not find pythonw.exe. Make sure Python is installed correctly.\n"
        f"Looked in: {venv_pw}, {sibling}, and PATH."
    )


def get_startup_command(pythonw: Path) -> str:
    """Build the command string stored in the registry."""
    return f'"{pythonw}" "{SERVICE_SCRIPT}"'


# ── Registry helpers ──────────────────────────────────────────────────────────

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def add_to_startup(command: str):
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, REGISTRY_KEY, 0, winreg.REG_SZ, command)
    print(f"  ✅ Registry key added: HKCU\\{RUN_KEY}\\{REGISTRY_KEY}")


def remove_from_startup():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, REGISTRY_KEY)
        print(f"  ✅ Registry key removed: {REGISTRY_KEY}")
    except FileNotFoundError:
        print(f"  ℹ️  Key '{REGISTRY_KEY}' was not in the registry.")


def is_installed() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, REGISTRY_KEY)
        return True
    except FileNotFoundError:
        return False


# ── Desktop shortcut ──────────────────────────────────────────────────────────

def create_shortcut(pythonw: Path):
    """Create a Desktop .lnk shortcut using PowerShell (no extra deps needed)."""
    desktop = Path(os.path.expanduser("~")) / "Desktop"
    lnk     = desktop / "JARVIS.lnk"

    ps_script = f"""
$WS = New-Object -ComObject WScript.Shell
$SC = $WS.CreateShortcut("{lnk}")
$SC.TargetPath = "{pythonw}"
$SC.Arguments = '"{SERVICE_SCRIPT}"'
$SC.WorkingDirectory = "{BASE_DIR}"
$SC.Description = "JARVIS Background Service"
$SC.IconLocation = "{BASE_DIR}\\face.png, 0"
$SC.Save()
"""
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            check=True, capture_output=True
        )
        print(f"  ✅ Desktop shortcut created: {lnk}")
    except Exception as e:
        print(f"  ⚠️  Could not create desktop shortcut: {e}")


def remove_shortcut():
    lnk = Path(os.path.expanduser("~")) / "Desktop" / "JARVIS.lnk"
    if lnk.exists():
        lnk.unlink()
        print(f"  ✅ Desktop shortcut removed")
    else:
        print(f"  ℹ️  No desktop shortcut found")


# ── Startup folder method (fallback / alternative) ────────────────────────────

def add_to_startup_folder(pythonw: Path):
    """
    Alternative: drop a .vbs launcher into the Windows Startup folder.
    This is a fallback if the registry method doesn't work for your setup.
    """
    startup_folder = Path(os.getenv("APPDATA")) / r"Microsoft\Windows\Start Menu\Programs\Startup"
    vbs_path       = startup_folder / "JARVIS.vbs"

    vbs_content = f"""Set WshShell = CreateObject("WScript.Shell")
WshShell.Run Chr(34) & "{pythonw}" & Chr(34) & " " & Chr(34) & "{SERVICE_SCRIPT}" & Chr(34), 0, False
"""
    vbs_path.write_text(vbs_content, encoding="utf-8")
    print(f"  ✅ Startup folder entry created: {vbs_path}")
    return vbs_path


def remove_from_startup_folder():
    startup_folder = Path(os.getenv("APPDATA")) / r"Microsoft\Windows\Start Menu\Programs\Startup"
    vbs_path       = startup_folder / "JARVIS.vbs"
    if vbs_path.exists():
        vbs_path.unlink()
        print(f"  ✅ Startup folder entry removed")
    else:
        print(f"  ℹ️  No startup folder entry found")


# ── Main ──────────────────────────────────────────────────────────────────────

def install():
    print("\n🤖  JARVIS Startup Installer")
    print("=" * 45)

    # Verify the service script exists
    if not SERVICE_SCRIPT.exists():
        print(f"\n❌  ERROR: jarvis_service.pyw not found at:\n   {SERVICE_SCRIPT}")
        print("   Make sure jarvis_service.pyw is in the same folder as this script.")
        sys.exit(1)

    # Find pythonw.exe
    print("\n[1/4]  Finding pythonw.exe...")
    try:
        pythonw = find_pythonw()
        print(f"  ✅  Found: {pythonw}")
    except FileNotFoundError as e:
        print(f"\n❌  {e}")
        sys.exit(1)

    # Add to Windows registry startup
    print("\n[2/4]  Adding to Windows startup (registry)...")
    command = get_startup_command(pythonw)
    print(f"  Command: {command}")
    add_to_startup(command)

    # Also add to Startup folder as backup
    print("\n[3/4]  Adding to Startup folder (backup method)...")
    add_to_startup_folder(pythonw)

    # Desktop shortcut
    print("\n[4/4]  Creating Desktop shortcut...")
    create_shortcut(pythonw)

    print("\n" + "=" * 45)
    print("✅  JARVIS will now start automatically on every Windows login.")
    print()
    print("📌  What happens next:")
    print("   • On next login → JARVIS starts silently in background")
    print("   • You'll see a JARVIS icon in your system tray (bottom-right)")
    print("   • Say 'Hey Jarvis' anywhere — UI pops up instantly")
    print("   • Or click the tray icon to show JARVIS manually")
    print()

    # Ask to start now
    ans = input("▶  Start JARVIS background service now? (y/n): ").strip().lower()
    if ans == "y":
        print("\n🚀  Starting JARVIS...")
        subprocess.Popen(
            [str(pythonw), str(SERVICE_SCRIPT)],
            cwd=str(BASE_DIR),
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        )
        print("  ✅  JARVIS started. Check your system tray.")
    else:
        print("\n  ℹ️  You can start it manually: double-click the Desktop shortcut")
        print(f"  Or run: pythonw \"{SERVICE_SCRIPT}\"")


def uninstall():
    print("\n🤖  JARVIS Startup Uninstaller")
    print("=" * 45)

    print("\n[1/3]  Removing registry entry...")
    remove_from_startup()

    print("\n[2/3]  Removing startup folder entry...")
    remove_from_startup_folder()

    print("\n[3/3]  Removing desktop shortcut...")
    remove_shortcut()

    print("\n" + "=" * 45)
    print("✅  JARVIS removed from Windows startup.")
    print("   (The project files are untouched — just won't auto-start anymore)")


if __name__ == "__main__":
    if sys.platform != "win32":
        print("❌  This installer is Windows-only.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="JARVIS startup installer")
    parser.add_argument("--uninstall", action="store_true", help="Remove JARVIS from startup")
    args = parser.parse_args()

    if args.uninstall:
        uninstall()
    else:
        install()