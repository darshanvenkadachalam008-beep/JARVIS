"""
patch_no_flash.py — Fix the flashing terminal on JARVIS startup
================================================================
The terminal flashes every 3 seconds because the PowerShell subprocess
calls in core/intruder_alert.py are missing the CREATE_NO_WINDOW flag.
Windows briefly opens a console window for each PowerShell call — 3
times per second of polling. This patch adds the flag to all 3 calls
so they run completely invisibly in the background.

Run:
    python patch_no_flash.py

Then restart JARVIS:
    python jarvis_service.pyw
"""
import re
import shutil
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
TARGET   = BASE_DIR / "core" / "intruder_alert.py"
BACKUP   = BASE_DIR / "core" / "intruder_alert.py.bak_noflash"


def patch():
    print("\n🔧  JARVIS — Fix Flashing Terminal Patch")
    print("=" * 45)

    if not TARGET.exists():
        print(f"❌  Not found: {TARGET}")
        print("    Make sure you run this from the JARVIS project folder.")
        sys.exit(1)

    # Backup
    shutil.copy2(TARGET, BACKUP)
    print(f"  📦  Backup saved: {BACKUP.name}")

    src = TARGET.read_text(encoding="utf-8")

    # Check if already patched
    if src.count("CREATE_NO_WINDOW") >= 3:
        print("  ✅  Already patched — CREATE_NO_WINDOW already present in all calls")
        print("\n  Restart JARVIS to confirm the flash is gone:")
        print("    python jarvis_service.pyw")
        return

    # Add CREATE_NO_WINDOW to every subprocess.run that's missing it
    # Pattern matches the closing args of each subprocess.run call
    fixed = re.sub(
        r'(capture_output=True, text=True, timeout=\d+)\s*\)',
        r'\1,\n            creationflags=subprocess.CREATE_NO_WINDOW\n        )',
        src
    )

    count = fixed.count("CREATE_NO_WINDOW")
    if count == 0:
        print("❌  Could not find the expected subprocess.run pattern.")
        print("    The file may have been modified. Please share it and I'll help.")
        sys.exit(1)

    TARGET.write_text(fixed, encoding="utf-8")
    print(f"  ✅  Fixed {count} subprocess.run call(s) — terminal flash suppressed")

    print()
    print("=" * 45)
    print("✅  Patch applied!")
    print()
    print("  Restart JARVIS to apply:")
    print("    python jarvis_service.pyw")
    print()
    print("  The terminal will no longer flash while JARVIS is running.")


if __name__ == "__main__":
    if sys.platform != "win32":
        print("❌  Windows only.")
        sys.exit(1)
    patch()