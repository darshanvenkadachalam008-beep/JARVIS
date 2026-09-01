"""
fix_mobile_server_syntax.py
===========================
Fixes SyntaxError: f-string invalid syntax on mobile_server.py line 565.
Caused by the previous FCM token refresh patch injecting JS with
backslash-u unicode escapes inside a Python f-string.

Run once:
    python fix_mobile_server_syntax.py

Then restart JARVIS:
    python jarvis_service.pyw
"""
from pathlib import Path
import re, sys, shutil

BASE_DIR = Path(__file__).resolve().parent
TARGET   = BASE_DIR / "mobile_server.py"
BACKUP   = BASE_DIR / "mobile_server.py.bak_syntax"

if not TARGET.exists():
    print(f"❌  Not found: {TARGET}")
    sys.exit(1)

src = TARGET.read_text(encoding="utf-8")

# ── Find and fix the problematic injected fetch block ─────────────────────────
# The patch inserted JS fetch code after the ws.send register_token line.
# The issue is \u inside an f-string triple-quote in Python 3.10.
# We'll replace the entire injected block with a clean version.

BAD_PATTERN = re.compile(
    r"(ws\.send\(JSON\.stringify\(\{+type: 'register_token', data: (?:token|window\.__PENDING_FCM_TOKEN__)\}+\)\);)\s*"
    r"// Also POST token via HTTP.*?\.catch\(\(\) => \{\}\);",
    re.DOTALL
)

if BAD_PATTERN.search(src):
    shutil.copy2(TARGET, BACKUP)
    print(f"✅  Backup saved → {BACKUP.name}")

    CLEAN_JS = r"""ws.send(JSON.stringify({{type: 'register_token', data: token}}));
          // Also POST token via HTTP so watcher service always has fresh token
          fetch('/register-token', {{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{token:token}})}}).then(r=>r.json()).then(d=>{{if(d.ok)addLine('SYS: FCM token refreshed on PC','sys');}}).catch(()=>{{}});"""

    src = BAD_PATTERN.sub(CLEAN_JS, src)
    TARGET.write_text(src, encoding="utf-8")
    print("✅  Syntax error fixed in mobile_server.py")
else:
    # Fallback: restore from backup if it exists
    bak = BASE_DIR / "mobile_server.py.bak"
    if bak.exists():
        shutil.copy2(TARGET, BACKUP)
        shutil.copy2(bak, TARGET)
        print("✅  Restored mobile_server.py from backup")
        print("ℹ️   FCM token HTTP refresh patch will be re-applied cleanly")
    else:
        print("⚠️   Could not find the bad pattern — checking line 565 manually...")
        lines = src.splitlines()
        for i, line in enumerate(lines[560:570], start=561):
            print(f"  {i}: {line}")
        print("\nPaste the above output and I'll fix it manually.")
        sys.exit(1)

print()
print("=" * 50)
print("  Now restart JARVIS:")
print("    python jarvis_service.pyw")
print()
print("  Then restart the watcher service:")
print("    nssm start JARVISWatcher")
print("=" * 50)