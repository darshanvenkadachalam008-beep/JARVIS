"""Fix the bad unicode escape on line 294 of jarvis_watcher_service.py"""
from pathlib import Path

f = Path("jarvis_watcher_service.py")
src = f.read_text(encoding="utf-8")

# Find and fix the bad line
bad = r"""\u{1F480}"""
if bad in src:
    # Replace the entire bad title line with a clean one
    import re
    src = re.sub(
        r'title\s*=\s*"\\u\{1F480\}[^"]*"\.replace\("[^"]*",\s*"[^"]*"\)',
        'title   = "\U0001F480 DANGER \u2014 INTRUSION DETECTED \U0001F480"',
        src
    )
    f.write_text(src, encoding="utf-8")
    print("Fixed successfully!")
else:
    print("Bad pattern not found — checking line 294:")
    lines = src.splitlines()
    for i, line in enumerate(lines[290:298], start=291):
        print(f"  {i}: {line}")
