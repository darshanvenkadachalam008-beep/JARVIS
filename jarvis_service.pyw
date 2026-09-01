"""
jarvis_service.pyw — Windowless launcher stub for jarvis_service.py
===================================================================
Provides double-click-without-console convenience on Windows while
allowing jarvis_service.py to be imported as a standard Python module.
"""
import runpy
from pathlib import Path

_script = Path(__file__).resolve().parent / "jarvis_service.py"
runpy.run_path(str(_script), run_name="__main__")