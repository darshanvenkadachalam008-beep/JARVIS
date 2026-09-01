"""
memory/memory_editor.py — Phase 3: Memory Editor HUD Overlay
=============================================================
Always-on-top PyQt overlay that shows all stored memory facts.
User can view, delete, and refresh entries.  No inline editing
(by design — voice commands handle that).

Usage (from main.py or ui.py):
    from memory.memory_editor import MemoryEditorOverlay
    editor = MemoryEditorOverlay()
    editor.show()
"""

from __future__ import annotations
import sys
import json
from pathlib import Path
from datetime import datetime

import sys as _sys

# Resolve whichever PyQt version is installed. Pylance sees PyQt6 first;
# at runtime we fall back to PyQt5 if needed.
try:
    from PyQt6.QtCore    import Qt, QTimer, pyqtSignal          # type: ignore[import]
    from PyQt6.QtGui     import QColor, QFont                   # type: ignore[import]
    from PyQt6.QtWidgets import (                               # type: ignore[import]
        QApplication, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QPushButton, QScrollArea, QFrame, QSizePolicy,
    )
except ImportError:
    from PyQt5.QtCore    import Qt, QTimer, pyqtSignal          # type: ignore[import]
    from PyQt5.QtGui     import QColor, QFont                   # type: ignore[import]
    from PyQt5.QtWidgets import (                               # type: ignore[import]
        QApplication, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QPushButton, QScrollArea, QFrame, QSizePolicy,
    )

def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


MEMORY_PATH    = _base_dir() / "memory" / "long_term.json"
SUMMARIES_PATH = _base_dir() / "memory" / "conversation_summaries.json"

# ── Colour palette (mirrors ui.py C class) ───────────────────────────────────
_BG       = "#00060a"
_PANEL    = "#010d14"
_BORDER   = "#0d3347"
_BORDER_B = "#1a5c7a"
_PRI      = "#00d4ff"
_PRI_DIM  = "#007a99"
_PRI_GHO  = "#001f2e"
_ACC      = "#ff6b00"
_RED      = "#ff3355"
_GREEN    = "#00ff88"
_TEXT     = "#8ffcff"
_TEXT_DIM = "#3a8a9a"
_TEXT_MED = "#5ab8cc"
_WHITE    = "#d8f8ff"

_CAT_COLOURS = {
    "identity":      "#00d4ff",
    "preferences":   "#ffcc00",
    "projects":      "#00ff88",
    "relationships": "#ff9900",
    "wishes":        "#cc88ff",
    "habits":        "#44ddff",
    "goals":         "#ff6644",
    "notes":         "#8ffcff",
}


class _MemoryRow(QWidget):
    delete_requested = pyqtSignal(str, str)   # category, key

    def __init__(self, category: str, key: str, value: str, updated: str, parent=None):
        super().__init__(parent)
        self.category = category
        self.key      = key
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

        cat_col = _CAT_COLOURS.get(category, _TEXT)
        self.setStyleSheet(f"""
            _MemoryRow, QWidget#row {{
                background: {_PANEL};
                border: 1px solid {_BORDER};
                border-radius: 4px;
            }}
        """)
        self.setObjectName("row")

        hl = QHBoxLayout(self)
        hl.setContentsMargins(10, 6, 6, 6)
        hl.setSpacing(8)

        cat_lbl = QLabel(f"[{category}]")
        cat_lbl.setFont(QFont("Courier New", 7, QFont.Weight.Bold))
        cat_lbl.setStyleSheet(f"color: {cat_col}; background: transparent; min-width: 88px;")
        hl.addWidget(cat_lbl)

        key_lbl = QLabel(key.replace("_", " "))
        key_lbl.setFont(QFont("Courier New", 8, QFont.Weight.Bold))
        key_lbl.setStyleSheet(f"color: {_WHITE}; background: transparent; min-width: 120px;")
        hl.addWidget(key_lbl)

        val_lbl = QLabel(value)
        val_lbl.setFont(QFont("Courier New", 8))
        val_lbl.setStyleSheet(f"color: {_TEXT_MED}; background: transparent;")
        val_lbl.setWordWrap(False)
        val_lbl.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        hl.addWidget(val_lbl, stretch=1)

        date_lbl = QLabel(updated)
        date_lbl.setFont(QFont("Courier New", 7))
        date_lbl.setStyleSheet(f"color: {_TEXT_DIM}; background: transparent; min-width: 80px;")
        date_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        hl.addWidget(date_lbl)

        del_btn = QPushButton("✕")
        del_btn.setFixedSize(22, 22)
        del_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        del_btn.setFont(QFont("Courier New", 8))
        del_btn.setStyleSheet(f"""
            QPushButton {{ background: transparent; color: {_TEXT_DIM};
                           border: 1px solid {_BORDER}; border-radius: 3px; }}
            QPushButton:hover {{ color: {_RED}; border: 1px solid {_RED}; }}
        """)
        del_btn.clicked.connect(lambda: self.delete_requested.emit(category, key))
        hl.addWidget(del_btn)


class _SummaryRow(QWidget):
    delete_requested = pyqtSignal(int)   # index in summaries list

    def __init__(self, idx: int, date: str, summary: str, topics: list, parent=None):
        super().__init__(parent)
        self.idx = idx
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet(f"""
            QWidget {{ background: {_PANEL}; border: 1px solid {_BORDER};
                       border-radius: 4px; }}
        """)

        hl = QHBoxLayout(self)
        hl.setContentsMargins(10, 6, 6, 6)
        hl.setSpacing(8)

        cat_lbl = QLabel("[summary]")
        cat_lbl.setFont(QFont("Courier New", 7, QFont.Weight.Bold))
        cat_lbl.setStyleSheet(f"color: #aa88ff; background: transparent; min-width: 88px;")
        hl.addWidget(cat_lbl)

        text = summary[:120] + ("…" if len(summary) > 120 else "")
        if topics:
            text += f"  ({', '.join(topics[:4])})"
        val_lbl = QLabel(text)
        val_lbl.setFont(QFont("Courier New", 8))
        val_lbl.setStyleSheet(f"color: {_TEXT_MED}; background: transparent;")
        val_lbl.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        hl.addWidget(val_lbl, stretch=1)

        date_lbl = QLabel(date[:16] if date else "")
        date_lbl.setFont(QFont("Courier New", 7))
        date_lbl.setStyleSheet(f"color: {_TEXT_DIM}; background: transparent; min-width: 100px;")
        date_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        hl.addWidget(date_lbl)

        del_btn = QPushButton("✕")
        del_btn.setFixedSize(22, 22)
        del_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        del_btn.setFont(QFont("Courier New", 8))
        del_btn.setStyleSheet(f"""
            QPushButton {{ background: transparent; color: {_TEXT_DIM};
                           border: 1px solid {_BORDER}; border-radius: 3px; }}
            QPushButton:hover {{ color: {_RED}; border: 1px solid {_RED}; }}
        """)
        del_btn.clicked.connect(lambda: self.delete_requested.emit(idx))
        hl.addWidget(del_btn)


class MemoryEditorOverlay(QWidget):
    """
    Always-on-top memory viewer + delete panel.
    Show with .show(); close with the ✕ button or call .hide().
    """

    closed = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent, Qt.WindowType.Tool |
                         Qt.WindowType.WindowStaysOnTopHint |
                         Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setFixedWidth(760)
        self.setStyleSheet(f"""
            MemoryEditorOverlay, QWidget#mem_root {{
                background: rgba(0, 6, 10, 248);
                border: 1px solid {_BORDER_B};
                border-radius: 8px;
            }}
        """)
        self.setObjectName("mem_root")

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(8)

        # ── Header ────────────────────────────────────────────────────────
        hdr = QHBoxLayout()
        title = QLabel("◈  JARVIS MEMORY BANK")
        title.setFont(QFont("Courier New", 13, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {_PRI}; background: transparent;")
        hdr.addWidget(title)
        hdr.addStretch()

        refresh_btn = QPushButton("⟳")
        refresh_btn.setFixedSize(26, 26)
        refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        refresh_btn.setFont(QFont("Courier New", 11))
        refresh_btn.setStyleSheet(f"""
            QPushButton {{ background: transparent; color: {_TEXT_DIM};
                           border: 1px solid {_BORDER}; border-radius: 3px; }}
            QPushButton:hover {{ color: {_PRI}; border: 1px solid {_PRI}; }}
        """)
        refresh_btn.clicked.connect(self.refresh)
        hdr.addWidget(refresh_btn)

        close_btn = QPushButton("✕")
        close_btn.setFixedSize(26, 26)
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.setFont(QFont("Courier New", 10))
        close_btn.setStyleSheet(f"""
            QPushButton {{ background: transparent; color: {_TEXT_DIM};
                           border: 1px solid {_BORDER}; border-radius: 3px; }}
            QPushButton:hover {{ color: {_RED}; border: 1px solid {_RED}; }}
        """)
        close_btn.clicked.connect(self._close)
        hdr.addWidget(close_btn)
        root.addLayout(hdr)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"color: {_BORDER};")
        root.addWidget(sep)

        self._count_lbl = QLabel("")
        self._count_lbl.setFont(QFont("Courier New", 7))
        self._count_lbl.setStyleSheet(f"color: {_TEXT_DIM}; background: transparent;")
        root.addWidget(self._count_lbl)

        # ── Scrollable list ───────────────────────────────────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet(f"""
            QScrollArea {{ background: transparent; border: none; }}
            QScrollBar:vertical {{
                background: {_PANEL}; width: 6px; border-radius: 3px;
            }}
            QScrollBar::handle:vertical {{
                background: {_PRI_DIM}; border-radius: 3px; min-height: 20px;
            }}
        """)
        root.addWidget(scroll, stretch=1)

        self._list_widget = QWidget()
        self._list_widget.setStyleSheet("background: transparent;")
        self._list_layout = QVBoxLayout(self._list_widget)
        self._list_layout.setContentsMargins(0, 0, 0, 0)
        self._list_layout.setSpacing(4)
        self._list_layout.addStretch()
        scroll.setWidget(self._list_widget)

        # ── Footer ────────────────────────────────────────────────────────
        sep2 = QFrame()
        sep2.setFrameShape(QFrame.Shape.HLine)
        sep2.setStyleSheet(f"color: {_BORDER};")
        root.addWidget(sep2)

        footer = QHBoxLayout()
        hint = QLabel('Say "JARVIS, search memory for…" or "forget my preference for…"')
        hint.setFont(QFont("Courier New", 7))
        hint.setStyleSheet(f"color: {_TEXT_DIM}; background: transparent;")
        footer.addWidget(hint)
        footer.addStretch()
        root.addLayout(footer)

        self._summaries: list = []
        self.refresh()
        self._position_overlay()

    # ── Positioning ───────────────────────────────────────────────────────

    def _position_overlay(self):
        try:
            screen = QApplication.primaryScreen()
            geo    = screen.availableGeometry()
            self.setFixedHeight(min(600, geo.height() - 80))
            self.move(geo.x() + geo.width() - self.width() - 20,
                      geo.y() + (geo.height() - self.height()) // 2)
        except Exception:
            pass

    # ── Data loading ──────────────────────────────────────────────────────

    def refresh(self):
        # Clear existing rows (except final stretch item)
        while self._list_layout.count() > 1:
            item = self._list_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        memory    = self._load_memory()
        summaries = self._load_summaries()
        self._summaries = summaries

        rows_added = 0
        ORDERED_CATS = ["identity", "preferences", "projects", "relationships",
                        "wishes", "habits", "goals", "notes"]

        for cat in ORDERED_CATS:
            items = memory.get(cat, {})
            if not isinstance(items, dict):
                continue
            for key, entry in sorted(items.items()):
                if not isinstance(entry, dict):
                    continue
                val     = str(entry.get("value", ""))
                updated = entry.get("updated", "")
                row = _MemoryRow(cat, key, val, updated)
                row.delete_requested.connect(self._on_delete_fact)
                self._list_layout.insertWidget(self._list_layout.count() - 1, row)
                rows_added += 1

        # Add conversation summaries
        for i, s in enumerate(reversed(summaries)):  # most recent first
            idx = len(summaries) - 1 - i
            row = _SummaryRow(idx, s.get("date", ""), s.get("summary", ""), s.get("topics", []))
            row.delete_requested.connect(self._on_delete_summary)
            self._list_layout.insertWidget(self._list_layout.count() - 1, row)
            rows_added += 1

        self._count_lbl.setText(
            f"{rows_added} entries  ·  "
            f"{rows_added - len(summaries)} facts  ·  "
            f"{len(summaries)} conversation summaries"
        )

    @staticmethod
    def _load_memory() -> dict:
        try:
            if MEMORY_PATH.exists():
                return json.loads(MEMORY_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
        return {}

    @staticmethod
    def _load_summaries() -> list:
        try:
            if SUMMARIES_PATH.exists():
                return json.loads(SUMMARIES_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
        return []

    # ── Delete handlers ───────────────────────────────────────────────────

    def _on_delete_fact(self, category: str, key: str):
        try:
            data = self._load_memory()
            cat  = data.get(category, {})
            if key in cat:
                del cat[key]
                data[category] = cat
                MEMORY_PATH.write_text(
                    json.dumps(data, indent=2, ensure_ascii=False),
                    encoding="utf-8"
                )
                print(f"[MemoryEditor] 🗑️  Deleted {category}/{key}")
        except Exception as e:
            print(f"[MemoryEditor] ⚠️ Delete error: {e}")
        self.refresh()

    def _on_delete_summary(self, idx: int):
        try:
            summaries = self._load_summaries()
            if 0 <= idx < len(summaries):
                del summaries[idx]
                SUMMARIES_PATH.write_text(
                    json.dumps(summaries, indent=2, ensure_ascii=False),
                    encoding="utf-8"
                )
                print(f"[MemoryEditor] 🗑️  Deleted summary #{idx}")
        except Exception as e:
            print(f"[MemoryEditor] ⚠️ Delete summary error: {e}")
        self.refresh()

    def _close(self):
        self.hide()
        self.closed.emit()


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = QApplication(sys.argv)
    w   = MemoryEditorOverlay()
    w.show()
    sys.exit(app.exec())