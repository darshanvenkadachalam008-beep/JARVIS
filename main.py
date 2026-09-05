"""
JARVIS — Mark XXXIX-OR  |  Phase 1 Advanced Upgrade
=====================================================
Upgrades over base build:
  • Always-on background service with system-tray icon
  • Software wake-word detection ("Hey Jarvis" / "Jarvis, wake up")
  • Continuous mic monitoring — JARVIS listens even when window is minimised
  • Proactive daily/evening briefing scheduler (like the video)
  • Business Intelligence tools: app_stats, content_metrics, email_triage, delegate_task
  • Enhanced JARVIS persona — proactive, chief-of-staff energy
  • Session resumption + auto-reconnect hardened
  • Graceful shutdown / tray-quit
"""

import asyncio
import threading
import json
import sys
import os
import re
import time
import traceback
from datetime import datetime, timedelta
from pathlib import Path

# ── Third-party ───────────────────────────────────────────────────────────────
import sounddevice as sd
import numpy as np
from google import genai
from google.genai import types

# ── Local modules ─────────────────────────────────────────────────────────────
from ui import JarvisUI
from core.wake_word import WakeWordEngine
from core.vad_filter import MicEnergyFilter, DEFAULT_NOISE_FLOOR_RMS
from memory.memory_manager import (
    load_memory, update_memory, format_memory_for_prompt,
    should_extract_memory, extract_memory,
    summarise_conversation, search_memory, format_search_results,
)
from actions.file_processor    import file_processor
from actions.flight_finder     import flight_finder
from actions.open_app          import open_app
from actions.weather_report    import weather_action
from actions.send_message      import send_message
from actions.reminder          import reminder
from actions.computer_settings import computer_settings
from actions.screen_processor  import screen_process
from actions.youtube_video     import youtube_video
from actions.desktop           import desktop_control
from actions.browser_control   import browser_control
from actions.file_controller   import file_controller
from actions.code_helper       import code_helper
from actions.dev_agent         import dev_agent
from actions.web_search        import web_search as web_search_action
from actions.computer_control  import computer_control
from actions.game_updater      import game_updater

# ── Phase 4: State machine & proactive intelligence ───────────────────────────
from core.states                import JarvisState, StateManager
from core.proactive_intelligence import ProactiveIntelligence
from mobile_server              import MobileServer


# ═══════════════════════════════════════════════════════════════════════════════
#  PATHS & CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

def get_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent


BASE_DIR            = get_base_dir()
API_CONFIG_PATH     = BASE_DIR / "config" / "api_keys.json"
PROMPT_PATH         = BASE_DIR / "core" / "prompt.txt"
BI_DATA_PATH        = BASE_DIR / "memory" / "bi_data.json"   # business intelligence cache
BRIEFING_STATE_PATH = BASE_DIR / "memory" / "briefing_state.json"

LIVE_MODEL          = "models/gemini-2.5-flash-native-audio-preview-12-2025"
CHANNELS            = 1
SEND_SAMPLE_RATE    = 16000
RECEIVE_SAMPLE_RATE = 24000
CHUNK_SIZE          = 1024

# Wake-word phrases (all lowercase).  Detected via cheap energy + text match.
WAKE_WORDS = [
    "hey jarvis", "jarvis", "hey j.a.r.v.i.s", "j.a.r.v.i.s",
    "wake up jarvis", "jarvis wake up", "daddy's home",
]

# How long (seconds) to keep JARVIS "awake" after the last interaction
#  before returning to silent background mode.
ACTIVE_TIMEOUT_SECS = 30


# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _get_api_key() -> str:
    with open(API_CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)["gemini_api_key"]


DEFAULT_WAKE_SENSITIVITY = 0.7  # higher = less noise false-triggers; tune down if wake word misses


def _get_wake_sensitivity() -> float:
    """Load saved wake-word sensitivity from config/api_keys.json.
    Falls back to DEFAULT_WAKE_SENSITIVITY if unset or unreadable.
    Enforces a minimum of 0.65 to prevent false wake-word triggers."""
    MIN_THRESHOLD = 0.65   # never go below this — prevents ambient noise wakes
    try:
        with open(API_CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        val = float(data.get("wake_sensitivity", DEFAULT_WAKE_SENSITIVITY))
        return max(val, MIN_THRESHOLD)
    except Exception:
        return DEFAULT_WAKE_SENSITIVITY


def _save_wake_sensitivity(value: float) -> None:
    """Persist wake-word sensitivity so the slider position survives restarts."""
    value = max(0.05, min(0.95, float(value)))
    data: dict = {}
    try:
        with open(API_CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        pass
    data["wake_sensitivity"] = value
    API_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(API_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _get_gesture_control_enabled() -> bool:
    """Webcam gesture control is opt-in (off by default) since it requires
    camera access — read the saved toggle from config/api_keys.json,
    default False if unset or unreadable."""
    try:
        with open(API_CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return bool(data.get("gesture_control_enabled", False))
    except Exception:
        return False


def _save_gesture_control_enabled(value: bool) -> None:
    data: dict = {}
    try:
        with open(API_CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        pass
    data["gesture_control_enabled"] = bool(value)
    API_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(API_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _get_noise_floor_rms() -> float:
    """Load saved mic noise floor threshold from config/api_keys.json."""
    try:
        with open(API_CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return float(data.get("mic_noise_floor_rms", DEFAULT_NOISE_FLOOR_RMS))
    except Exception:
        return DEFAULT_NOISE_FLOOR_RMS


def _save_noise_floor_rms(value: float) -> None:
    """Persist mic noise floor threshold so it survives restarts."""
    value = max(10.0, min(5000.0, float(value)))
    data: dict = {}
    try:
        with open(API_CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        pass
    data["mic_noise_floor_rms"] = value
    API_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(API_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _load_system_prompt() -> str:
    try:
        return PROMPT_PATH.read_text(encoding="utf-8")
    except Exception:
        return ""


def _load_bi_data() -> dict:
    """Load cached business intelligence data (app stats, email queue, etc.)."""
    try:
        if BI_DATA_PATH.exists():
            return json.loads(BI_DATA_PATH.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _save_bi_data(data: dict) -> None:
    BI_DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
    BI_DATA_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _load_briefing_state() -> dict:
    try:
        if BRIEFING_STATE_PATH.exists():
            return json.loads(BRIEFING_STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _save_briefing_state(state: dict) -> None:
    BRIEFING_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    BRIEFING_STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")


# ═══════════════════════════════════════════════════════════════════════════════
#  MEMORY
# ═══════════════════════════════════════════════════════════════════════════════

_last_memory_input = ""
_exchange_count    = 0   # trigger summarisation every N meaningful exchanges
_SUMMARISE_EVERY   = 5   # summarise after every 5 exchanges


def _update_memory_async(user_text: str, jarvis_text: str) -> None:
    global _last_memory_input, _exchange_count
    user_text   = (user_text   or "").strip()
    jarvis_text = (jarvis_text or "").strip()
    if len(user_text) < 5 or user_text == _last_memory_input:
        return
    _last_memory_input = user_text
    _exchange_count   += 1
    try:
        api_key = _get_api_key()

        # ── Structured fact extraction (OpenRouter, existing) ─────────────
        if should_extract_memory(user_text, jarvis_text, api_key):
            data = extract_memory(user_text, jarvis_text, api_key)
            if data:
                update_memory(data)
                print(f"[Memory] ✅ {list(data.keys())}")

        # ── Conversation summarisation (Gemini Flash, Phase 3) ────────────
        if _exchange_count % _SUMMARISE_EVERY == 0 and len(user_text) > 30:
            summarise_conversation(user_text, jarvis_text, api_key)

    except Exception as e:
        if "429" not in str(e):
            print(f"[Memory] ⚠️ {e}")



#  PROACTIVE BRIEFING SCHEDULER
# ═══════════════════════════════════════════════════════════════════════════════

class BriefingScheduler:
    """
    Fires proactive briefings at configured times.
    Default: morning (08:00) and evening (20:00) — mirrors the video demo.
    Times are stored in bi_data.json so the user can adjust via JARVIS voice.
    Wired into ProactiveBridge with NORMAL priority and fallback to on_briefing callback.
    """

    DEFAULT_TIMES = [
        {"hour": 8,  "minute": 0,  "label": "morning"},
        {"hour": 20, "minute": 0,  "label": "evening"},
    ]

    def __init__(self, on_briefing=None, bridge=None):
        self._on_briefing = on_briefing
        self._bridge      = bridge
        self._thread      = None
        self._running     = False

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._run, daemon=True, name="BriefingScheduler")
        self._thread.start()
        print("[Briefing] [Scheduler] Thread started")

    def stop(self):
        self._running = False

    def _get_times(self) -> list:
        bi = _load_bi_data()
        return bi.get("briefing_times", self.DEFAULT_TIMES)

    def _run(self):
        while self._running:
            try:
                self._check()
            except Exception as e:
                print(f"[Briefing] [!] Check error: {e}")
            for _ in range(30):
                if not self._running:
                    break
                time.sleep(1)

    def _check(self):
        now    = datetime.now()
        state  = _load_briefing_state()
        today  = now.strftime("%Y-%m-%d")

        for slot in self._get_times():
            key = f"{today}_{slot['label']}"
            if state.get(key):
                continue  # already fired today
            target = now.replace(
                hour=slot["hour"], minute=slot["minute"],
                second=0, microsecond=0
            )
            if abs((now - target).total_seconds()) < 90:  # within 90s window
                state[key] = True
                _save_briefing_state(state)
                print(f"[Briefing] [!] Firing {slot['label']} briefing")
                brief_text = (
                    f"[AUTO BRIEFING] It is now {slot['label']} briefing time. "
                    f"Deliver the {slot['label']} briefing proactively using the daily_briefing tool."
                )
                if self._bridge:
                    try:
                        from core.proactive_bridge import ProactiveEvent, ProactivePriority
                        self._bridge.dispatch(ProactiveEvent(
                            category="briefing",
                            title=f"{slot['label'].title()} Briefing",
                            message=brief_text,
                            priority=ProactivePriority.NORMAL,
                            ttl_seconds=1800.0,
                            dedup_key=f"briefing:{key}",
                            data={"label": slot["label"], "time": now.strftime("%H:%M")},
                            channels={"voice", "ui", "mobile"},
                        ))
                    except Exception as e:
                        print(f"[Briefing] [!] Bridge dispatch error: {e}")
                        if self._on_briefing:
                            self._on_briefing(slot["label"])
                elif self._on_briefing:
                    self._on_briefing(slot["label"])


# ═══════════════════════════════════════════════════════════════════════════════
#  TOOL DECLARATIONS
# ═══════════════════════════════════════════════════════════════════════════════

TOOL_DECLARATIONS = [
    # ── Existing tools (unchanged) ──────────────────────────────────────────
    {
        "name": "open_app",
        "description": (
            "Opens any application on the computer. "
            "Use this whenever the user asks to open, launch, or start any app, "
            "website, or program. Always call this tool — never just say you opened it."
        ),
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "app_name": {
                    "type": "STRING",
                    "description": "Exact name of the application (e.g. 'WhatsApp', 'Chrome', 'Spotify')"
                }
            },
            "required": ["app_name"]
        }
    },
    {
        "name": "web_search",
        "description": "Searches the web for any information.",
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "query":  {"type": "STRING", "description": "Search query"},
                "mode":   {"type": "STRING", "description": "search (default) or compare"},
                "items":  {"type": "ARRAY", "items": {"type": "STRING"}, "description": "Items to compare"},
                "aspect": {"type": "STRING", "description": "price | specs | reviews"}
            },
            "required": ["query"]
        }
    },
    {
        "name": "weather_report",
        "description": "Gives the weather report to user.",
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "city": {"type": "STRING", "description": "City name"}
            },
            "required": ["city"]
        }
    },
    {
        "name": "send_message",
        "description": "Sends a text message via WhatsApp, Telegram, or other messaging platform.",
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "receiver":     {"type": "STRING", "description": "Recipient contact name"},
                "message_text": {"type": "STRING", "description": "The message to send"},
                "platform":     {"type": "STRING", "description": "Platform: WhatsApp, Telegram, etc."}
            },
            "required": ["receiver", "message_text", "platform"]
        }
    },
    {
        "name": "reminder",
        "description": "Sets a timed reminder using Windows Task Scheduler.",
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "date":    {"type": "STRING", "description": "Date in YYYY-MM-DD format"},
                "time":    {"type": "STRING", "description": "Time in HH:MM format (24h)"},
                "message": {"type": "STRING", "description": "Reminder message text"}
            },
            "required": ["date", "time", "message"]
        }
    },
    {
        "name": "youtube_video",
        "description": "Controls YouTube: playing, summarizing, trending.",
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "action": {"type": "STRING", "description": "play | summarize | get_info | trending"},
                "query":  {"type": "STRING", "description": "Search query for play action"},
                "save":   {"type": "BOOLEAN", "description": "Save summary to file"},
                "region": {"type": "STRING", "description": "Country code e.g. US, TR"},
                "url":    {"type": "STRING", "description": "Video URL for get_info"},
            },
            "required": []
        }
    },
    {
        "name": "screen_process",
        "description": (
            "Phase 6 — Vision & Screen Awareness. "
            "CRITICAL MODE SELECTION RULES — always pick the most specific mode:\n"
            "  analyze_tabs — MUST use this when user asks about browser tabs, open tabs, "
            "what is in the browser, what websites are open, tab titles, or anything "
            "about what the browser contains. NOT analyze — always analyze_tabs for tabs.\n"
            "  analyze — general one-shot question about what is on screen or camera;\n"
            "  game_start — activate smart real-time game analysis (only narrates when screen changes);\n"
            "  game_stop — deactivate game mode; use when user says stop, exit, or deactivate game mode;\n"
            "  game_speed — change game mode interval, pass speed=fast(2s)|normal(4s)|slow(8s);\n"
            "  read_document — read and summarise a document, PDF, or article on screen;\n"
            "  auto_fill — detect form fields on screen for filling;\n"
            "  save_screen — save a screenshot to disk when user says save, capture, or screenshot.\n"
            "For angle='both' (fusion mode): use mode=analyze + angle=both when the user wants "
            "JARVIS to look at the screen AND the webcam together — e.g. 'do I look like I need "
            "help with this', 'check on me', or anything implying JARVIS should notice both what's "
            "on screen and the user's reaction to it.\n"
            "After calling this tool stay SILENT — vision module speaks directly. Never repeat its output."
        ),
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "mode":  {"type": "STRING", "description": "analyze | analyze_tabs | game_start | game_stop | game_speed | read_document | auto_fill | save_screen"},
                "speed": {"type": "STRING", "description": "fast | normal | slow (only for game_speed mode)"},
                "angle": {"type": "STRING", "description": "screen (default) | camera | both (fusion — screen + camera correlated together)"},
                "text":  {"type": "STRING", "description": "Question or instruction (for analyze mode)"}
            },
            "required": []
        }
    },
    {
        "name": "computer_settings",
        "description": (
            "Controls the computer: volume, brightness, window management, keyboard shortcuts, "
            "typing, closing apps, fullscreen, dark mode, WiFi, restart, shutdown, "
            "scrolling, tab management, zoom, screenshots, lock screen."
        ),
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "action":      {"type": "STRING", "description": "The action to perform"},
                "description": {"type": "STRING", "description": "Natural language description of what to do"},
                "value":       {"type": "STRING", "description": "Optional value: volume level, text to type, etc."}
            },
            "required": []
        }
    },
    {
        "name": "browser_control",
        "description": "Controls the web browser: opening websites, clicking, filling forms, scrolling.",
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "action":      {"type": "STRING", "description": "go_to | search | click | type | scroll | fill_form | smart_click | smart_type | get_text | press | close"},
                "url":         {"type": "STRING", "description": "URL for go_to action"},
                "query":       {"type": "STRING", "description": "Search query"},
                "selector":    {"type": "STRING", "description": "CSS selector"},
                "text":        {"type": "STRING", "description": "Text to click or type"},
                "description": {"type": "STRING", "description": "Element description for smart_click/smart_type"},
                "direction":   {"type": "STRING", "description": "up or down for scroll"},
                "key":         {"type": "STRING", "description": "Key name for press action"},
                "incognito":   {"type": "BOOLEAN", "description": "Open in private/incognito mode"},
            },
            "required": ["action"]
        }
    },
    {
        "name": "file_controller",
        "description": "Manages files and folders: list, create, delete, move, copy, rename, read, write, find, disk usage.",
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "action":      {"type": "STRING", "description": "list | create_file | create_folder | delete | move | copy | rename | read | write | find | largest | disk_usage | organize_desktop | info"},
                "path":        {"type": "STRING", "description": "File/folder path"},
                "destination": {"type": "STRING", "description": "Destination for move/copy"},
                "new_name":    {"type": "STRING", "description": "New name for rename"},
                "content":     {"type": "STRING", "description": "Content for create_file/write"},
                "name":        {"type": "STRING", "description": "File name to search for"},
                "extension":   {"type": "STRING", "description": "File extension e.g. .pdf"},
                "count":       {"type": "INTEGER", "description": "Number of results for largest"},
            },
            "required": ["action"]
        }
    },
    {
        "name": "desktop_control",
        "description": "Controls the desktop: wallpaper, organize, clean, list, stats.",
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "action": {"type": "STRING", "description": "wallpaper | wallpaper_url | organize | clean | list | stats | task"},
                "path":   {"type": "STRING", "description": "Image path for wallpaper"},
                "url":    {"type": "STRING", "description": "Image URL for wallpaper_url"},
                "mode":   {"type": "STRING", "description": "by_type or by_date for organize"},
                "task":   {"type": "STRING", "description": "Natural language desktop task"},
            },
            "required": ["action"]
        }
    },
    {
        "name": "code_helper",
        "description": (
            "Writes, edits, explains, runs, or builds code files. "
            "Do NOT use this if the user names Tom or asks for a 'script'/'app'/'project' "
            "in a way that matches Tom's domain — use persona_task instead."
        ),
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "action":      {"type": "STRING", "description": "write | edit | explain | run | build | auto"},
                "description": {"type": "STRING", "description": "What the code should do"},
                "language":    {"type": "STRING", "description": "Programming language"},
                "output_path": {"type": "STRING", "description": "Where to save the file"},
                "file_path":   {"type": "STRING", "description": "Path to existing file"},
                "code":        {"type": "STRING", "description": "Raw code string for explain"},
                "args":        {"type": "STRING", "description": "CLI arguments for run/build"},
                "timeout":     {"type": "INTEGER", "description": "Execution timeout in seconds"},
            },
            "required": ["action"]
        }
    },
    {
        "name": "dev_agent",
        "description": (
            "Builds complete multi-file projects from scratch: plans, writes files, installs deps, opens VSCode. "
            "Do NOT use this if the user names Tom — use persona_task instead."
        ),
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "description":  {"type": "STRING", "description": "What the project should do"},
                "language":     {"type": "STRING", "description": "Programming language"},
                "project_name": {"type": "STRING", "description": "Optional project folder name"},
                "timeout":      {"type": "INTEGER", "description": "Run timeout in seconds"},
            },
            "required": ["description"]
        }
    },
    {
        "name": "agent_task",
        "description": (
            "Executes complex multi-step tasks requiring multiple different tools. "
            "Examples: 'research X and save to file', 'find and organize files'. "
            "DO NOT use for single commands."
        ),
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "goal":     {"type": "STRING", "description": "Complete description of what to accomplish"},
                "priority": {"type": "STRING", "description": "low | normal | high"}
            },
            "required": ["goal"]
        }
    },
    {
        "name": "persona_task",
        "description": (
            "Routes a task to one of the four named JARVIS sub-agents: "
            "Tom (coding/development), Scout (web research), Ada (social media content "
            "drafts), or Nova (analytics: YouTube/GitHub/Instagram/Google Analytics/Meta). "
            "Use this whenever the user explicitly asks for Tom, Scout, Ada, or Nova, "
            "or describes a task matching one of those domains (e.g. 'have Scout look "
            "into X', 'ask Ada for an Instagram caption', 'get Nova's GitHub stats'). "
            "If the user doesn't name an agent, omit agent_name and it will be auto-detected."
        ),
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "task":       {"type": "STRING", "description": "Complete description of what the agent should do"},
                "agent_name": {"type": "STRING", "description": "Tom | Scout | Ada | Nova (optional — auto-detected if omitted)"},
            },
            "required": ["task"]
        }
    },
    {
        "name": "computer_control",
        "description": "Direct computer control: type, click, hotkeys, scroll, screenshots, find elements on screen.",
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "action":      {"type": "STRING", "description": "type | smart_type | click | double_click | right_click | hotkey | press | scroll | move | copy | paste | screenshot | wait | clear_field | focus_window | screen_find | screen_click | random_data | user_data"},
                "text":        {"type": "STRING", "description": "Text to type or paste"},
                "x":           {"type": "INTEGER", "description": "X coordinate"},
                "y":           {"type": "INTEGER", "description": "Y coordinate"},
                "keys":        {"type": "STRING", "description": "Key combination e.g. 'ctrl+c'"},
                "key":         {"type": "STRING", "description": "Single key e.g. 'enter'"},
                "direction":   {"type": "STRING", "description": "up | down | left | right"},
                "amount":      {"type": "INTEGER", "description": "Scroll amount"},
                "seconds":     {"type": "NUMBER",  "description": "Seconds to wait"},
                "title":       {"type": "STRING",  "description": "Window title for focus_window"},
                "description": {"type": "STRING",  "description": "Element description for screen_find/screen_click"},
                "type":        {"type": "STRING",  "description": "Data type for random_data"},
                "field":       {"type": "STRING",  "description": "Field for user_data: name|email|city"},
                "clear_first": {"type": "BOOLEAN", "description": "Clear field before typing"},
                "path":        {"type": "STRING",  "description": "Save path for screenshot"},
            },
            "required": ["action"]
        }
    },
    {
        "name": "game_updater",
        "description": (
            "THE ONLY tool for ANY Steam or Epic Games request. "
            "Use for: installing, downloading, updating games, listing installed games. "
            "ALWAYS call directly. NEVER use agent_task or browser_control for Steam/Epic."
        ),
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "action":    {"type": "STRING",  "description": "update | install | list | download_status | schedule | cancel_schedule | schedule_status"},
                "platform":  {"type": "STRING",  "description": "steam | epic | both"},
                "game_name": {"type": "STRING",  "description": "Game name"},
                "app_id":    {"type": "STRING",  "description": "Steam AppID for install"},
                "hour":      {"type": "INTEGER", "description": "Hour for scheduled update 0-23"},
                "minute":    {"type": "INTEGER", "description": "Minute for scheduled update 0-59"},
                "shutdown_when_done": {"type": "BOOLEAN", "description": "Shut down PC when download finishes"},
            },
            "required": []
        }
    },
    {
        "name": "flight_finder",
        "description": "Searches Google Flights and speaks the best options.",
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "origin":      {"type": "STRING",  "description": "Departure city or airport code"},
                "destination": {"type": "STRING",  "description": "Arrival city or airport code"},
                "date":        {"type": "STRING",  "description": "Departure date"},
                "return_date": {"type": "STRING",  "description": "Return date for round trips"},
                "passengers":  {"type": "INTEGER", "description": "Number of passengers"},
                "cabin":       {"type": "STRING",  "description": "economy | premium | business | first"},
                "save":        {"type": "BOOLEAN", "description": "Save results to file"},
            },
            "required": ["origin", "destination", "date"]
        }
    },
    {
        "name": "file_processor",
        "description": (
            "Processes any file the user has uploaded. "
            "Supports images, PDFs, Word docs, CSV/Excel, JSON, code, audio, video, archives. "
            "ALWAYS call when a file has been uploaded and the user gives a command about it."
        ),
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "action":    {"type": "STRING", "description": "The action: summarize | extract_text | analyze | fix | translate | ocr | resize | convert | run | etc."},
                "file_path": {"type": "STRING", "description": "Path to the file"},
                "output":    {"type": "STRING", "description": "Optional output format or path"},
                "prompt":    {"type": "STRING", "description": "Custom instruction for the action"},
                "language":  {"type": "STRING", "description": "Target language for translation"},
            },
            "required": ["action"]
        }
    },

    # ── NEW Phase 1 tools ────────────────────────────────────────────────────

    {
        "name": "app_stats",
        "description": (
            "Retrieves your app's performance metrics: downloads, revenue, ratings, "
            "crash reports, and user retention. Call when the user asks 'how is the app doing', "
            "'pull up our app stats', 'what are our numbers', or any business metric question. "
            "Returns a formatted summary you can speak directly."
        ),
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "period":  {"type": "STRING", "description": "today | 7days | 30days | custom (default: 7days)"},
                "metric":  {"type": "STRING", "description": "all | downloads | revenue | ratings | crashes | retention (default: all)"},
                "store":   {"type": "STRING", "description": "appstore | playstore | both (default: both)"},
                "from_date": {"type": "STRING", "description": "Start date YYYY-MM-DD for custom period"},
                "to_date":   {"type": "STRING", "description": "End date YYYY-MM-DD for custom period"},
            },
            "required": []
        }
    },
    {
        "name": "content_metrics",
        "description": (
            "Pulls organic content performance: video views, engagement, follower growth, "
            "best/worst performing content. Call when user asks about content, videos, "
            "social media performance, 'how did the content do', channel growth, etc."
        ),
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "platform": {"type": "STRING", "description": "youtube | tiktok | instagram | twitter | all (default: all)"},
                "period":   {"type": "STRING", "description": "today | 7days | 30days (default: 7days)"},
                "detail":   {"type": "STRING", "description": "summary | top_posts | worst_posts | trends (default: summary)"},
            },
            "required": []
        }
    },
    {
        "name": "ads_performance",
        "description": (
            "Reports paid advertising performance: spend, ROAS, CTR, best/worst creatives, "
            "recommendations. Call when user asks about ads, spending, ROAS, creatives, "
            "ad performance, 'how are the ads doing'."
        ),
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "platform": {"type": "STRING", "description": "meta | google | tiktok | all (default: all)"},
                "period":   {"type": "STRING", "description": "today | 7days | 30days (default: 7days)"},
                "detail":   {"type": "STRING", "description": "summary | by_creative | by_audience | recommendations (default: summary)"},
            },
            "required": []
        }
    },
    {
        "name": "email_triage",
        "description": (
            "Manages and triages the customer email/support inbox. "
            "Can: list unread emails with AI-generated summaries and priority scores, "
            "auto-draft replies for common issues, flag emails needing personal attention, "
            "track feature requests, and mark emails as handled. "
            "Call when user asks about emails, inbox, customer issues, support tickets."
        ),
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "action":     {"type": "STRING", "description": "list | auto_reply | flag | summarize | feature_requests | mark_done (default: list)"},
                "email_id":   {"type": "STRING", "description": "Specific email ID for reply/flag/mark_done"},
                "reply_text": {"type": "STRING", "description": "Custom reply text to send"},
                "category":   {"type": "STRING", "description": "Filter: all | needs_attention | auto_resolved | feature_request (default: all)"},
                "limit":      {"type": "INTEGER", "description": "Max emails to process (default: 20)"},
            },
            "required": []
        }
    },
    {
        "name": "delegate_task",
        "description": (
            "Delegates a task to a named sub-agent (like 'Tom the developer agent', "
            "'Scout the research agent', 'Ada the content agent'). "
            "Use when the user wants to hand off work to a specific agent, "
            "check status of delegated tasks, or review completed work. "
            "This is how JARVIS manages a team of specialist AI agents."
        ),
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "agent":       {"type": "STRING", "description": "Agent name: tom | scout | ada | nova | or any custom name"},
                "task":        {"type": "STRING", "description": "Full description of the task to delegate"},
                "priority":    {"type": "STRING", "description": "low | normal | high | urgent (default: normal)"},
                "action":      {"type": "STRING", "description": "assign | status | review | approve | reject | list_all (default: assign)"},
                "task_id":     {"type": "STRING", "description": "Task ID for status/review/approve/reject actions"},
                "feedback":    {"type": "STRING", "description": "Feedback text for reject action"},
            },
            "required": []
        }
    },
    {
        "name": "daily_briefing",
        "description": (
            "Generates and delivers a comprehensive daily briefing report: "
            "app stats, content performance, ad metrics, email summary, "
            "pending tasks, calendar overview, and AI-generated recommendations. "
            "Call when user says 'briefing', 'morning report', 'evening report', "
            "'catch me up', 'what did I miss', or arrives home."
        ),
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "type":    {"type": "STRING", "description": "morning | evening | full | quick (default: full)"},
                "period":  {"type": "STRING", "description": "today | 7days (default: 7days for evening, today for morning)"},
                "include": {"type": "STRING", "description": "Comma-separated sections: apps,content,ads,emails,tasks,calendar,recommendations"},
            },
            "required": []
        }
    },
    {
        "name": "set_briefing_schedule",
        "description": (
            "Configures when JARVIS automatically delivers proactive briefings. "
            "Call when user says 'brief me at 9am', 'send evening report at 8pm', "
            "'change my briefing time', 'stop morning briefings', etc."
        ),
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "slot":    {"type": "STRING", "description": "morning | evening | custom"},
                "hour":    {"type": "INTEGER", "description": "Hour 0-23"},
                "minute":  {"type": "INTEGER", "description": "Minute 0-59 (default: 0)"},
                "enabled": {"type": "BOOLEAN", "description": "Enable or disable this briefing slot"},
            },
            "required": ["slot"]
        }
    },
    {
        "name": "save_memory",
        "description": (
            "Saves a piece of information to JARVIS long-term memory for future recall. "
            "Categories: identity | preferences | projects | relationships | "
            "wishes | habits | goals | notes"
        ),
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "category": {"type": "STRING", "description": "Category: identity | preferences | projects | relationships | wishes | habits | goals | notes"},
                "key":      {"type": "STRING", "description": "Short identifying key (snake_case)"},
                "value":    {"type": "STRING", "description": "Value to remember"},
            },
            "required": ["key", "value"]
        }
    },
    {
        "name": "search_memory",
        "description": (
            "Searches JARVIS long-term memory for facts and past conversation summaries. "
            "Call when user asks 'what do you remember about X', 'do you remember when I told you about Y', "
            "'last time I mentioned Z', 'have I ever asked about W', 'search your memory for…'. "
            "Returns matching facts and relevant conversation summaries."
        ),
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "query": {"type": "STRING", "description": "Search term or topic to look up in memory"},
            },
            "required": ["query"]
        }
    },
    {
        "name": "open_memory_editor",
        "description": (
            "Opens the JARVIS Memory Bank overlay so the user can view all stored facts "
            "and conversation summaries, and delete any entry. "
            "Call when user says 'open memory editor', 'show me your memory', "
            "'what have you stored about me', 'manage your memory', 'show memory bank'."
        ),
        "parameters": {"type": "OBJECT", "properties": {}, "required": []}
    },
    {
        "name": "shutdown_jarvis",
        "description": "Shuts down the JARVIS assistant. Only call if user clearly intends to stop the session.",
        "parameters": {"type": "OBJECT", "properties": {}, "required": []}
    },
    # ── Phase 4: Proactive Intelligence tools ─────────────────────────────────
    {
        "name": "get_morning_briefing",
        "description": (
            "Delivers the personalised morning briefing from memory: goals, tasks, reminders, "
            "and relationship context. Call only after the user confirms they want the briefing."
        ),
        "parameters": {"type": "OBJECT", "properties": {}, "required": []}
    },
    {
        "name": "get_news_digest",
        "description": (
            "Searches the web for personalised news based on the user's stored interests and "
            "preferences. Only call when the user explicitly requests news or a digest."
        ),
        "parameters": {"type": "OBJECT", "properties": {}, "required": []}
    },
    {
        "name": "sleep_jarvis",
        "description": (
            "Puts JARVIS into sleeping/background mode. Microphone stops streaming to Gemini. "
            "JARVIS will only wake again when the wake word is detected. "
            "Call when user says goodbye, goodnight, go to sleep, stand by, etc."
        ),
        "parameters": {"type": "OBJECT", "properties": {}, "required": []}
    },
    {
        "name": "read_clipboard",
        "description": (
            "Reads the current text content of the clipboard. "
            "Call when the user says 'summarise this', 'translate this', "
            "'fix the grammar', 'explain this code', 'reply to this', "
            "'what did I copy', or any request implying they want to act on something "
            "they just copied. Returns the clipboard text for you to process."
        ),
        "parameters": {"type": "OBJECT", "properties": {}, "required": []}
    },
    {
        "name": "get_active_window",
        "description": (
            "Returns the title of the currently focused application window. "
            "Call when context requires knowing what the user is working on, "
            "or when you want to give context-aware help without the user explaining "
            "which app they mean."
        ),
        "parameters": {"type": "OBJECT", "properties": {}, "required": []}
    },
    {
        "name": "remote_control",
        "description": (
            "Controls the PC remotely from mobile or by voice — runs any computer "
            "action: volume, brightness, lock, shutdown, restart, screenshot, open app, "
            "close window, type text, click, scroll, keyboard shortcuts, play/pause media. "
            "Use when the user wants to control their PC/laptop from their phone, "
            "or when a physical action on the computer is needed. "
            "Examples: 'lock my laptop from phone', 'turn up volume', 'take a screenshot', "
            "'open Chrome', 'close this window', 'press Ctrl+S'."
        ),
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "action": {
                    "type": "STRING",
                    "description": (
                        "The action to perform. Examples: volume_up, volume_down, volume_mute, "
                        "brightness_up, brightness_down, lock, shutdown, restart, screenshot, "
                        "open_app, close_window, minimize, maximize, fullscreen, "
                        "type, click, scroll_up, scroll_down, hotkey, press_key, "
                        "play_pause, next_track, prev_track, media_stop"
                    )
                },
                "value": {
                    "type": "STRING",
                    "description": "Optional value for the action (e.g. app name to open, text to type, key combo)"
                }
            },
            "required": ["action"]
        }
    },
    {
        "name": "get_calendar_events",
        "description": (
            "Fetches upcoming events from Google Calendar. "
            "Call when the user asks about their schedule, meetings, appointments, "
            "or anything on their calendar today or this week. "
            "Returns a formatted list of upcoming events."
        ),
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "hours_ahead": {
                    "type": "NUMBER",
                    "description": "How many hours ahead to look (default 24, max 168 for one week)"
                }
            },
            "required": []
        }
    },
]


# ═══════════════════════════════════════════════════════════════════════════════
#  BUSINESS INTELLIGENCE TOOL HANDLERS
# ═══════════════════════════════════════════════════════════════════════════════

def _handle_app_stats(args: dict) -> str:
    """
    Returns app stats from bi_data.json.
    If no real data is present, returns a helpful message explaining how to
    connect the data source (App Store Connect API / Play Console API).
    """
    bi = _load_bi_data()
    stats = bi.get("app_stats", {})
    period = args.get("period", "7days")

    if not stats:
        return (
            "App stats database is empty, sir. "
            "To connect your live data: add your metrics to memory/bi_data.json "
            "under the 'app_stats' key, or I can set up an App Store Connect / "
            "Play Console API integration for you — just say the word."
        )

    period_data = stats.get(period, stats.get("7days", {}))
    if not period_data:
        return f"No data found for period '{period}'."

    metric = args.get("metric", "all")
    lines  = [f"App performance — {period}:"]

    if metric in ("all", "downloads") and "downloads" in period_data:
        lines.append(f"  Downloads:  {period_data['downloads']:,}")
    if metric in ("all", "revenue") and "revenue" in period_data:
        lines.append(f"  Revenue:    ${period_data['revenue']:,.2f}")
    if metric in ("all", "ratings") and "ratings" in period_data:
        lines.append(f"  Rating:     {period_data['ratings'].get('average', 'N/A')} ★  ({period_data['ratings'].get('count', 0):,} reviews)")
    if metric in ("all", "retention") and "retention" in period_data:
        lines.append(f"  Retention:  {period_data['retention']}")

    return "\n".join(lines)


def _handle_content_metrics(args: dict) -> str:
    bi = _load_bi_data()
    content = bi.get("content_metrics", {})
    period  = args.get("period", "7days")

    if not content:
        return (
            "No content metrics on file yet, sir. "
            "Connect your YouTube / TikTok / Instagram analytics by populating "
            "memory/bi_data.json under 'content_metrics', or ask me to pull "
            "public stats via web search."
        )

    data = content.get(period, content.get("7days", {}))
    lines = [f"Content performance — {period}:"]
    for platform, pdata in data.items():
        lines.append(f"\n  [{platform.upper()}]")
        if "views"    in pdata: lines.append(f"    Views:    {pdata['views']:,}")
        if "growth"   in pdata: lines.append(f"    Growth:   +{pdata['growth']} followers")
        if "top_post" in pdata: lines.append(f"    Top post: {pdata['top_post']}")
        if "worst"    in pdata: lines.append(f"    Weakest:  {pdata['worst']}")

    return "\n".join(lines) if len(lines) > 1 else "No platform data available."


def _handle_ads_performance(args: dict) -> str:
    bi   = _load_bi_data()
    ads  = bi.get("ads_performance", {})
    period = args.get("period", "7days")

    if not ads:
        return (
            "No ad performance data found, sir. "
            "Populate memory/bi_data.json under 'ads_performance' with your "
            "Meta / Google / TikTok Ads data, or I can build an integration."
        )

    data  = ads.get(period, ads.get("7days", {}))
    lines = [f"Ad performance — {period}:"]
    if "spend"       in data: lines.append(f"  Spend:    ${data['spend']:,.2f}")
    if "roas"        in data: lines.append(f"  ROAS:     {data['roas']}×")
    if "ctr"         in data: lines.append(f"  CTR:      {data['ctr']}%")
    if "best"        in data: lines.append(f"  Best:     {data['best']}")
    if "worst"       in data: lines.append(f"  Weakest:  {data['worst']}")
    if "recommendation" in data: lines.append(f"  Recommendation: {data['recommendation']}")

    return "\n".join(lines) if len(lines) > 1 else "No ad data for period."


def _handle_email_triage(args: dict) -> str:
    bi      = _load_bi_data()
    inbox   = bi.get("email_inbox", [])
    action  = args.get("action", "list")
    limit   = args.get("limit", 20)

    if action == "list":
        if not inbox:
            return "Inbox is clear, sir. No pending emails."
        pending   = [e for e in inbox if not e.get("resolved")][:limit]
        auto_done = [e for e in pending if e.get("auto_resolvable")]
        needs_you = [e for e in pending if not e.get("auto_resolvable")]

        lines = [f"Inbox: {len(pending)} pending email(s)."]
        if auto_done:
            lines.append(f"  Auto-resolvable:  {len(auto_done)} (common Q&A, account issues)")
        if needs_you:
            lines.append(f"  Needs your attention:  {len(needs_you)}")
            for e in needs_you[:5]:
                lines.append(f"    • [{e.get('from','?')}] {e.get('subject','(no subject)')}")
        return "\n".join(lines)

    if action == "feature_requests":
        reqs = [e for e in inbox if e.get("category") == "feature_request"]
        if not reqs:
            return "No feature requests logged."
        grouped: dict = {}
        for r in reqs:
            k = r.get("feature", r.get("subject", "unknown"))
            grouped[k] = grouped.get(k, 0) + 1
        lines = ["Feature requests:"]
        for feat, count in sorted(grouped.items(), key=lambda x: -x[1])[:10]:
            lines.append(f"  {count}×  {feat}")
        return "\n".join(lines)

    return f"Email action '{action}' noted."


def _handle_delegate_task(args: dict) -> str:
    bi     = _load_bi_data()
    action = args.get("action", "assign")
    agent  = args.get("agent", "unknown").lower()
    task   = args.get("task", "")

    AGENT_PROFILES = {
        "tom":   "developer agent — builds back-end features, APIs, and fixes bugs",
        "scout": "research agent — gathers data, analyses trends, summarises findings",
        "ada":   "content agent — writes copy, scripts, captions, and blog posts",
        "nova":  "analytics agent — generates reports, charts, and business insights",
    }

    if action == "assign":
        if not task:
            return "No task description provided."
        task_id = f"{agent}_{int(time.time())}"
        tasks   = bi.get("delegated_tasks", [])
        tasks.append({
            "id":        task_id,
            "agent":     agent,
            "task":      task,
            "priority":  args.get("priority", "normal"),
            "status":    "in_progress",
            "created":   datetime.now().isoformat(),
            "result":    None,
        })
        bi["delegated_tasks"] = tasks
        _save_bi_data(bi)
        profile = AGENT_PROFILES.get(agent, f"specialist agent '{agent}'")
        return (
            f"Task delegated to {agent.title()} ({profile}). "
            f"Task ID: {task_id}. "
            f"I'll notify you when it's ready for review, sir."
        )

    if action in ("status", "list_all"):
        tasks = bi.get("delegated_tasks", [])
        if not tasks:
            return "No delegated tasks on record."
        lines = ["Delegated tasks:"]
        for t in tasks[-10:]:
            lines.append(
                f"  [{t['id']}] {t['agent'].title()} — {t['task'][:60]} — {t['status']}"
            )
        return "\n".join(lines)

    return f"Delegate action '{action}' recorded."


def _clean_report_for_speech(text: str) -> str:
    """
    Convert a verbatim Activity Log report (TOM/SCOUT/ADA/NOVA REPORT blocks,
    code previews, file paths, box-drawing borders) into something natural
    to listen to. The RAW text still goes to the log unchanged — this is
    ONLY applied to the copy that gets spoken aloud.

    Without this, JARVIS would read things like "═══ TOM REPORT ═══" and
    full Python source code line-by-line, which sounds broken and is not
    what the person actually wants to hear.
    """
    if not text:
        return ""

    t = text

    # Drop box-drawing border lines (═══, ───, ━━━, etc.) entirely.
    t = re.sub(r"^[\s]*[═━─_]{3,}[\s]*$", "", t, flags=re.MULTILINE)

    # Strip a "Solution:" / "Preview:" code block onward — code is unreadable
    # spoken aloud. Replace with a short spoken-friendly note instead.
    code_block_match = re.search(
        r"(Solution\s*:|Preview\s*:)\s*\n", t, flags=re.IGNORECASE
    )
    if code_block_match:
        head = t[:code_block_match.start()]
        t = head + "The code has been written and saved. Check the activity log for the full source."

    # Collapse "Label   : value" report rows into natural "Label is value." speech.
    t = re.sub(r"^([A-Za-z][A-Za-z \/]{2,20}?)\s*:\s*", r"\1: ", t, flags=re.MULTILINE)

    # Strip emoji/symbols that TTS engines either skip oddly or mispronounce.
    t = re.sub(r"[✅⚠️❌🔍📊📁🎯⭐️▶️◀️➡️⬅️🔧🧠💡🚀]", "", t)

    # Strip markdown emphasis characters and stray pipe/bracket table junk.
    # (Underscore is intentionally NOT stripped — it's common in filenames
    # like rename_files.py and stripping it mangles those when spoken/seen.)
    t = re.sub(r"[*`#|]", "", t)
    t = re.sub(r"\[([^\]]+)\]", r"\1", t)

    # Collapse repeated blank lines and excess whitespace from the formatting strip.
    t = re.sub(r"\n{2,}", ". ", t)
    t = re.sub(r"[ \t]{2,}", " ", t)
    t = t.replace("\n", ". ").strip()
    t = re.sub(r"\.{2,}", ".", t)
    t = re.sub(r"\s+\.", ".", t)
    t = re.sub(r"^[\.\s]+", "", t)  # drop leading stray punctuation from stripped border lines

    return t.strip() or "Task completed. Full details are in the activity log."


def _speak_via_edge_tts(text: str, ui=None, set_speaking=None) -> None:
    """
    Speak `text` using edge-tts (Microsoft Neural TTS) in a fire-and-forget
    thread.
    """
    import io
    import tempfile

    PRIMARY_VOICE  = "en-GB-RyanNeural"
    FALLBACK_VOICE = "en-US-GuyNeural"
    RATE  = "+2%"
    PITCH = "-2Hz"

    def _safe_set_speaking(state: bool):
        if set_speaking:
            try:
                set_speaking(state)
            except Exception:
                pass
        elif ui and hasattr(ui, 'set_speaking'):
            try:
                ui.set_speaking(state)
            except Exception:
                pass

    def _play_mp3_pygame(mp3_buf: "io.BytesIO") -> None:
        """Play an in-memory MP3 using pygame.mixer — no external player."""
        import pygame
        import time as _time

        mp3_buf.seek(0)
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".mp3") as f:
                f.write(mp3_buf.read())
                tmp_path = f.name

            # pygame.mixer may already be initialised by the UI; re-init is safe.
            if not pygame.mixer.get_init():
                pygame.mixer.init(frequency=24000, size=-16, channels=1, buffer=512)

            pygame.mixer.music.load(tmp_path)
            _safe_set_speaking(True)
            pygame.mixer.music.play()
            while pygame.mixer.music.get_busy():
                _time.sleep(0.05)
        finally:
            _safe_set_speaking(False)
            try:
                pygame.mixer.music.stop()
            except Exception:
                pass
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

    async def _synthesize(voice: str) -> "io.BytesIO":
        import edge_tts
        communicate = edge_tts.Communicate(text, voice=voice, rate=RATE, pitch=PITCH)
        mp3_buf = io.BytesIO()
        async for chunk in communicate.stream():
            if chunk["type"] == "audio":
                mp3_buf.write(chunk["data"])
        mp3_buf.seek(0)
        return mp3_buf

    try:
        import asyncio as _aio
        import sounddevice as _sd
        import numpy as _np

        async def _run():
            try:
                mp3_buf = await _synthesize(PRIMARY_VOICE)
            except Exception:
                # Primary voice unavailable/blocked — fall back automatically
                # rather than going silent.
                mp3_buf = await _synthesize(FALLBACK_VOICE)

            # ── Strategy 1: pygame (no subprocess, no console window) ────────
            try:
                _play_mp3_pygame(mp3_buf)
                return
            except Exception:
                pass

            # ── Strategy 2: sounddevice + pydub (chunked real RMS playback) ──
            try:
                from pydub import AudioSegment
                seg = AudioSegment.from_file(mp3_buf, format="mp3")
                pcm = _np.frombuffer(seg.raw_data, dtype=_np.int16)
                _safe_set_speaking(True)
                chunk_samples = max(256, int(seg.frame_rate * 0.05)) # ~50ms chunk
                channels = seg.channels
                with _sd.OutputStream(samplerate=seg.frame_rate, channels=channels, dtype=_np.int16) as stream:
                    step = chunk_samples * channels
                    for i in range(0, len(pcm), step):
                        chunk = pcm[i : i + step]
                        if len(chunk) == 0:
                            break
                        samples_f = chunk.astype(_np.float32)
                        rms = float(_np.sqrt(_np.mean(samples_f * samples_f)))
                        level = min(1.0, rms / 3000.0)
                        if ui and hasattr(ui, 'set_audio_level'):
                            try:
                                ui.set_audio_level(level)
                            except Exception:
                                pass
                        stream.write(chunk)
                return
            except Exception as e:
                if ui:
                    ui.write_log(f"SYS: pydub/ffmpeg playback failed — {e}")
            finally:
                _safe_set_speaking(False)

        _aio.run(_run())

    except ImportError:
        # edge-tts not installed — fall back to pyttsx3 (no audio file at all)
        try:
            import pyttsx3
            engine = pyttsx3.init()
            engine.setProperty("rate", 170)
            for v in engine.getProperty("voices"):
                if "david" in v.name.lower() or "mark" in v.name.lower() or "ryan" in v.name.lower():
                    engine.setProperty("voice", v.id)
                    break
            _safe_set_speaking(True)
            engine.say(text)
            engine.runAndWait()
        except Exception as e:
            if ui:
                ui.write_log(f"SYS: edge-tts not installed. pip install edge-tts  ({e})")
        finally:
            _safe_set_speaking(False)
    except Exception as e:
        if ui:
            ui.write_log(f"SYS: edge-tts error — {e}")
        _safe_set_speaking(False)



def _handle_daily_briefing(args: dict, speak_fn: callable, ui=None, set_speaking=None, **_kwargs) -> str:
    """
    Assembles the full briefing, writes it to the activity log, and speaks
    the ENTIRE text via edge-tts in a background thread.

    Gemini receives only a one-line silent acknowledgement so the Live API
    WebSocket never has to TTS a long string — eliminating the session
    timeout crash that previously cut briefings off mid-sentence.

    Voice: edge-tts  en-US-GuyNeural  (deep male, closest to Charon)
    Install once:  pip install edge-tts
    """
    btype    = args.get("type", "full")
    now      = datetime.now()
    hour     = now.hour
    greeting = "Good morning" if hour < 12 else ("Good afternoon" if hour < 18 else "Good evening")

    # ── Gather all sections ───────────────────────────────────────────────────
    app_result     = _handle_app_stats({"period": "7days", "metric": "all"})
    content_result = _handle_content_metrics({"period": "7days"})
    ads_result     = _handle_ads_performance({"period": "7days"})
    email_result   = _handle_email_triage({"action": "list"})
    tasks_result   = _handle_delegate_task({"action": "list_all"})

    # ── Write full detail to the activity log ────────────────────────────────
    if ui is not None:
        ui.write_log("─" * 50)
        ui.write_log(f"BRIEFING — {now.strftime('%a %d %b %Y  %I:%M %p')}")
        ui.write_log("─" * 50)
        ui.write_log(app_result)
        ui.write_log(content_result)
        ui.write_log(ads_result)
        ui.write_log(email_result)
        ui.write_log(tasks_result)
        ui.write_log("─" * 50)

    # ── Build the FULL spoken script for edge-tts ────────────────────────────
    spoken_lines = [f"{greeting}, sir. Here is your {btype} briefing."]

    # App stats
    if "empty" not in app_result and "No data" not in app_result:
        spoken_lines.append("App performance this week.")
        for line in app_result.splitlines():
            l = line.strip()
            if l and ":" in l and not l.startswith("App performance"):
                spoken_lines.append(l)
    else:
        spoken_lines.append("App stats: no data connected yet.")

    # Content
    if "No content" not in content_result and "No platform" not in content_result:
        spoken_lines.append("Content metrics.")
        for line in content_result.splitlines():
            l = line.strip()
            if l and not l.startswith("Content performance") and not l.startswith("["):
                spoken_lines.append(l)
    else:
        spoken_lines.append("Content: no metrics connected yet.")

    # Ads
    if "No ad" not in ads_result:
        spoken_lines.append("Advertising.")
        for line in ads_result.splitlines():
            l = line.strip()
            if l and not l.startswith("Ad performance"):
                spoken_lines.append(l)
    else:
        spoken_lines.append("Ads: no data connected yet.")

    # Emails
    spoken_lines.append("Inbox.")
    spoken_lines.append(email_result.replace("\n", ". ").strip())

    # Tasks
    if "No delegated" not in tasks_result:
        spoken_lines.append("Agent tasks.")
        for line in tasks_result.splitlines():
            l = line.strip()
            if l and not l.startswith("Delegated tasks"):
                spoken_lines.append(l)
    else:
        spoken_lines.append("No active agent tasks.")

    spoken_lines.append("That concludes your briefing, sir. Full detail is in the activity log.")

    full_speech = "  ".join(spoken_lines)

    # ── Speak via edge-tts in background — does NOT block Gemini session ─────
    threading.Thread(
        target=_speak_via_edge_tts,
        args=(full_speech, ui, set_speaking),
        daemon=True
    ).start()

    # ── Return a silent one-liner to Gemini so it stays quiet ────────────────
    return "[BRIEFING_DELIVERED_VIA_EDGE_TTS] Stay completely silent. The briefing is already being spoken aloud by the edge-tts engine. Do NOT speak. Do NOT summarise. Just say nothing."


def _handle_set_briefing_schedule(args: dict) -> str:
    bi   = _load_bi_data()
    slot = args.get("slot", "custom")
    hour = args.get("hour")
    minute = args.get("minute", 0)
    enabled = args.get("enabled", True)

    times = bi.get("briefing_times", [
        {"hour": 8,  "minute": 0,  "label": "morning", "enabled": True},
        {"hour": 20, "minute": 0,  "label": "evening", "enabled": True},
    ])

    updated = False
    for t in times:
        if t["label"] == slot:
            if hour is not None: t["hour"]   = hour
            t["minute"]  = minute
            t["enabled"] = enabled
            updated = True
            break

    if not updated and hour is not None:
        times.append({"hour": hour, "minute": minute, "label": slot, "enabled": enabled})

    bi["briefing_times"] = times
    _save_bi_data(bi)

    if not enabled:
        return f"{slot.title()} briefing disabled, sir."
    return (
        f"{slot.title()} briefing scheduled for "
        f"{hour:02d}:{minute:02d}. I'll brief you automatically."
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN JARVIS CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class JarvisLive:

    def __init__(self, ui: JarvisUI):
        self.ui             = ui
        self.session        = None
        self.audio_in_queue = None
        self.out_queue      = None
        self._loop          = None
        self._is_speaking   = False
        self._speaking_lock = threading.Lock()
        self._speaking_since = None
        self._last_activity = time.time()

        # ── Phase 4: Shutdown event — set on shutdown, checked by run() loop ──
        self._shutdown_event = threading.Event()

        # ── Response-in-progress event ────────────────────────────────────────
        # Set while Gemini is streaming a response. Blocks any send_client_content
        # injection that would cut the response short (briefings, proactive hints).
        self._response_in_progress = threading.Event()

        # ── Tool-in-flight flag ─────────────────────────────────────────────
        # True from the moment a tool_call is received until its function
        # response has been sent back AND the tool has fully returned.
        # turn_complete fires as soon as the model hands off to a tool —
        # that is NOT the end of the exchange, so sleep()/end-of-turn logic
        # must check this flag before deciding the conversation is over.
        self._tool_in_flight = False

        # ── THINKING-state watchdog ──────────────────────────────────────────
        # BUGFIX: THINKING is a manually-pushed UI label (not a real state in
        # core/states.py) that's only ever cleared by Gemini's own follow-up
        # (set_speaking(True) on output_transcription, or a tool's return path
        # leading to a spoken reply). If Gemini never sends anything back for
        # a turn — dropped session, empty/malformed response, a tool that
        # raises before producing any result — there is no other code path
        # that clears it, so the orb can get stuck on THINKING forever with
        # no way back to LISTENING. _thinking_since records when THINKING was
        # last pushed; a watchdog coroutine (_thinking_watchdog) checks it and
        # force-recovers after a timeout.
        self._thinking_since = None

        # ── Session resumption handle ────────────────────────────────────────
        # STEADY-CONNECTION FIX (1/3): Gemini Live sends a fresh resumption
        # handle in every `session_resumption_update` message. If we hand that
        # handle back in SessionResumptionConfig(handle=...) on the *next*
        # connect, the server restores the in-progress turn/context instead of
        # starting cold. Previously this was configured but never wired up —
        # `_build_config()` always created SessionResumptionConfig() with no
        # handle, so every reconnect was a brand-new session regardless of
        # what the server offered. That's the main reason a mid-reply drop
        # actually lost the reply instead of seamlessly continuing it.
        self._resumption_handle = None
        # DEDUP FIX: tracks last typed text so recv loop skips echoed input_transcription
        self._last_typed_text: str = ""

        # ── Phase 4: State machine ────────────────────────────────────────────
        # SLEEPING → LISTENING (wake word) → ACTIVE_CONVERSATION → LISTENING
        # SHUTDOWN is terminal: no auto-restart, mic stops, session closes.
        self._state_manager = StateManager(
            on_change=self._on_state_change,
            initial=JarvisState.SLEEPING,
        )

        # Hook text input from UI
        self.ui.on_text_command = self._on_text_command
        self.ui.on_gesture_toggle = self._on_gesture_toggle_ui

        # Always-on offline wake-word detector (openWakeWord, no cloud calls)
        self._wake_detector = WakeWordEngine(
            on_wake=self._on_wake_word,
            threshold=_get_wake_sensitivity(),
            on_error=self._on_wake_detector_error,
        )

        # Optional webcam gesture control — same on/off shape as the wake
        # detector. Open palm wakes JARVIS the same way the wake word does;
        # closed fist puts it back to sleep. Off by default (needs camera
        # permission the user should explicitly grant); enable by calling
        # self._gesture_engine.start() — wired to a UI toggle in ui.py.
        from core.gesture_control import GestureControlEngine
        self._gesture_engine = GestureControlEngine(
            on_gesture={
                "Open_Palm":   self._on_gesture_wake,
                "Closed_Fist": self._on_gesture_sleep,
            },
            on_error=self._on_gesture_error,
        )

        # Let the settings UI (sensitivity slider) push live threshold updates
        self.ui.on_wake_sensitivity_changed = self._on_wake_sensitivity_changed

        # Phase 3: Memory editor button
        self._memory_editor = None
        self.ui.on_open_memory_editor = self._open_memory_editor_ui

        # Phase 1: Energy-based mic pre-filter (drops ambient noise before Gemini queue)
        self._mic_filter = MicEnergyFilter(threshold_rms=_get_noise_floor_rms())

        # ── Phase 4: Proactive Bridge (Unified Proactive Push) ────────────────
        from core.proactive_bridge import ProactiveBridge
        self._proactive_bridge = ProactiveBridge(
            get_state=lambda: self._state_manager.state.name if hasattr(self, "_state_manager") else "LISTENING",
            voice_sink=self.speak,
            ui_sink=self.ui.write_log if self.ui else None,
            interrupt_sink=self._interrupt_playback,
        )

        # Wire EmergencyWipeController singleton to ProactiveBridge for CRITICAL blocked wipe alerts
        try:
            from core.sentinel_extras import EmergencyWipeController
            EmergencyWipeController.get_instance().set_bridge(self._proactive_bridge)
        except Exception as _we:
            print(f"[WipeController] Bridge wiring skipped: {_we}")

        # Phase 1 & 4: proactive briefing scheduler wired to ProactiveBridge
        self._briefing_scheduler = BriefingScheduler(
            on_briefing=self._on_scheduled_briefing,
            bridge=self._proactive_bridge,
        )


        # ── Phase 4: Proactive Intelligence ──────────────────────────────────
        # Voice emotion detector — analyses mic PCM in real-time
        from core.voice_emotion import VoiceEmotionDetector
        def _on_mood(state: str):
            _mood_prompts = {
                "stressed": (
                    "I notice your voice sounds a bit tense, sir. "
                    "Would you like to take a short break, or shall I help lighten the load?"
                ),
                "tired": (
                    "Sir, your voice suggests you may be fatigued. "
                    "Might I suggest wrapping up for now?"
                ),
                "calm": None,   # no interruption for calm — just update state silently
            }
            msg = _mood_prompts.get(state)
            if msg:
                try:
                    asyncio.run_coroutine_threadsafe(
                        self._inject_text(msg), self._loop
                    )
                except Exception:
                    pass
        self._emotion = VoiceEmotionDetector(on_state_change=_on_mood)

        self._proactive = ProactiveIntelligence(
            get_state  = lambda: self._state_manager.state,
            speak_fn   = self.speak,
            log_fn     = self.ui.write_log,
            weather_fn = weather_action,   # reuse existing weather action
        )

        # ── Phase 7: Mobile companion server ──────────────────────────────────
        self._intercom_active = False
        self._intercom_mic_stream = None
        self._intercom_speaker_stream = None
        self._intercom_playback_queue = None
        try:
            self._mobile = MobileServer()
            def _on_mobile_cmd(cmd: str):
                try:
                    asyncio.run_coroutine_threadsafe(self._inject_text(cmd), self._loop)
                except Exception as e:
                    print(f"[Mobile] Error injecting command: {e}")
            self._mobile.set_callbacks(
                on_command = _on_mobile_cmd,
                on_wake    = self._on_wake_word,
                on_intercom_start = self._on_intercom_start,
                on_intercom_stop  = self._on_intercom_stop,
                on_intercom_audio = self._on_intercom_audio_received,
            )
        except Exception as _me:
            print(f"[Mobile] Initialization skipped: {_me}")
            self._mobile = None

    # ── Activity tracking ────────────────────────────────────────────────────

    # ── State machine callback ─────────────────────────────────────────────────────

    def _on_state_change(self, new_state: JarvisState, ui_label: str):
        """Called by StateManager on every valid transition."""
        # Mirror to HUD; suppress during SPEAKING to avoid flicker
        if not self.ui.muted or new_state in (JarvisState.SHUTDOWN, JarvisState.SLEEPING):
            self.ui.set_state(ui_label)

    # ── Activity tracking ────────────────────────────────────────────────────────

    def _touch_activity(self):
        self._last_activity = time.time()
        # NOTE: Do NOT promote SLEEPING → LISTENING here.
        # Only _on_wake_word() is allowed to make that transition.
        # This prevents mic noise / JARVIS own TTS from accidentally waking.

    def _on_wake_word(self):
        """Called by WakeWordEngine when wake word is heard."""
        if self._state_manager.is_shutdown():
            return

        with self._speaking_lock:
            currently_speaking = self._is_speaking
        if currently_speaking:
            return
        if self._state_manager.is_active():
            return

        self._last_activity = time.time()
        self._state_manager.wake()   # SLEEPING → LISTENING
        self.ui.write_log("SYS: Wake word detected — JARVIS activated")

        # Phase 4: offer morning briefing right after wake word
        self._proactive.on_wake_word()

        # Inject acknowledgement into the live Gemini session so JARVIS
        # actually speaks — without this, the UI shows LISTENING but Gemini
        # never knows it was woken up and stays completely silent.
        if self.session and self._loop:
            asyncio.run_coroutine_threadsafe(
                self.session.send_client_content(
                    turns={"parts": [{"text": "[WAKE] User called for JARVIS. Acknowledge briefly and wait for command."}]},
                    turn_complete=True
                ),
                self._loop
            )

    def _on_wake_detector_error(self, message: str):
        """
        Called by WakeWordEngine if model loading fails during start().
        Only logs the error — wake word won't work this session but
        typed commands and everything else still function normally.
        """
        self.ui.write_log(f"SYS: ⚠️ {message}")

    def _on_gesture_wake(self):
        """Called by GestureControlEngine on a stable open-palm gesture.
        Mirrors _on_wake_word's guard checks so a gesture can't fire the
        same invalid transitions voice wake already protects against."""
        if self._state_manager.is_shutdown():
            return
        with self._speaking_lock:
            currently_speaking = self._is_speaking
        if currently_speaking or self._state_manager.is_active():
            return

        self._last_activity = time.time()
        if self._state_manager.wake():
            self.ui.write_log("SYS: Gesture detected (open palm) — JARVIS activated")
            if self.session and self._loop:
                asyncio.run_coroutine_threadsafe(
                    self.session.send_client_content(
                        turns={"parts": [{"text": "[WAKE] User raised an open palm. Acknowledge briefly and wait for command."}]},
                        turn_complete=True
                    ),
                    self._loop
                )

    def _on_gesture_sleep(self):
        """Called by GestureControlEngine on a stable closed-fist gesture."""
        if self._state_manager.is_shutdown() or self._state_manager.is_active():
            return
        if self._state_manager.sleep():
            self.ui.write_log("SYS: Gesture detected (closed fist) — JARVIS standing by")

    def _on_gesture_error(self, message: str):
        """Called by GestureControlEngine if the camera or model fails to
        load. Gesture control simply won't work this session — voice and
        typed commands are unaffected."""
        self.ui.write_log(f"SYS: ⚠️ Gesture control — {message}")

    def _on_gesture_toggle_ui(self, enabled: bool):
        """Called when the user clicks the GESTURE CONTROL button in the UI.
        Starts/stops the real engine and persists the choice for next launch."""
        _save_gesture_control_enabled(enabled)
        if enabled:
            self._gesture_engine.start()
        else:
            self._gesture_engine.stop()

    def _on_wake_sensitivity_changed(self, value: float):
        """Called once per debounce commit (400 ms after user stops moving slider).
        Applies new threshold to the running listener and logs once."""
        self._wake_detector.set_threshold(value)
        self.ui.write_log(f"SYS: Wake sensitivity → {value:.2f}")

    def _open_memory_editor_ui(self):
        """Show the Memory Bank overlay (creates it lazily)."""
        from memory.memory_editor import MemoryEditorOverlay
        if self._memory_editor is None:
            self._memory_editor = MemoryEditorOverlay()
            self._memory_editor.closed.connect(lambda: None)
        else:
            self._memory_editor.refresh()
        self._memory_editor.show()
        self._memory_editor.raise_()
        self.ui.write_log("SYS: Memory Bank opened")

    def _on_scheduled_briefing(self, label: str):
        """Called by BriefingScheduler at configured times.
        Phase 4: never interrupt an ACTIVE_CONVERSATION or while speaking."""
        if self._state_manager.is_shutdown():
            return
        # Do NOT inject while JARVIS is speaking or user is mid-conversation —
        # it cuts JARVIS off mid-sentence and shows as a garbled command.
        with self._speaking_lock:
            currently_speaking = self._is_speaking
        response_busy = self._response_in_progress.is_set()
        if currently_speaking or response_busy or self._state_manager.is_active():
            self.ui.write_log(f"SYS: Auto-briefing ({label}) deferred — busy")
            return
        self._touch_activity()
        self.ui.write_log(f"SYS: Auto-briefing triggered — {label}")
        brief_text = (
            f"[AUTO BRIEFING] It is now {label} briefing time. "
            f"Deliver the {label} briefing proactively using the daily_briefing tool."
        )
        if self.session and self._loop:
            asyncio.run_coroutine_threadsafe(
                self.session.send_client_content(
                    turns={"parts": [{"text": brief_text}]},
                    turn_complete=True
                ),
                self._loop
            )

    # ── Intercom: live two-way audio with the phone (Phase 7) ─────────────────

    def _on_intercom_start(self, ip: str):
        """Called from the mobile server's background thread when the
        phone taps START INTERCOM. Starts a dedicated mic-capture stream
        (PC mic → phone) and a dedicated playback queue (phone mic → PC
        speakers), independent of the voice-assistant's own mic/speaker
        streams so the two don't interfere with each other."""
        if self._intercom_active:
            return
        print(f"[Intercom] 🎙️ Starting — requested by {ip}")
        self._intercom_active = True
        import queue as _queue
        self._intercom_playback_queue = _queue.Queue()

        def _mic_capture_loop():
            def _cb(indata, frames, time_info, status):
                if not self._intercom_active:
                    raise sd.CallbackStop()
                try:
                    if getattr(self, "_mobile", None):
                        self._mobile.broadcast_intercom_audio(bytes(indata))
                except Exception as e:
                    print(f"[Intercom] ⚠️ mic broadcast error: {e}")
            try:
                with sd.InputStream(samplerate=16000, channels=1,
                                     dtype="int16", blocksize=1024,
                                     callback=_cb) as stream:
                    self._intercom_mic_stream = stream
                    while self._intercom_active:
                        time.sleep(0.1)
            except Exception as e:
                print(f"[Intercom] ❌ mic capture failed: {e}")
            finally:
                self._intercom_mic_stream = None

        def _speaker_playback_loop():
            try:
                with sd.RawOutputStream(samplerate=16000, channels=1,
                                         dtype="int16", blocksize=1024) as stream:
                    self._intercom_speaker_stream = stream
                    while self._intercom_active:
                        try:
                            chunk = self._intercom_playback_queue.get(timeout=0.2)
                        except Exception:
                            continue
                        try:
                            stream.write(chunk)
                        except Exception as e:
                            print(f"[Intercom] ⚠️ playback write error: {e}")
            except Exception as e:
                print(f"[Intercom] ❌ speaker playback failed: {e}")
            finally:
                self._intercom_speaker_stream = None

        threading.Thread(target=_mic_capture_loop, daemon=True, name="IntercomMic").start()
        threading.Thread(target=_speaker_playback_loop, daemon=True, name="IntercomSpeaker").start()
        if getattr(self, "_mobile", None):
            self._mobile.notify("Intercom link opened, sir.")

    def _on_intercom_stop(self, ip: str):
        if not self._intercom_active:
            return
        print(f"[Intercom] ⏹ Stopping — requested by {ip}")
        self._intercom_active = False
        if getattr(self, "_mobile", None):
            self._mobile.notify("Intercom link closed, sir.")

    def _on_intercom_audio_received(self, pcm_bytes: bytes):
        """Called from the mobile server's background thread whenever a
        chunk of the phone's mic audio arrives. Queues it for the speaker
        playback thread started in _on_intercom_start."""
        if not self._intercom_active or not getattr(self, "_intercom_playback_queue", None):
            return
        try:
            self._intercom_playback_queue.put_nowait(pcm_bytes)
        except Exception:
            pass

    # ── Text command from UI ─────────────────────────────────────────────────

    def _on_text_command(self, text: str):
        if self._state_manager.is_shutdown():
            return   # reject input after shutdown
        self._touch_activity()
        self._state_manager.begin_conversation()   # typed command = active
        if not self._loop or not self.session:
            return
        # Log immediately so user sees their typed message.
        # Store text so recv loop skips the echoed input_transcription duplicate.
        self._last_typed_text = text.strip().lower()
        self.ui.write_log(f"You: {text}")
        # Kick off memory extraction on the typed text straight away
        # (voice path also does this via in_buf, but typed text may never
        # produce an input_transcription event)
        threading.Thread(
            target=_update_memory_async,
            args=(text, ""),
            daemon=True
        ).start()
        asyncio.run_coroutine_threadsafe(
            self.session.send_client_content(
                turns={"parts": [{"text": text}]},
                turn_complete=True
            ),
            self._loop
        )

    def inject(self, text: str):
        """Push a message into the live session from outside."""
        if not self._loop or not self.session:
            return
        asyncio.run_coroutine_threadsafe(
            self.session.send_client_content(
                turns={"parts": [{"text": text}]},
                turn_complete=True
            ),
            self._loop
        )

    async def _inject_text(self, text: str):
        if self.session:
            await self.session.send_client_content(
                turns={"parts": [{"text": text}]},
                turn_complete=True
            )

    # ── Speaking state ───────────────────────────────────────────────────────

    def set_speaking(self, value: bool):
        with self._speaking_lock:
            self._is_speaking = value
            self._speaking_since = time.time() if value else None
        # FLICKER FIX: the UI label comes from two independent sources —
        # this method calling ui.set_state() directly, AND the StateManager's
        # on_change callback (_on_state_change) firing from
        # begin_conversation()/end_conversation() below.
        if value:
            if not self.ui.muted:
                self.ui.set_state("SPEAKING")
            self._wake_detector.pause()   # Pause wake-word listener while JARVIS talks so TTS can't re-trigger.
            self._state_manager.begin_conversation()   # LISTENING -> ACTIVE_CONVERSATION (internal bookkeeping only)
            self._thinking_since = None   # Gemini responded — no longer stuck
        else:
            if not self.ui.muted:
                self.ui.set_state("LISTENING")
            self._wake_detector.resume()
            self._state_manager.end_conversation()     # ACTIVE_CONVERSATION -> LISTENING (internal bookkeeping only)

        if hasattr(self, "_proactive_bridge") and self._proactive_bridge:
            self._proactive_bridge.on_state_change("SPEAKING" if value else "LISTENING")

    def _interrupt_playback(self):
        """Phase 2: Immediately stops playback, drains incoming audio queue, and opens mic for barge-in."""
        with self._speaking_lock:
            self._is_speaking = False
            self._speaking_since = None
        self._wake_detector.resume()
        try:
            import pygame
            if pygame.mixer.get_init():
                pygame.mixer.music.stop()
        except Exception:
            pass
        try:
            import sounddevice as _sd
            _sd.stop()
        except Exception:
            pass
        if self.audio_in_queue:
            while not self.audio_in_queue.empty():
                try:
                    self.audio_in_queue.get_nowait()
                except Exception:
                    break
        if not self.ui.muted:
            self.ui.set_state("LISTENING")
        self._state_manager.begin_conversation()
        print("[BARGE-IN] 🛑 Interrupted JARVIS playback; drained audio queue, halted TTS, and returned to LISTENING.")

    def speak(self, text: str):
        if not self._loop or not self.session:
            return
        asyncio.run_coroutine_threadsafe(
            self.session.send_client_content(
                turns={"parts": [{"text": text}]},
                turn_complete=True
            ),
            self._loop
        )

    def speak_error(self, tool_name: str, error: str):
        short = str(error)[:120]
        self.ui.write_log(f"ERR: {tool_name} — {short}")
        self.speak(f"Sir, {tool_name} encountered an error. {short}")

    # ── Config builder ───────────────────────────────────────────────────────

    def _build_config(self) -> types.LiveConnectConfig:
        memory    = load_memory()
        mem_str   = format_memory_for_prompt(memory)
        sys_prompt = _load_system_prompt()
        bi_data   = _load_bi_data()

        now      = datetime.now()
        time_str = now.strftime("%A, %B %d, %Y — %I:%M %p")
        # BUG FIX: tz_label makes the timezone explicit. Previously this block
        # gave the model a bare timestamp with no timezone info — when asked
        # specifically for "Indian time" / IST, the model would guess the
        # given time was UTC and add +5:30 on top of what was ALREADY local
        # IST time, producing a time ~5:30 ahead of the real clock. Stating
        # the timezone explicitly and telling the model not to convert fixes
        # that. Also explicitly bans mixing 24-hour + AM/PM (e.g. "13:57 PM").
        tz_label = now.astimezone().strftime("%Z (UTC%z)")

        # Build rich context block
        context_parts = []

        # Time context
        context_parts.append(
            f"[CURRENT DATE & TIME]\n"
            f"Right now it is: {time_str} {tz_label} — this IS the user's local "
            f"timezone already. It is already fully correct and final.\n"
            f"NEVER apply any additional timezone conversion, offset, or adjustment "
            f"to this value, even if explicitly asked for 'Indian time', 'IST', or any "
            f"other timezone name — this value already IS that. "
            f"Always state it in exactly this format (12-hour clock with AM/PM, e.g. "
            f"'01:57 PM') — never mix 24-hour notation with AM/PM (e.g. never say '13:57 PM').\n"
            f"Use this to calculate exact times for reminders and briefings.\n"
        )

        # Business context
        if bi_data:
            context_parts.append(
                "[BUSINESS CONTEXT]\n"
                "You manage the following active projects and business assets:\n" +
                json.dumps(bi_data.get("business_context", {}), indent=2) + "\n"
            )

        # Agent roster
        context_parts.append(
            "[AGENT ROSTER]\n"
            "You command a team of specialist sub-agents:\n"
            "  • Tom     — developer agent (back-end, APIs, bug fixes)\n"
            "  • Scout   — research agent (data gathering, trend analysis)\n"
            "  • Ada     — content agent (copy, scripts, captions)\n"
            "  • Nova    — analytics agent (reports, charts, insights)\n"
            "Delegate tasks to them via the delegate_task tool.\n"
        )

        # Operational mode
        context_parts.append(
            "[OPERATIONAL MODE]\n"
            "You are running as a persistent background service. "
            "You listen continuously. Wake-word detection is handled offline "
            "by a separate local engine — you do NOT self-trigger on wake words. "
            "You proactively brief the user at scheduled times. "
            "You behave like Tony Stark's JARVIS — always on, always sharp, "
            "proactively managing every aspect of the user's digital life and business.\n"
        )

        # Active window context — tells JARVIS what app the user is in
        try:
            import win32gui as _w32g
            _hwnd  = _w32g.GetForegroundWindow()
            _title = _w32g.GetWindowText(_hwnd).strip()
            if _title:
                context_parts.append(f"[ACTIVE WINDOW]\nUser is currently working in: {_title}\n")
        except Exception:
            pass  # win32gui not available on non-Windows — skip silently

        if mem_str:
            context_parts.append(mem_str)

        context_parts.append(sys_prompt)

        # Enhanced system prompt addition
        context_parts.append(
            "\n[PHASE 1 ENHANCEMENTS]\n"
            "You now have business intelligence tools: app_stats, content_metrics, "
            "ads_performance, email_triage, delegate_task, daily_briefing, set_briefing_schedule.\n"
            "When the user speaks after the wake word, "
            "proactively ask if they want a briefing or proceed with what they need.\n"
            "When auto-briefing fires, deliver it naturally as if you tracked everything all day.\n"
            "Always address the user as 'sir' unless they've specified otherwise.\n"
        )

        return types.LiveConnectConfig(
            response_modalities=["AUDIO"],
            output_audio_transcription={},
            input_audio_transcription={},
            system_instruction="\n".join(context_parts),
            tools=[{"function_declarations": TOOL_DECLARATIONS}],
            # STEADY-CONNECTION FIX (2/3): hand back whatever resumption handle
            # the server last gave us. On a clean first connect this is None,
            # which behaves exactly as before (new session). On a reconnect
            # after a drop, this restores server-side state instead of
            # starting from scratch.
            #
            # transparent=True was removed here — it raises ValueError
            # ("transparent parameter is only supported in Gemini Enterprise
            # Agent Platform mode, not in Gemini Developer API mode") on
            # every single connect when using a plain API-key client
            # (genai.Client(api_key=...)), which is what this project uses.
            # That made every connection attempt fail and reconnect-loop
            # forever — JARVIS never actually came online. The `handle=`
            # resumption itself IS supported in Developer API mode and is
            # kept; only the Vertex-only `transparent` flag is gone.
            session_resumption=types.SessionResumptionConfig(
                handle=self._resumption_handle,
            ),
            speech_config=types.SpeechConfig(
                voice_config=types.VoiceConfig(
                    prebuilt_voice_config=types.PrebuiltVoiceConfig(
                        voice_name="Charon"
                    )
                )
            ),
        )

    # ── Tool executor ────────────────────────────────────────────────────────

    def _set_thinking(self):
        """Push the THINKING label and record when, so the watchdog can
        force-recover if nothing ever clears it (see _thinking_watchdog)."""
        self.ui.set_state("THINKING")
        self._thinking_since = time.time()

    async def _execute_tool(self, fc) -> types.FunctionResponse:
        name = fc.name
        args = dict(fc.args or {})

        print(f"[JARVIS] 🔧 {name}  {args}")
        # Only show THINKING if JARVIS is NOT currently speaking an answer.
        # Setting THINKING while already SPEAKING causes the yellow-word flicker bug.
        with self._speaking_lock:
            _currently_speaking = self._is_speaking
        if not _currently_speaking:
            self._set_thinking()
        self._touch_activity()

        # ── Memory save (silent) ────────────────────────────────────────────
        if name == "save_memory":
            category = args.get("category", "notes")
            key      = args.get("key", "")
            value    = args.get("value", "")
            if key and value:
                update_memory({category: {key: {"value": value}}})
                print(f"[Memory] 💾 {category}/{key} = {value}")
            if not self.ui.muted:
                self.ui.set_state("LISTENING")
                self._thinking_since = None
            return types.FunctionResponse(
                id=fc.id, name=name,
                response={"result": "ok", "silent": True}
            )

        loop   = asyncio.get_event_loop()
        result = "Done."

        try:
            # ── Existing tools ──────────────────────────────────────────────
            if name == "open_app":
                r = await loop.run_in_executor(None, lambda: open_app(parameters=args, response=None, player=self.ui))
                result = r or f"Opened {args.get('app_name')}."

            elif name == "weather_report":
                r = await loop.run_in_executor(None, lambda: weather_action(parameters=args, player=self.ui))
                result = r or "Weather delivered."

            elif name == "browser_control":
                r = await loop.run_in_executor(None, lambda: browser_control(parameters=args, player=self.ui))
                result = r or "Done."

            elif name == "file_controller":
                r = await loop.run_in_executor(None, lambda: file_controller(parameters=args, player=self.ui))
                result = r or "Done."

            elif name == "send_message":
                r = await loop.run_in_executor(None, lambda: send_message(parameters=args, response=None, player=self.ui, session_memory=None))
                result = r or f"Message sent to {args.get('receiver')}."

            elif name == "reminder":
                r = await loop.run_in_executor(None, lambda: reminder(parameters=args, response=None, player=self.ui))
                result = r or "Reminder set."

            elif name == "youtube_video":
                r = await loop.run_in_executor(None, lambda: youtube_video(parameters=args, response=None, player=self.ui))
                result = r or "Done."

            elif name == "file_processor":
                if not args.get("file_path") and self.ui.current_file:
                    args["file_path"] = self.ui.current_file
                r = await loop.run_in_executor(
                    None,
                    lambda: file_processor(parameters=args, player=self.ui, speak=self.speak)
                )
                result = r or "Done."

            elif name == "screen_process":
                threading.Thread(
                    target=screen_process,
                    kwargs={"parameters": args, "response": None,
                            "player": self.ui, "session_memory": None},
                    daemon=True
                ).start()
                result = "Vision module activated. Stay completely silent — vision module will speak directly."

            elif name == "computer_settings":
                r = await loop.run_in_executor(None, lambda: computer_settings(parameters=args, response=None, player=self.ui))
                result = r or "Done."

            elif name == "desktop_control":
                r = await loop.run_in_executor(None, lambda: desktop_control(parameters=args, player=self.ui))
                result = r or "Done."

            elif name == "code_helper":
                r = await loop.run_in_executor(None, lambda: code_helper(parameters=args, player=self.ui, speak=self.speak))
                result = r or "Done."

            elif name == "dev_agent":
                r = await loop.run_in_executor(None, lambda: dev_agent(parameters=args, player=self.ui, speak=self.speak))
                result = r or "Done."

            elif name == "agent_task":
                from agent.task_queue import get_queue, TaskPriority
                priority_map = {"low": TaskPriority.LOW, "normal": TaskPriority.NORMAL, "high": TaskPriority.HIGH}
                priority = priority_map.get(args.get("priority", "normal").lower(), TaskPriority.NORMAL)
                task_id  = get_queue().submit(goal=args.get("goal", ""), priority=priority, speak=self.speak)
                result   = f"Task started (ID: {task_id})."

            elif name == "persona_task":
                from agents.agent_manager import get_manager
                task       = args.get("task", "")
                agent_name = args.get("agent_name") or None
                # Valid persona names only — fall back to auto-detect on a typo/garbage value
                if agent_name and agent_name.capitalize() not in ("Tom", "Scout", "Ada", "Nova"):
                    agent_name = None
                elif agent_name:
                    agent_name = agent_name.capitalize()
                keepalive = asyncio.ensure_future(self._keepalive_during_tool())
                try:
                    r = await loop.run_in_executor(
                        None,
                        lambda: get_manager().route_direct(task, agent_name=agent_name, speak=self.speak)
                    )
                finally:
                    keepalive.cancel()
                report = r or "Agent task completed with no output."
                # ── Speak the FULL report aloud via edge-tts, in sync with the log ──
                # Previously the report only ever reached the Activity Log — nothing
                # ever spoke it, since `speak=self.speak` above is only used by the
                # agent for short interim status lines, never the final report text.
                # This mirrors the existing web_search pattern: write to log AND
                # speak the same text aloud via edge-tts, instead of routing a long
                # string through the Gemini Live session (which risks the WebSocket
                # timeout/disconnect this project has already hit once before).
                threading.Thread(
                    target=_speak_via_edge_tts,
                    args=(_clean_report_for_speech(report), self.ui, self.set_speaking),
                    daemon=True
                ).start()
                result = (
                    "[PERSONA_REPORT_DELIVERED_VIA_EDGE_TTS] The full report is already "
                    "in the Activity Log and is being spoken aloud right now by the "
                    "edge-tts engine. Do NOT repeat, summarise, or read it back. Stay "
                    "completely silent."
                )

            elif name == "web_search":
                # Run search with keepalive to prevent WebSocket silence timeout
                keepalive = asyncio.ensure_future(self._keepalive_during_tool())
                try:
                    r = await loop.run_in_executor(None, lambda: web_search_action(parameters=args, player=self.ui))
                finally:
                    keepalive.cancel()
                search_result = r or "No results found."
                # Speak the full result via edge-tts so Gemini doesn't have to
                # TTS a long string (which causes the WebSocket timeout crash).
                # Cleaned first so markdown links/brackets aren't read literally.
                threading.Thread(
                    target=_speak_via_edge_tts,
                    args=(_clean_report_for_speech(search_result), self.ui, self.set_speaking),
                    daemon=True
                ).start()
                result = "[SEARCH_RESULT_DELIVERED_VIA_EDGE_TTS] The search result is already being spoken aloud by the edge-tts engine. Do NOT repeat or summarise it. Stay completely silent."

            elif name == "computer_control":
                r = await loop.run_in_executor(None, lambda: computer_control(parameters=args, player=self.ui))
                result = r or "Done."

            elif name == "game_updater":
                r = await loop.run_in_executor(None, lambda: game_updater(parameters=args, player=self.ui, speak=self.speak))
                result = r or "Done."

            elif name == "flight_finder":
                r = await loop.run_in_executor(None, lambda: flight_finder(parameters=args, player=self.ui))
                result = r or "Done."

            # ── Phase 1 new tools ───────────────────────────────────────────
            elif name == "app_stats":
                result = await loop.run_in_executor(None, lambda: _handle_app_stats(args))

            elif name == "content_metrics":
                result = await loop.run_in_executor(None, lambda: _handle_content_metrics(args))

            elif name == "ads_performance":
                result = await loop.run_in_executor(None, lambda: _handle_ads_performance(args))

            elif name == "email_triage":
                result = await loop.run_in_executor(None, lambda: _handle_email_triage(args))

            elif name == "delegate_task":
                result = await loop.run_in_executor(None, lambda: _handle_delegate_task(args))

            elif name == "daily_briefing":
                # daily_briefing calls multiple data sources synchronously.
                # Keep the Live API WebSocket alive during the wait.
                keepalive = asyncio.ensure_future(self._keepalive_during_tool())
                try:
                    result = await loop.run_in_executor(
                        None, lambda: _handle_daily_briefing(args, self.speak, ui=self.ui, set_speaking=self.set_speaking)
                    )
                finally:
                    keepalive.cancel()

            elif name == "set_briefing_schedule":
                result = await loop.run_in_executor(None, lambda: _handle_set_briefing_schedule(args))

            # ── Phase 3: Memory tools ────────────────────────────────────
            elif name == "search_memory":
                query   = args.get("query", "").strip()
                results = search_memory(query)
                result  = format_search_results(query, results)

            elif name == "open_memory_editor":
                self._open_memory_editor_ui()
                result = "Memory Bank opened, sir."

            elif name == "shutdown_jarvis":
                # Phase 4: enter SHUTDOWN state first so wake-word handler
                # ignores any accidental triggers during the goodbye speech.
                self._state_manager.shutdown()
                self._shutdown_event.set()          # signal run() loop immediately
                self.ui.write_log("SYS: Shutdown requested. Entering SHUTDOWN state.")
                self.ui.set_state("OFFLINE")
                self.speak("Goodbye, sir. JARVIS standing down.")
                # Stop proactive intelligence and wake detector immediately
                self._proactive.stop()
                self._wake_detector.stop()
                self._gesture_engine.stop()
                def _hard_exit():
                    time.sleep(2.5)
                    os._exit(0)
                threading.Thread(target=_hard_exit, daemon=True).start()

            # ── Phase 4: Proactive Intelligence tools ─────────────────────
            elif name == "get_morning_briefing":
                # Build the briefing from memory and return it as the tool
                # result — Gemini will read it out directly. Do NOT also call
                # send_client_content or Gemini gets confused and drops the text.
                memory = load_memory()
                from datetime import datetime as _dt
                now    = _dt.now()
                hour   = now.hour
                greeting = "Good morning" if hour < 12 else ("Good afternoon" if hour < 18 else "Good evening")
                parts  = [f"{greeting}, sir. Here is your briefing for {now.strftime('%A, %d %B %Y')}."]

                goals = memory.get("goals", {})
                goal_vals = [e.get("value","") for e in goals.values()
                             if isinstance(e,dict) and e.get("value")]
                if goal_vals:
                    parts.append("Active goals: " + "; ".join(goal_vals[:5]) + ".")

                notes = memory.get("notes", {})
                kwds  = ["need to","should","call","meet","deadline","appointment","remind"]
                pending = [e.get("value","") for e in notes.values()
                           if isinstance(e,dict) and any(k in e.get("value","").lower() for k in kwds)]
                if pending:
                    parts.append("Pending items: " + "; ".join(pending[:5]) + ".")

                rels = memory.get("relationships", {})
                people = [f"{k}: {e.get('value','')}" for k,e in rels.items()
                          if isinstance(e,dict) and e.get("value")]
                if people:
                    parts.append("People context: " + "; ".join(people[:3]) + ".")

                habits = memory.get("habits", {})
                habit_vals = [e.get("value","") for e in habits.values()
                              if isinstance(e,dict) and e.get("value")]
                if habit_vals:
                    parts.append("Known habits: " + "; ".join(habit_vals[:3]) + ".")

                if len(parts) == 1:
                    parts.append("No specific goals or reminders stored yet, sir. "
                                 "You can tell me things to remember and I will include them next time.")

                result = " ".join(parts)

            elif name == "get_news_digest":
                # get_news_digest may trigger web searches — keep the WS alive
                keepalive = asyncio.ensure_future(self._keepalive_during_tool())
                try:
                    news_prompt = await loop.run_in_executor(None, self._proactive.get_news_digest)
                finally:
                    keepalive.cancel()
                if self.session and self._loop:
                    asyncio.run_coroutine_threadsafe(
                        self.session.send_client_content(
                            turns={"parts": [{"text": news_prompt}]},
                            turn_complete=True
                        ),
                        self._loop
                    )
                result = "News digest in progress, sir."

            elif name == "sleep_jarvis":
                # Transition to SLEEPING — wake-word detector stays on,
                # but audio is NOT sent to Gemini until wake word fires again.
                self._state_manager.sleep()
                self.ui.write_log("SYS: JARVIS sleeping. Say 'Hey Jarvis' to wake.")
                result = "JARVIS entering sleep mode. Goodnight, sir."

            elif name == "get_calendar_events":
                hours = int(args.get("hours_ahead", 24))
                hours = max(1, min(hours, 168))
                try:
                    from core.calendar_intel import get_events, format_events
                    events = await loop.run_in_executor(None, lambda: get_events(hours))
                    result = format_events(events)
                except Exception as _cale:
                    result = (f"Calendar unavailable: {_cale}. "
                              "Set up Google Calendar by adding google_credentials.json to config/.")

            elif name == "read_clipboard":
                # Read clipboard via pyperclip (already installed)
                try:
                    import pyperclip as _pc
                    text = _pc.paste()
                    if text and text.strip():
                        result = f"[CLIPBOARD CONTENT]\n{text.strip()[:4000]}"
                        self.ui.write_log(f"SYS: Clipboard read ({len(text)} chars)")
                    else:
                        result = "The clipboard is currently empty, sir."
                except Exception as _cbe:
                    result = f"Clipboard read failed: {_cbe}"

            elif name == "get_active_window":
                # Get currently focused window title (Windows: win32gui, fallback: psutil)
                try:
                    import win32gui as _w32g
                    hwnd  = _w32g.GetForegroundWindow()
                    title = _w32g.GetWindowText(hwnd).strip()
                    result = f"Active window: {title or '(unknown)'}"
                except ImportError:
                    try:
                        import subprocess as _sp
                        out = _sp.check_output(
                            ["powershell", "-command",
                             "(Get-Process | Where-Object {$_.MainWindowTitle} | "
                             "Sort-Object CPU -Descending | Select-Object -First 1).MainWindowTitle"],
                            text=True, timeout=5
                        )
                        result = f"Active window: {out.strip() or '(unknown)'}"
                    except Exception as _awe:
                        result = f"Could not read active window: {_awe}"
                except Exception as _awe:
                    result = f"Could not read active window: {_awe}"

            elif name == "remote_control":
                # Universal remote control — routes to the correct action module
                action = args.get("action", "").lower().strip()
                value  = args.get("value", "").strip()
                try:
                    from actions.computer_settings import (
                        volume_up, volume_down, volume_mute, volume_set,
                        brightness_up, brightness_down,
                        lock_screen, shutdown, restart,
                        minimize_window, close_app, close_window, full_screen,
                    )
                    from actions.computer_control import computer_control as _cc
                    _vol_map = {
                        "volume_up": volume_up, "volume_down": volume_down,
                        "volume_mute": volume_mute,
                    }
                    _bright_map = {
                        "brightness_up": brightness_up, "brightness_down": brightness_down,
                    }
                    if action in _vol_map:
                        _vol_map[action](); result = f"{action.replace('_',' ').title()} done, sir."
                    elif action == "volume_set":
                        volume_set(int(value) if value.isdigit() else 50)
                        result = f"Volume set to {value}%, sir."
                    elif action in _bright_map:
                        _bright_map[action](); result = f"{action.replace('_',' ').title()} done, sir."
                    elif action in ("lock", "lock_screen"):
                        lock_screen(); result = "Screen locked, sir."
                    elif action == "shutdown":
                        shutdown(); result = "Shutting down, sir."
                    elif action == "restart":
                        restart(); result = "Restarting, sir."
                    elif action == "minimize":
                        minimize_window(); result = "Window minimised, sir."
                    elif action in ("close", "close_window"):
                        close_window(); result = "Window closed, sir."
                    elif action == "fullscreen":
                        full_screen(); result = "Toggled fullscreen, sir."
                    elif action == "screenshot":
                        result = await loop.run_in_executor(
                            None, lambda: _cc(parameters={"action": "screenshot"}, player=self.ui)
                        )
                    elif action == "open_app":
                        from actions.open_app import open_app
                        result = await loop.run_in_executor(
                            None, lambda: open_app(parameters={"app_name": value}, player=self.ui)
                        )
                    elif action in ("type", "type_text"):
                        result = await loop.run_in_executor(
                            None, lambda: _cc(parameters={"action": "type", "text": value}, player=self.ui)
                        )
                    elif action == "hotkey":
                        result = await loop.run_in_executor(
                            None, lambda: _cc(parameters={"action": "hotkey", "keys": value}, player=self.ui)
                        )
                    elif action == "press_key":
                        result = await loop.run_in_executor(
                            None, lambda: _cc(parameters={"action": "press", "key": value}, player=self.ui)
                        )
                    elif action in ("scroll_up", "scroll_down"):
                        direction = "up" if "up" in action else "down"
                        result = await loop.run_in_executor(
                            None, lambda: _cc(parameters={"action": "scroll", "direction": direction}, player=self.ui)
                        )
                    elif action in ("play_pause", "media_play", "next_track", "prev_track", "media_stop"):
                        _media = {"play_pause": "playpause", "media_play": "playpause",
                                  "next_track": "nexttrack", "prev_track": "prevtrack",
                                  "media_stop": "stop"}
                        result = await loop.run_in_executor(
                            None, lambda: _cc(parameters={"action": "press", "key": _media.get(action, "playpause")}, player=self.ui)
                        )
                    else:
                        # Generic fallback — pass straight to computer_control
                        result = await loop.run_in_executor(
                            None, lambda: _cc(parameters={"action": action, "value": value}, player=self.ui)
                        )
                except Exception as _rce:
                    result = f"Remote control failed ({action}): {_rce}"

            else:
                result = f"Unknown tool: {name}"

        except Exception as e:
            result = f"Tool '{name}' failed: {e}"
            traceback.print_exc()
            self.speak_error(name, e)

        # Do NOT call end_conversation() / set LISTENING here.
        # Gemini's audio response streams immediately after the tool response,
        # and _receive_audio will call set_speaking(True) → SPEAKING.
        # Forcing LISTENING/ACTIVE state here causes the visible flicker of
        # yellow THINKING words appearing mid-answer.
        # Exception: SHUTDOWN must still be handled cleanly.
        if self._state_manager.is_shutdown():
            pass  # terminal — leave in SHUTDOWN

        print(f"[JARVIS] 📤 {name} → {str(result)[:100]}")
        return types.FunctionResponse(
            id=fc.id, name=name,
            response={"result": result}
        )

    # ── Keepalive during long tool calls ─────────────────────────────────────

    from contextlib import asynccontextmanager as _acm   # imported once at class level

    @staticmethod
    async def _keepalive_noop():
        """Dummy coroutine used when keepalive is not needed."""
        pass

    async def _keepalive_during_tool(self):
        """
        Send silent PCM audio to the Gemini Live WebSocket every 5 seconds
        while a slow tool (web_search, daily_briefing, etc.) is running.

        WHY: The Gemini Live API (free tier) enforces a hard ~60 s session-
        silence timeout.  When _execute_tool() awaits run_in_executor() for an
        OpenRouter web_search call that can take 10-40 s, no audio frames are
        sent and the WebSocket closes with code 1006 "Abnormal closure."

        This coroutine runs concurrently with the tool via asyncio.gather() and
        keeps the connection alive by injecting 100 ms of zero-PCM audio every
        5 seconds.  The Live API ignores silent audio from a muted/sleeping
        state, so it never triggers a spurious response.
        """
        SILENT_CHUNK = b"\x00\x00" * (SEND_SAMPLE_RATE // 10)  # 100 ms @ 16 kHz, int16
        PING_INTERVAL = 5  # seconds between pings

        try:
            while True:
                await asyncio.sleep(PING_INTERVAL)
                if self.session:
                    try:
                        await self.session.send_realtime_input(
                            media={"data": SILENT_CHUNK, "mime_type": "audio/pcm"}
                        )
                    except Exception:
                        pass  # session gone — tool executor will surface the error
        except asyncio.CancelledError:
            pass  # normal cancellation when tool finishes

    async def _idle_keepalive(self):
        """
        Persistent, session-wide keepalive — runs the entire time a Gemini
        Live session is open, not just during a tool call.

        WHY: _keepalive_during_tool() only protects the ~10-40s window while
        a slow tool is running. But JARVIS spends the *overwhelming* majority
        of its life in SLEEPING (mic muted, only the local wake-word engine
        is listening) or simply idle between turns — and during all of that
        time _listen_audio()'s callback intentionally sends NOTHING (see
        `audio_allowed` gating), because streaming the user's ambient room
        audio to Gemini while "asleep" would be wrong. That silence is
        exactly what trips the Live API's ~60s no-audio session timeout and
        is the real cause of the "Connection dropped mid-reply" log spam —
        most drops aren't happening mid-reply at all, they're happening
        during ordinary idle gaps and then get discovered the next time the
        user speaks, which *looks* like mid-reply.

        This task pings 100ms of silent PCM every PING_INTERVAL seconds
        whenever nothing else has sent real audio recently, and steps aside
        automatically the instant real audio starts flowing (active
        conversation) so it never competes with or delays genuine input.
        """
        SILENT_CHUNK  = b"\x00\x00" * (SEND_SAMPLE_RATE // 10)  # 100 ms @ 16 kHz, int16
        PING_INTERVAL = 20   # seconds — comfortably under the ~60s silence timeout

        try:
            while True:
                await asyncio.sleep(PING_INTERVAL)
                # Skip the ping if real audio has gone out recently — no need
                # to pile a silent frame on top of a live conversation, and
                # doing so could very slightly muddy timing-sensitive turns.
                if (time.time() - self._last_activity) < PING_INTERVAL:
                    continue
                if self._tool_in_flight:
                    continue  # _keepalive_during_tool() already has this covered
                if not self.session:
                    continue
                try:
                    await self.session.send_realtime_input(
                        media={"data": SILENT_CHUNK, "mime_type": "audio/pcm"}
                    )
                except Exception:
                    pass  # session is gone — the receive/send tasks will surface it
        except asyncio.CancelledError:
            pass  # normal cancellation on session teardown

    async def _thinking_watchdog(self):
        """
        Force-recover if the THINKING label gets stuck with no follow-up.

        WHY: THINKING is a manually-pushed UI label, not a tracked state in
        core/states.py. It's only ever cleared by Gemini's own follow-up —
        set_speaking(True) when output_transcription arrives, or a tool's
        recovery path. If that follow-up never comes (a dropped/empty
        response, a tool that raises before producing speech, a turn that
        Gemini silently swallows), nothing else clears it and the orb sits
        on THINKING forever — exactly what showed up after a plain typed
        "jarvis wake up" with no further reply.

        This runs continuously alongside the other session tasks. Every
        2 seconds it checks how long THINKING has been showing; past the
        timeout, it clears the watchdog flag, drops the UI back to
        LISTENING, and tells the user plainly what happened instead of
        leaving them staring at a frozen orb with no explanation.
        """
        CHECK_INTERVAL = 2     # seconds between checks
        STUCK_TIMEOUT  = 20    # seconds THINKING may show before recovery

        try:
            while True:
                await asyncio.sleep(CHECK_INTERVAL)
                since = self._thinking_since
                if since is None:
                    continue
                if time.time() - since < STUCK_TIMEOUT:
                    continue
                # Stuck — recover.
                self._thinking_since = None
                with self._speaking_lock:
                    self._is_speaking = False
                if self._state_manager.is_shutdown():
                    continue  # don't fight a real shutdown
                self._state_manager.wake()
                if not self.ui.muted:
                    self.ui.set_state("LISTENING")
                self.ui.write_log(
                    "SYS: No reply came back in time, sir — JARVIS is ready "
                    "again. Please repeat your request."
                )
        except asyncio.CancelledError:
            pass  # normal cancellation on session teardown

    # ── Audio streams ────────────────────────────────────────────────────────

    async def _send_realtime(self):
        while True:
            msg = await self.out_queue.get()
            await self.session.send_realtime_input(media=msg)

    async def _listen_audio(self):
        print("[JARVIS] 🎤 Mic started")
        loop = asyncio.get_event_loop()
        diag_state = {
            "last_log": 0.0,
            "sent_count": 0,
            "blocked_count": 0,
            "noise_dropped_count": 0,
        }
        last_level_push = [0.0]

        BARGE_IN_DEBOUNCE_SECS = 0.4  # 400ms debounce
        def callback(indata, frames, time_info, status):
            with self._speaking_lock:
                jarvis_speaking = self._is_speaking
                speaking_since = self._speaking_since
            # Phase 4: only stream audio when LISTENING or ACTIVE_CONVERSATION.
            # SLEEPING and SHUTDOWN states do not send mic audio to Gemini.
            state = self._state_manager.state
            from core.states import JarvisState as _JS
            audio_allowed = state in (_JS.LISTENING, _JS.ACTIVE_CONVERSATION)
            if self._tool_in_flight:
                audio_allowed = False

            now = time.time()

            # ── Phase 2: Barge-in detection during playback ────────────────────────
            # NOTE: Acoustic Echo Cancellation (AEC) limitation:
            # Without hardware or OS-level AEC, acoustic playback from speakers into
            # the microphone can potentially cause false barge-in if speaker volume
            # is very loud. A 400ms debounce ensures initial playback transients do
            # not falsely interrupt, and the calibrated noise floor (280 RMS) requires
            # genuine voice energy to trigger.
            if jarvis_speaking and not self.ui.muted and audio_allowed:
                if speaking_since and (now - speaking_since >= BARGE_IN_DEBOUNCE_SECS):
                    pass_filter, rms = self._mic_filter.process_chunk(indata, now=now)
                    if pass_filter and rms >= self._mic_filter.threshold_rms:
                        # Genuine speech onset detected while speaking -> BARGE IN
                        loop.call_soon_threadsafe(self._interrupt_playback)
                        data = indata.tobytes()
                        self._touch_activity()
                        def add_barge_audio():
                            try:
                                self.out_queue.put_nowait({"data": data, "mime_type": "audio/pcm"})
                            except asyncio.QueueFull:
                                pass
                        loop.call_soon_threadsafe(add_barge_audio)
                        diag_state["sent_count"] += 1
                        return
                diag_state["blocked_count"] += 1
                return

            allowed = not jarvis_speaking and not self.ui.muted and audio_allowed

            if not allowed:
                diag_state["blocked_count"] += 1
                self._mic_filter.reset()
            else:
                # Energy-based VAD pre-filter with hangover
                pass_filter, rms = self._mic_filter.process_chunk(indata, now=now)
                if not pass_filter:
                    diag_state["noise_dropped_count"] += 1
                else:
                    diag_state["sent_count"] += 1
                    data = indata.tobytes()
                    self._touch_activity()
                    def add_audio():
                        try:
                            self.out_queue.put_nowait({"data": data, "mime_type": "audio/pcm"})
                        except asyncio.QueueFull:
                            pass
                    loop.call_soon_threadsafe(add_audio)

                    # Real voice-reactive hologram pulse (gated strictly on speech passing filter)
                    if now - last_level_push[0] > 0.08:
                        try:
                            level = min(1.0, rms / 3000.0)
                            self.ui.set_audio_level(level)
                        except Exception:
                            pass
                        last_level_push[0] = now

                    # Voice emotion — feed raw PCM once per VU update (every ~80ms, speech only)
                    try:
                        self._emotion.feed(data)
                    except Exception:
                        pass

            if now - diag_state["last_log"] > 2.0:
                print(f"[DIAG] mic gate: speaking={jarvis_speaking} muted={self.ui.muted} state={state.name} "
                      f"allowed={allowed} sent={diag_state['sent_count']} blocked={diag_state['blocked_count']} "
                      f"noise_dropped={diag_state['noise_dropped_count']}")
                diag_state["last_log"] = now

        try:
            with sd.InputStream(
                samplerate=SEND_SAMPLE_RATE,
                channels=CHANNELS,
                dtype="int16",
                blocksize=CHUNK_SIZE,
                callback=callback,
            ):
                print("[JARVIS] 🎤 Mic stream open")
                while True:
                    await asyncio.sleep(0.1)
        except Exception as e:
            print(f"[JARVIS] ❌ Mic: {e}")
            raise

    async def _receive_audio(self):
        print("[JARVIS] 👂 Recv started")
        out_buf, in_buf = [], []

        try:
            while True:
                async for response in self.session.receive():

                    # STEADY-CONNECTION FIX (3/3a): capture the resumption handle
                    # every time the server offers one. This is what makes the
                    # SessionResumptionConfig(handle=...) in _build_config()
                    # actually do something on the *next* reconnect. The server
                    # sends this periodically and after meaningful state changes
                    # (not just at the very end), so by the time a drop happens
                    # we almost always already have a recent handle saved.
                    if response.session_resumption_update:
                        sru = response.session_resumption_update
                        if sru.resumable and sru.new_handle:
                            self._resumption_handle = sru.new_handle

                    # STEADY-CONNECTION FIX (3/3b): the Live API warns it's about
                    # to close the connection (quota/maintenance rotation) via a
                    # go_away message with a countdown, instead of just dropping
                    # it. Previously this was never read, so JARVIS only found
                    # out the connection was gone *after* it was gone — an
                    # ungraceful close, mid-reply, with whatever was being said
                    # cut off. Treat go_away as a clean signal to reconnect now
                    # (using the resumption handle above) rather than waiting
                    # for the abrupt failure.
                    if response.go_away:
                        print(f"[JARVIS] ⚠️ Server go_away — {response.go_away.time_left} left, reconnecting proactively.")
                        raise ConnectionResetError("go_away: server requested reconnect")

                    if response.data:
                        self._response_in_progress.set()   # audio streaming = busy
                        # BUGFIX: same QueueFull crash as jarvis_service.pyw —
                        # an unhandled put_nowait() on a full queue used to
                        # kill the whole session and force a reconnect every
                        # time playback fell slightly behind. Drop the oldest
                        # buffered chunk to make room instead of crashing.
                        try:
                            self.audio_in_queue.put_nowait(response.data)
                        except asyncio.QueueFull:
                            try:
                                self.audio_in_queue.get_nowait()
                            except asyncio.QueueEmpty:
                                pass
                            try:
                                self.audio_in_queue.put_nowait(response.data)
                            except asyncio.QueueFull:
                                pass

                    if response.server_content:
                        sc = response.server_content

                        if sc.output_transcription and sc.output_transcription.text:
                            self.set_speaking(True)
                            self._response_in_progress.set()   # block injections
                            txt = sc.output_transcription.text.strip()
                            if txt:
                                out_buf.append(txt)

                        if sc.input_transcription and sc.input_transcription.text:
                            txt = sc.input_transcription.text.strip()
                            if txt:
                                in_buf.append(txt)
                                self._touch_activity()   # any speech = active
                                self._state_manager.begin_conversation()  # LISTENING -> ACTIVE_CONVERSATION

                        if sc.turn_complete:
                            self._response_in_progress.clear()  # allow injections again
                            # BUGFIX (race condition): do NOT clear speaking here.
                            # turn_complete only means Gemini finished sending text/audio
                            # data — it does NOT mean the speaker has finished playing it.
                            # audio_in_queue can still hold several buffered chunks.
                            # Calling set_speaking(False) here re-opens the mic and lets
                            # JARVIS hear its own trailing speech, which the Live API's
                            # VAD reads as a user interruption and cuts the answer off
                            # mid-sentence. _play_audio() now owns clearing this once the
                            # queue is actually empty and playback has finished.

                            full_in = " ".join(in_buf).strip()
                            if full_in:
                                # DEDUP FIX: Gemini echoes typed commands back as
                                # input_transcription — skip logging if that's what this is.
                                if full_in.strip().lower() != self._last_typed_text:
                                    self.ui.write_log(f"You: {full_in}")
                                self._last_typed_text = ""  # consume flag
                            in_buf = []

                            full_out = " ".join(out_buf).strip()
                            if full_out:
                                self.ui.write_log(f"Jarvis: {full_out}")
                            out_buf = []

                            if full_in and len(full_in) > 5:
                                threading.Thread(
                                    target=_update_memory_async,
                                    args=(full_in, full_out or "Acknowledged."),
                                    daemon=True
                                ).start()

                            # Only go SLEEPING after a real user command was FULLY
                            # answered. turn_complete also fires on the interim
                            # "handing off to a tool" turn (e.g. web_search) — that
                            # is NOT the end of the exchange, so check
                            # _tool_in_flight before deciding to sleep.
                            # full_in is empty for the wake-word acknowledgement turn
                            # (JARVIS speaks first, user hasn't said anything yet).
                            if self._tool_in_flight:
                                # Mid-tool-call handoff turn — the real spoken
                                # answer is still coming. Stay active, do NOT sleep
                                # and do NOT touch the UI state (would flicker).
                                pass
                            elif full_in:
                                self._state_manager.sleep()
                                # BUGFIX: the internal state manager went to SLEEPING
                                # but the HUD widget was never told, so the orb could
                                # freeze on whatever label it last had (often a stale
                                # "SPEAKING"/"THINKING" combined with Bug 1 above).
                                self.ui.set_state("SLEEPING")
                                self.ui.write_log("SYS: JARVIS sleeping. Say 'Hey Jarvis' to wake.")
                            else:
                                # Wake ack turn finished - stay LISTENING for the command
                                self.ui.set_state("LISTENING")

                    if response.tool_call:
                        self._tool_in_flight = True
                        try:
                            fn_responses = []
                            for fc in response.tool_call.function_calls:
                                print(f"[JARVIS] 📞 {fc.name}")
                                fr = await self._execute_tool(fc)
                                fn_responses.append(fr)
                            await self.session.send_tool_response(
                                function_responses=fn_responses
                            )
                        finally:
                            self._tool_in_flight = False

        except Exception as e:
            print(f"[JARVIS] ❌ Recv: {e}")
            traceback.print_exc()
            raise

    async def _play_audio(self):
        print("[JARVIS] 🔊 Play started")
        stream = sd.RawOutputStream(
            samplerate=RECEIVE_SAMPLE_RATE,
            channels=CHANNELS,
            dtype="int16",
            blocksize=CHUNK_SIZE,
        )
        stream.start()
        last_level_push = 0.0
        try:
            while True:
                chunk = await self.audio_in_queue.get()
                self.set_speaking(True)

                # PHASE 1 GAP FIX: same real voice-reactive pulse as the mic
                # side, but for JARVIS's own speech — "louder = bigger pulse"
                # should react while JARVIS is talking too, not just while
                # listening. Cheap, throttled, never allowed to break playback.
                now_t = time.time()
                if now_t - last_level_push > 0.08:
                    try:
                        samples = np.frombuffer(chunk, dtype=np.int16).astype(np.float32)
                        if samples.size:
                            rms = float(np.sqrt(np.mean(samples * samples)))
                            level = min(1.0, rms / 3000.0)
                            self.ui.set_audio_level(level)
                    except Exception:
                        pass
                    last_level_push = now_t

                await asyncio.to_thread(stream.write, chunk)

                # BUGFIX (race condition): only reopen the mic once playback has
                # actually caught up with everything Gemini sent. Immediately
                # after a write, more chunks for the SAME reply are usually
                # already queued (or about to be) — only treat this as "JARVIS
                # finished talking" once the queue stays empty for a brief
                # moment. This stops JARVIS hearing its own trailing audio and
                # the Live API's VAD treating that as a user interruption,
                # which was cutting answers off mid-sentence.
                if self.audio_in_queue.empty():
                    await asyncio.sleep(0.35)
                    if self.audio_in_queue.empty():
                        self.set_speaking(False)
        except Exception as e:
            print(f"[JARVIS] ❌ Play: {e}")
            raise
        finally:
            self.set_speaking(False)
            stream.stop()
            stream.close()

    # ── Main run loop ────────────────────────────────────────────────────────

    async def run(self):
        client = genai.Client(
            api_key=_get_api_key(),
            http_options={"api_version": "v1beta"}
        )

        # Start background services
        self._wake_detector.start()
        if _get_gesture_control_enabled():
            self._gesture_engine.start()
        self._briefing_scheduler.start()
        # Calendar reminder — 10-min meeting alerts
        try:
            from core.calendar_intel import CalendarReminder
            self._calendar_reminder = CalendarReminder(
                inject_fn=lambda msg: asyncio.run_coroutine_threadsafe(
                    self._inject_text(msg), self._loop
                ) if self._loop else None,
                bridge=getattr(self, "_proactive_bridge", None),
            )
            self._calendar_reminder.start()
        except Exception as _ce:
            print(f"[Calendar] Reminder skipped: {_ce}")

        self._proactive.start()   # Phase 4: proactive intelligence
        if getattr(self, "_mobile", None):
            try:
                self._mobile.start()   # Phase 7: mobile companion server
            except Exception as _me:
                print(f"[Mobile] Companion server start failed: {_me}")
        # Wire ambient vision glances into ProactiveIntelligence.
        # Fires a silent screen_process("screen") glance every 15 min while
        # JARVIS is idle (LISTENING), so it can offer proactive help unprompted.
        def _ambient_glance():
            from actions.screen_processor import screen_process, warmup_session
            warmup_session(player=self.ui)
            screen_process(
                {"angle": "screen",
                 "text": (
                     "You are doing a quiet ambient check on sir's screen. "
                     "If anything looks like it needs attention (an error, a long wait, "
                     "an obvious task you could help with) mention it very briefly — "
                     "one sentence. If the screen looks completely normal and idle, "
                     "stay silent: respond with exactly the word SKIP and nothing else."
                 )},
                player=self.ui,
            )
        self._proactive.set_vision_fn(_ambient_glance, interval_seconds=900)

        # Begin in SLEEPING state — only the wake-word detector is truly "on"
        # NOTE: StateManager is initialized with SLEEPING so sleep() is a no-op
        # (same-state transitions are rejected). Force the UI label here explicitly
        # so the HUD shows "SLEEPING" on first boot instead of a stale default.
        self._state_manager.sleep()          # no-op if already SLEEPING — that's fine
        self.ui.set_state("SLEEPING")        # push UI label unconditionally on startup
        self.ui.write_log("SYS: JARVIS sleeping. Say 'Hey Jarvis' to wake.")

        # ── Reconnect resilience ────────────────────────────────────────────────
        # Tracks consecutive failed connection attempts so the retry delay backs
        # off instead of hammering the API every flat 3s during an outage (the
        # log showed repeated "timed out during opening handshake" in a row).
        reconnect_attempt = 0
        RECONNECT_BASE_DELAY = 3      # seconds
        RECONNECT_MAX_DELAY  = 30     # seconds

        # Whether the PREVIOUS session died while JARVIS was actively mid-reply
        # (speaking or streaming a response). Must be captured at the moment of
        # failure — set_speaking(False) at the bottom of each loop pass clears
        # _is_speaking, so reading it at the top of the next iteration would
        # always see False. False on the very first pass (clean startup).
        was_mid_reply = False

        while True:
            # ── Phase 4: SHUTDOWN is terminal — stop the run loop ──────────
            if self._state_manager.is_shutdown() or self._shutdown_event.is_set():
                print("[JARVIS] 🔴 SHUTDOWN state — exiting run loop.")
                return   # cleanly exits the coroutine; os._exit called by tool

            tasks = []
            try:
                resuming = self._resumption_handle is not None
                print(f"[JARVIS] 🔌 Connecting{' (resuming previous session)' if resuming else ''}...")
                if not was_mid_reply:
                    self.ui.set_state("THINKING")
                config = self._build_config()

                async with client.aio.live.connect(model=LIVE_MODEL, config=config) as session:
                    self.session = session
                    self._loop   = asyncio.get_event_loop()
                    self.audio_in_queue = asyncio.Queue(maxsize=300)
                    self.out_queue      = asyncio.Queue(maxsize=100)

                    print("[JARVIS] ✅ Connected.")
                    reconnect_attempt = 0   # reset backoff after a successful connect

                    if was_mid_reply:
                        # BUGFIX: the previous session was cut off while JARVIS was
                        # still talking (e.g. mid-briefing). Don't force SLEEPING —
                        # that hides the interruption and silently drops the rest
                        # of the answer. Let the user know what happened and stay
                        # LISTENING so they can simply ask again right away.
                        self._state_manager.wake()
                        self.ui.set_state("LISTENING")
                        self.ui.write_log(
                            "SYS: Connection dropped mid-reply and was restored. "
                            "Say 'Hey Jarvis' or repeat your request if it cut off."
                        )
                        was_mid_reply = False
                    else:
                        # Clean reconnect (first boot, or we were already idle) —
                        # safe to force SLEEPING as before.
                        self._state_manager.sleep()
                        self.ui.set_state("SLEEPING")
                        self.ui.write_log("SYS: JARVIS online — sleeping. Say 'Hey Jarvis' to activate.")
                        self.ui.write_log("SYS: Shutdown = permanent off | Sleep = temporary (wake word restarts)")
                        self.ui.write_log("SYS: Wake word: 'Hey Jarvis' | Auto-briefings: enabled")

                    # Python 3.10-compatible: use asyncio.gather instead of TaskGroup
                    tasks = [
                        asyncio.ensure_future(self._send_realtime()),
                        asyncio.ensure_future(self._listen_audio()),
                        asyncio.ensure_future(self._receive_audio()),
                        asyncio.ensure_future(self._play_audio()),
                        asyncio.ensure_future(self._thinking_watchdog()),
                        asyncio.ensure_future(self._idle_keepalive()),
                    ]
                    # Wait until any task raises (session drop, mic error, etc.)
                    done, pending = await asyncio.wait(
                        tasks, return_when=asyncio.FIRST_EXCEPTION
                    )
                    # Cancel remaining tasks cleanly
                    for t in pending:
                        t.cancel()
                    # Re-raise the first exception so the outer handler logs it
                    for t in done:
                        if not t.cancelled() and t.exception():
                            raise t.exception()

            except Exception as e:
                # If shutdown was triggered during this session, stop cleanly
                if self._state_manager.is_shutdown():
                    print("[JARVIS] 🔴 Session ended due to SHUTDOWN.")
                    return
                print(f"[JARVIS] ⚠️ {e}")
                traceback.print_exc()
                # BUGFIX: capture mid-reply status NOW, before set_speaking(False)
                # below resets it, so the next connection attempt knows whether
                # this drop interrupted an active answer.
                was_mid_reply = self._response_in_progress.is_set() or self._is_speaking
                # Cancel any still-running tasks from this session
                for t in tasks:
                    if not t.done():
                        t.cancel()
            else:
                # Loop body exited the `async with` without an exception only
                # via the explicit `raise` re-propagation above, so this branch
                # is effectively unreachable — kept for clarity/safety only.
                was_mid_reply = False

            self.session = None
            self.set_speaking(False)

            # Do NOT reconnect if we're in SHUTDOWN
            if self._state_manager.is_shutdown() or self._shutdown_event.is_set():
                print("[JARVIS] 🔴 SHUTDOWN — not reconnecting.")
                return

            if not was_mid_reply:
                self.ui.set_state("THINKING")
            # BUGFIX: exponential backoff (capped) instead of a flat 3s retry,
            # so a real outage (repeated handshake timeouts, as seen in the log)
            # doesn't hammer the API in a tight loop.
            reconnect_attempt += 1
            delay = min(RECONNECT_BASE_DELAY * (2 ** (reconnect_attempt - 1)), RECONNECT_MAX_DELAY)
            print(f"[JARVIS] 🔄 Reconnecting in {delay}s... (attempt {reconnect_attempt})")
            await asyncio.sleep(delay)


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    from core.integrity_monitor import verify_on_startup
    if not verify_on_startup():
        print("[Startup] 🚨 CODEBASE INTEGRITY VERIFICATION FAILED. Refusing to start JARVIS.")
        sys.exit(1)

    ui = JarvisUI("face.png")

    def runner():
        ui.wait_for_api_key()
        jarvis = JarvisLive(ui)
        try:
            asyncio.run(jarvis.run())
        except KeyboardInterrupt:
            print("\n🔴 JARVIS shutting down...")
        except Exception as e:
            # BUGFIX: this only used to catch KeyboardInterrupt. Any other
            # exception raised anywhere in run() (e.g. the wake-word model
            # load failure that used to crash here before model loading was
            # hardened in WakeWordEngine.start()) used to kill this daemon
            # thread completely silently — the PyQt window on the main
            # thread kept running and looked perfectly normal, but the
            # entire backend (wake word, Gemini session, mic) was dead,
            # with zero indication to the user. Surface it now instead.
            traceback.print_exc()
            try:
                ui.write_log(
                    f"SYS: ⚠️ JARVIS backend crashed unexpectedly "
                    f"({type(e).__name__}: {e}). Please restart the app."
                )
            except Exception:
                pass  # UI itself may be in a bad state — at least we printed above

    threading.Thread(target=runner, daemon=True).start()
    ui.root.mainloop()


if __name__ == "__main__":
    main()