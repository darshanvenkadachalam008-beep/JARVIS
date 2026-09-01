"""
core/proactive_intelligence.py — Phase 4: Proactive Intelligence
=================================================================
Provides four proactive capabilities that JARVIS can use to help the user
without being asked, while strictly respecting three rules:

  1. Never perform actions without confirmation.
  2. Never interrupt an ACTIVE_CONVERSATION.
  3. Reuse the existing memory system (memory/memory_manager.py).

Modules
-------
PatternDetector   — mines memory["habits"] for time-based patterns and
                    surfaces suggestions ("You usually check emails at 9 AM").
ReminderScanner   — scans memory["notes"] and memory["relationships"] for
                    pending commitments ("You mentioned calling mum on Monday").
MorningBriefing   — assembles an optional daily briefing from tasks, reminders,
                    and memory["goals"]; triggered after wake-word in the morning.
WeatherIntelligence — cross-references weather data with context from memory
                    to surface smart warnings ("Rain at 3 PM, you have a meeting").
NewsDigest        — personalised news summary from memory["preferences"] topics;
                    only generated when explicitly requested or opted-in.

All public methods return plain strings that JarvisLive can inject into the
Gemini session via send_client_content, or log as proactive suggestions.

Usage (from main.py) ────────────────────────────────────────────────────────
    from core.proactive_intelligence import ProactiveIntelligence

    pi = ProactiveIntelligence(
        get_state  = lambda: state_manager.state,
        speak_fn   = jarvis.speak,           # injects text into live session
        log_fn     = ui.write_log,
    )
    pi.start()          # starts background polling thread
    pi.stop()           # called on SHUTDOWN
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Optional
import sys

# ── local imports ─────────────────────────────────────────────────────────────
from memory.memory_manager import load_memory


# ─────────────────────────────────────────────────────────────────────────────
#  Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _now_str() -> str:
    return datetime.now().strftime("%H:%M")


def _today_str() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def _weekday_name() -> str:
    return datetime.now().strftime("%A")   # e.g. "Monday"


def _hour_now() -> int:
    return datetime.now().hour


def _minute_now() -> int:
    return datetime.now().minute


# ─────────────────────────────────────────────────────────────────────────────
#  Pattern Detector
# ─────────────────────────────────────────────────────────────────────────────

class PatternDetector:
    """
    Mines memory["habits"] for time-of-day patterns and surfaces a suggestion
    once per day when that time arrives (+/- 10-minute window).

    Example habit entry in long_term.json:
        "habits": {
            "morning_email": {
                "value": "Usually checks emails at 9 AM on weekdays",
                "updated": "2026-06-01"
            }
        }

    The detector looks for time references like "9 AM", "09:00", "3 PM" in
    the value string and triggers when the system clock is within 10 minutes
    of that time.
    """

    _TIME_KEYWORDS = [
        "AM", "PM", ":00", ":30", "morning", "evening", "night",
        "afternoon", "midnight", "noon", "lunchtime",
    ]

    # Approximate hour ranges for fuzzy time words
    _FUZZY_HOURS: dict[str, range] = {
        "morning":   range(6,  12),
        "noon":      range(11, 13),
        "lunchtime": range(12, 14),
        "afternoon": range(13, 18),
        "evening":   range(18, 22),
        "night":     range(20, 24),
        "midnight":  range(23, 25),
    }

    def __init__(self):
        self._fired_today: set[str] = set()

    def tick(self) -> Optional[str]:
        """
        Call every minute.  Returns a suggestion string if a habit pattern
        matches the current time, or None.
        """
        today = _today_str()
        # Reset daily tracking at midnight
        fire_key_prefix = today + ":"

        memory = load_memory()
        habits = memory.get("habits", {})
        h_now  = _hour_now()
        m_now  = _minute_now()

        for key, entry in habits.items():
            if not isinstance(entry, dict):
                continue
            value = entry.get("value", "")
            if not any(kw.lower() in value.lower() for kw in self._TIME_KEYWORDS):
                continue

            fire_key = f"{fire_key_prefix}{key}"
            if fire_key in self._fired_today:
                continue

            if self._matches_now(value, h_now, m_now):
                self._fired_today.add(fire_key)
                return (
                    f"[PROACTIVE PATTERN] I've noticed a pattern: {value}. "
                    f"Would you like me to prepare that for you now, sir? "
                    f"Please confirm before I take any action."
                )
        return None

    def reset_daily(self):
        """Call at midnight to clear fired-today cache."""
        self._fired_today.clear()

    # ── private ──────────────────────────────────────────────────────────

    def _matches_now(self, text: str, h: int, m: int) -> bool:
        """Return True if text contains a time reference ≈ current time."""
        import re

        # Match "9 AM", "9:30 AM", "09:00"
        for match in re.finditer(r'(\d{1,2})(?::(\d{2}))?\s*(AM|PM)', text, re.IGNORECASE):
            hour = int(match.group(1))
            minute = int(match.group(2) or 0)
            meridiem = match.group(3).upper()
            if meridiem == "PM" and hour != 12:
                hour += 12
            elif meridiem == "AM" and hour == 12:
                hour = 0
            if abs(h * 60 + m - (hour * 60 + minute)) <= 10:
                return True

        # Match 24h "14:00"
        for match in re.finditer(r'\b(\d{1,2}):(\d{2})\b', text):
            hour = int(match.group(1))
            minute = int(match.group(2))
            if 0 <= hour <= 23 and abs(h * 60 + m - (hour * 60 + minute)) <= 10:
                return True

        # Fuzzy words
        text_lower = text.lower()
        for word, hour_range in self._FUZZY_HOURS.items():
            if word in text_lower and h in hour_range and m < 15:
                return True

        return False


# ─────────────────────────────────────────────────────────────────────────────
#  Reminder Scanner
# ─────────────────────────────────────────────────────────────────────────────

class ReminderScanner:
    """
    Scans memory["notes"] and memory["relationships"] for commitment keywords
    and surfaces them once per day if the day/time context matches.

    Keywords: "call", "text", "email", "meet", "remind", "don't forget",
              "need to", "have to", "should", "appointment", "deadline".
    """

    _COMMITMENT_KEYWORDS = [
        "call", "ring", "text", "message", "email", "meet", "meeting",
        "remind", "don't forget", "do not forget", "need to", "have to",
        "should", "appointment", "deadline", "follow up",
    ]

    _DAY_NAMES = [
        "monday", "tuesday", "wednesday", "thursday",
        "friday", "saturday", "sunday", "today", "tomorrow",
    ]

    def __init__(self):
        self._fired_today: set[str] = set()

    def tick(self) -> Optional[str]:
        """
        Returns a reminder string if any stored note/relationship contains a
        commitment referencing the current day, or None.
        """
        today = _today_str()
        fire_key_prefix = today + ":"
        today_weekday   = _weekday_name().lower()
        tomorrow_dt     = datetime.now() + timedelta(days=1)
        tomorrow_weekday = tomorrow_dt.strftime("%A").lower()

        memory = load_memory()
        candidates: list[tuple[str, str, str]] = []  # (category, key, value)

        for category in ("notes", "relationships", "goals", "wishes"):
            section = memory.get(category, {})
            for key, entry in section.items():
                if not isinstance(entry, dict):
                    continue
                value = entry.get("value", "")
                value_lower = value.lower()

                # Must contain a commitment keyword
                if not any(kw in value_lower for kw in self._COMMITMENT_KEYWORDS):
                    continue

                # Must reference today, tomorrow, or a matching weekday
                has_day_ref = (
                    "today" in value_lower
                    or "tomorrow" in value_lower
                    or today_weekday in value_lower
                    or tomorrow_weekday in value_lower
                )
                if not has_day_ref:
                    continue

                candidates.append((category, key, value))

        if not candidates:
            return None

        # Deduplicate and fire one reminder at a time
        for category, key, value in candidates:
            fire_key = f"{fire_key_prefix}{category}:{key}"
            if fire_key in self._fired_today:
                continue
            self._fired_today.add(fire_key)
            return (
                f"[PROACTIVE REMINDER] Sir, you previously mentioned: \"{value}\". "
                f"Would you like me to help with that now? "
                f"Just confirm and I'll take care of it."
            )
        return None

    def reset_daily(self):
        self._fired_today.clear()


# ─────────────────────────────────────────────────────────────────────────────
#  Morning Briefing Builder
# ─────────────────────────────────────────────────────────────────────────────

class MorningBriefing:
    """
    Assembles a morning briefing text from memory when the user says the wake
    word between 06:00 and 10:00 AM.  The briefing is only offered, never
    forced — JARVIS asks if the user wants it.

    Call offer() right after a wake-word event to get the offer string (or
    None if it's not morning, or the briefing was already offered today).
    Call build() to construct the full briefing text from memory.
    """

    _BRIEFING_WINDOW = range(6, 10)   # 06:00–09:59

    def __init__(self):
        self._offered_today: Optional[str] = None   # date string

    def offer(self) -> Optional[str]:
        """
        Returns an offer string if it's morning and we haven't offered yet
        today, otherwise None.
        """
        if _hour_now() not in self._BRIEFING_WINDOW:
            return None
        today = _today_str()
        if self._offered_today == today:
            return None
        self._offered_today = today
        return (
            "[MORNING BRIEFING OFFER] Good morning, sir. Would you like your "
            "morning briefing? I can cover your goals, reminders, and any pending "
            "tasks. Just say 'Yes, give me the briefing' to proceed."
        )

    def build(self) -> str:
        """
        Builds the full briefing from memory.  Call this when the user says
        yes to the offer.  Returns a prompt string to inject into the session.
        """
        memory  = load_memory()
        now_str = datetime.now().strftime("%A, %d %B %Y, %H:%M")

        sections: list[str] = [
            f"[MORNING BRIEFING] Current time: {now_str}.",
        ]

        # Goals
        goals = memory.get("goals", {})
        if goals:
            goal_items = [
                entry.get("value", "") for entry in goals.values()
                if isinstance(entry, dict) and entry.get("value")
            ]
            if goal_items:
                sections.append(
                    "Active goals: " + "; ".join(goal_items[:5]) + "."
                )

        # Pending commitments from notes
        notes = memory.get("notes", {})
        commitment_keywords = ["need to", "should", "call", "meet", "deadline", "appointment"]
        commitments = [
            entry.get("value", "") for entry in notes.values()
            if isinstance(entry, dict)
            and any(kw in entry.get("value", "").lower() for kw in commitment_keywords)
        ]
        if commitments:
            sections.append(
                "Pending items: " + "; ".join(commitments[:5]) + "."
            )

        # Relationships — anyone mentioned recently
        relationships = memory.get("relationships", {})
        if relationships:
            people = [
                f"{k}: {e.get('value', '')}"
                for k, e in relationships.items()
                if isinstance(e, dict) and e.get("value")
            ]
            if people:
                sections.append(
                    "People context: " + "; ".join(people[:3]) + "."
                )

        sections.append(
            "Please deliver this as a concise, personalised morning briefing "
            "in JARVIS style. Do not take any actions — just inform, sir."
        )

        return " ".join(sections)


# ─────────────────────────────────────────────────────────────────────────────
#  Weather Intelligence
# ─────────────────────────────────────────────────────────────────────────────

class WeatherIntelligence:
    """
    Wraps the existing weather_action to add context-awareness.
    If memory contains schedule/appointment data and weather is bad, it
    surfaces a targeted warning.

    Call check() — returns a warning string or None.
    Fires at most once per hour to avoid spamming.
    """

    def __init__(self, weather_action_fn: Callable):
        self._weather_fn  = weather_action_fn
        self._last_check  = 0.0
        self._check_interval = 3600   # 1 hour

    def check(self, city: str = "") -> Optional[str]:
        """
        Runs a weather check and cross-references memory for schedule context.
        Returns a warning prompt string, or None if nothing notable.
        """
        now = time.time()
        if now - self._last_check < self._check_interval:
            return None
        self._last_check = now

        if not city:
            # Try to get city from memory
            memory = load_memory()
            identity = memory.get("identity", {})
            for key, entry in identity.items():
                if isinstance(entry, dict) and "city" in key.lower():
                    city = entry.get("value", "")
                    break

        if not city:
            return None

        try:
            weather_raw = self._weather_fn({"city": city})
        except Exception as e:
            print(f"[WeatherIntel] ⚠️ {e}")
            return None

        if not weather_raw:
            return None

        weather_lower = weather_raw.lower()
        bad_weather   = any(w in weather_lower for w in [
            "rain", "storm", "thunder", "snow", "hail", "fog",
            "hurricane", "flood", "drizzle", "showers",
        ])
        if not bad_weather:
            return None

        # Cross-reference with memory for schedule context
        memory = load_memory()
        schedule_context = ""
        today_weekday = _weekday_name().lower()

        for category in ("notes", "goals"):
            for entry in memory.get(category, {}).values():
                if not isinstance(entry, dict):
                    continue
                value = entry.get("value", "")
                if any(w in value.lower() for w in ["meeting", "appointment", "outside", "drive", "trip", "go to"]):
                    if today_weekday in value.lower() or "today" in value.lower():
                        schedule_context = value
                        break

        if schedule_context:
            return (
                f"[WEATHER ALERT] Sir, weather check for {city}: {weather_raw.strip()}. "
                f"This may affect your plans: \"{schedule_context}\". "
                f"Would you like me to help you prepare? I won't take any action without confirmation."
            )
        else:
            return (
                f"[WEATHER ALERT] Sir, heads-up: {weather_raw.strip()} for {city} today. "
                f"Shall I factor this into your plans?"
            )


# ─────────────────────────────────────────────────────────────────────────────
#  News Digest
# ─────────────────────────────────────────────────────────────────────────────

class NewsDigest:
    """
    Generates a personalised news summary prompt based on memory["preferences"].
    Only fires when:
      - The user explicitly requests it ("news", "what's happening today"), OR
      - news_auto_enabled is True in bi_data.json.

    Call build() to get the Gemini prompt string.
    """

    def build(self) -> str:
        memory      = load_memory()
        preferences = memory.get("preferences", {})

        topics: list[str] = []
        for entry in preferences.values():
            if isinstance(entry, dict):
                val = entry.get("value", "")
                # Only include preference values that look like topics/interests
                if any(kw in val.lower() for kw in [
                    "interested", "like", "love", "follow", "fan of",
                    "hobby", "interest", "topic", "news", "tech", "sport",
                    "music", "science", "business", "finance",
                ]):
                    topics.append(val)

        topic_str = (
            "focusing on: " + ", ".join(topics[:5])
            if topics else "covering general top stories"
        )

        return (
            f"[PERSONALISED NEWS REQUEST] Sir has asked for a news summary. "
            f"Please search the web for today's most important headlines, "
            f"{topic_str}. Keep it concise — 3 to 5 bullet points. "
            f"Do not open any apps or tabs without confirmation."
        )


# ─────────────────────────────────────────────────────────────────────────────
#  Main coordinator
# ─────────────────────────────────────────────────────────────────────────────

class ProactiveIntelligence:
    """
    Background coordinator that polls pattern/reminder detectors every 60 s
    and injects suggestions into JARVIS via speak_fn when appropriate.

    Parameters
    ----------
    get_state   : callable returning current JarvisState
    speak_fn    : callable(str) — injects text into the live Gemini session
    log_fn      : callable(str) — writes to the HUD log
    weather_fn  : optional callable({city}) → str for weather checks
    city        : user's city (can also be read from memory automatically)
    """

    def __init__(
        self,
        get_state: Callable,
        speak_fn:  Callable[[str], None],
        log_fn:    Callable[[str], None],
        weather_fn: Optional[Callable] = None,
        city: str = "",
    ):
        from core.states import JarvisState   # local to avoid circular at module level

        self._JarvisState  = JarvisState
        self._get_state    = get_state
        self._speak        = speak_fn
        self._log          = log_fn

        self._pattern_detector  = PatternDetector()
        self._reminder_scanner  = ReminderScanner()
        self._morning_briefing  = MorningBriefing()
        self._weather_intel     = WeatherIntelligence(weather_fn) if weather_fn else None
        self._news_digest       = NewsDigest()
        self._city              = city

        self._running  = False
        self._thread:  Optional[threading.Thread] = None
        self._last_day = _today_str()

        # Weather check: every hour but only during waking hours
        self._last_weather_check = 0.0
        self._WEATHER_INTERVAL   = 3600

        # Ambient vision glances — passive screen check every ~15 min
        # Only fires during LISTENING (idle), never during conversation.
        self._vision_fn:         Optional[Callable] = None  # set via set_vision_fn()
        self._last_vision_glance = 0.0
        self._VISION_INTERVAL    = 900  # 15 minutes default
        self._vision_enabled     = False

    # ── lifecycle ──────────────────────────────────────────────────────────

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._loop, daemon=True, name="ProactiveIntelligence")
        self._thread.start()
        print("[Proactive] 🧠 Proactive Intelligence started")

    def stop(self):
        self._running = False
        print("[Proactive] 🛑 Proactive Intelligence stopped")

    # ── called externally ─────────────────────────────────────────────────

    def on_wake_word(self):
        """
        Called by JarvisLive when the wake word fires.
        Offers a morning briefing if appropriate.
        """
        offer = self._morning_briefing.offer()
        if offer:
            self._inject(offer)

    def notify(self, msg: str):
        """
        BUGFIX: jarvis_service.pyw's Phase 7 mobile wiring does
        `_orig_notify = self._proactive.notify` and wraps it to also push
        to the phone — but this method never existed here, so that
        lookup raised AttributeError every time (silently swallowed by
        the bare `except Exception: pass` around it), meaning mobile
        push notifications from proactive intelligence never actually
        fired. This is the local-log half of a proactive notification;
        write_log here, and let jarvis_service.pyw's wrapper add the
        mobile broadcast on top, exactly as it already assumes.
        """
        self._log(f"NOTIFY: {msg}")

    def get_morning_briefing(self) -> str:
        """Returns the full morning briefing prompt (call when user confirms)."""
        return self._morning_briefing.build()

    def get_news_digest(self) -> str:
        """Returns the personalised news prompt."""
        return self._news_digest.build()

    # ── internal loop ─────────────────────────────────────────────────────

    def _loop(self):
        while self._running:
            try:
                self._tick()
            except Exception as e:
                print(f"[Proactive] ⚠️ tick error: {e}")
            time.sleep(60)

    def _tick(self):
        # Midnight reset
        today = _today_str()
        if today != self._last_day:
            self._last_day = today
            self._pattern_detector.reset_daily()
            self._reminder_scanner.reset_daily()

        # Only fire proactive hints when JARVIS is not mid-conversation
        if not self._can_interrupt():
            return

        # 1. Pattern detection
        pattern_msg = self._pattern_detector.tick()
        if pattern_msg:
            self._inject(pattern_msg)
            return   # one hint per minute max

        # 2. Reminder scan
        reminder_msg = self._reminder_scanner.tick()
        if reminder_msg:
            self._inject(reminder_msg)
            return

        # 3. Weather intelligence (once per hour, during waking hours 7–22)
        if self._weather_intel and 7 <= _hour_now() <= 22:
            now = time.time()
            if now - self._last_weather_check >= self._WEATHER_INTERVAL:
                self._last_weather_check = now
                weather_msg = self._weather_intel.check(self._city)
                if weather_msg:
                    self._inject(weather_msg)

        # 4. Ambient vision glance (passive screen check while idle)
        #    Only fires when LISTENING — never during ACTIVE_CONVERSATION.
        if (self._vision_enabled
                and self._vision_fn is not None
                and 7 <= _hour_now() <= 23):  # daytime hours only
            now = time.time()
            if now - self._last_vision_glance >= self._VISION_INTERVAL:
                self._last_vision_glance = now
                try:
                    self._log("[Proactive] 👁️  Ambient glance firing…")
                    self._vision_fn()
                except Exception as _ve:
                    print(f"[Proactive] ⚠️ Vision glance error: {_ve}")

    def set_vision_fn(self, fn: Callable, interval_seconds: int = 900):
        """Register the ambient vision glance callback.

        fn() is called with no args; it should trigger a non-blocking
        screen glance via screen_processor.screen_process().
        interval_seconds: minimum gap between glances (default 15 min).
        """
        self._vision_fn       = fn
        self._VISION_INTERVAL = max(120, interval_seconds)  # floor at 2 min
        self._vision_enabled  = True
        print(f"[Proactive] 👁️  Ambient vision glances enabled ({self._VISION_INTERVAL}s interval)")

    def set_vision_enabled(self, enabled: bool):
        """Pause/resume vision glances without unregistering the callback."""
        self._vision_enabled = enabled

    def _can_interrupt(self) -> bool:
        """True when the state machine allows proactive hints."""
        try:
            state = self._get_state()
            return state not in (
                self._JarvisState.ACTIVE_CONVERSATION,
                self._JarvisState.SHUTDOWN,
                self._JarvisState.SLEEPING,
            )
        except Exception:
            return False

    def _inject(self, text: str):
        """Send proactive text into the Gemini session."""
        self._log(f"PROACTIVE: {text[:120]}…" if len(text) > 120 else f"PROACTIVE: {text}")
        try:
            self._speak(text)
        except Exception as e:
            print(f"[Proactive] ⚠️ inject failed: {e}")