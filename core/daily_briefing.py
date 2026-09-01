"""
core/daily_briefing.py — Proactive daily briefing
=====================================================
Ties together three things that already exist separately in this codebase
into one proactive morning summary: today's calendar, today's weather, and
an overnight security recap. This is the "personal assistant" counterpart
to the security upgrades — it's the thing that makes Mark feel like it's
looking out for you before you ask, instead of only reacting to commands.

Data sources
------------
- Calendar : core.calendar_intel.get_today_summary() — reuses your existing
  Google Calendar integration as-is. If it's not configured, that section
  is simply omitted (not an error).
- Weather  : Open-Meteo (https://open-meteo.com) — free, no API key
  required. Location comes from core.sentinel_extras.geoip_lookup() (same
  IP-geolocation already used by the intrusion sentinel) unless you set
  fixed coordinates in the vault/config (briefing_latitude/briefing_longitude).
- Security : core.sentinel_extras.AlertHistory.recent() filtered to the
  overnight window, plus core.audit_log.AuditLog().verify() so the
  briefing tells you plainly if the security log's integrity check failed
  — which is exactly the kind of thing a good assistant should lead with,
  not bury.

Usage
-----
    from core.daily_briefing import build_daily_briefing

    briefing = build_daily_briefing(gemini_api_key=my_key)  # gemini_api_key optional
    print(briefing["text"])       # ready-to-speak/display summary
    print(briefing["sections"])   # structured dict if you want to render it differently

To run it automatically every morning:

    from core.daily_briefing import DailyBriefingScheduler

    def on_ready(text: str):
        speak(text)          # hook into your existing TTS call
        push_to_mobile(text) # hook into mobile_server's FCM pusher

    sched = DailyBriefingScheduler(hour=7, minute=30, callback=on_ready)
    sched.start()
"""
from __future__ import annotations

import json
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Optional


def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


def _load_config() -> dict:
    try:
        path = _base_dir() / "config" / "api_keys.json"
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


# ── Weather ──────────────────────────────────────────────────────────────

_WEATHER_CODES = {
    0: "clear sky", 1: "mostly clear", 2: "partly cloudy", 3: "overcast",
    45: "fog", 48: "depositing rime fog",
    51: "light drizzle", 53: "drizzle", 55: "dense drizzle",
    61: "light rain", 63: "rain", 65: "heavy rain",
    71: "light snow", 73: "snow", 75: "heavy snow",
    80: "light rain showers", 81: "rain showers", 82: "violent rain showers",
    95: "thunderstorm", 96: "thunderstorm with hail", 99: "severe thunderstorm with hail",
}


def get_weather_summary(lat: Optional[float] = None, lon: Optional[float] = None) -> Optional[dict]:
    """Returns today's high/low, current conditions, and precipitation chance.
    Returns None (not an exception) if location or the API is unavailable —
    a briefing should degrade gracefully, not crash, when weather is missing."""
    if lat is None or lon is None:
        cfg = _load_config()
        lat = lat or cfg.get("briefing_latitude")
        lon = lon or cfg.get("briefing_longitude")

    if lat is None or lon is None:
        try:
            from core.sentinel_extras import geoip_lookup
            geo = geoip_lookup()
            if geo:
                lat, lon = geo.get("lat"), geo.get("lon")
        except Exception:
            pass

    if lat is None or lon is None:
        return None

    url = (
        "https://api.open-meteo.com/v1/forecast"
        f"?latitude={lat}&longitude={lon}"
        "&current_weather=true"
        "&daily=temperature_2m_max,temperature_2m_min,precipitation_probability_max"
        "&timezone=auto"
    )
    try:
        with urllib.request.urlopen(url, timeout=8) as resp:
            data = json.loads(resp.read().decode())
        current = data.get("current_weather", {})
        daily = data.get("daily", {})
        code = current.get("weathercode")
        return {
            "condition": _WEATHER_CODES.get(code, "unknown conditions"),
            "current_temp_c": current.get("temperature"),
            "high_c": (daily.get("temperature_2m_max") or [None])[0],
            "low_c": (daily.get("temperature_2m_min") or [None])[0],
            "precip_chance_pct": (daily.get("precipitation_probability_max") or [None])[0],
        }
    except (urllib.error.URLError, Exception) as e:
        print(f"[DailyBriefing] Weather fetch failed: {e}")
        return None


# ── Calendar ─────────────────────────────────────────────────────────────

def get_calendar_summary() -> Optional[str]:
    try:
        from core.calendar_intel import get_today_summary
        return get_today_summary()
    except Exception as e:
        print(f"[DailyBriefing] Calendar unavailable: {e}")
        return None


# ── Security recap ──────────────────────────────────────────────────────

def get_security_summary(hours: int = 12) -> dict:
    """Overnight security recap: how many alerts fired, of what kind, and
    whether the tamper-evident audit log still checks out clean."""
    summary = {"alert_count": 0, "alerts": [], "audit_log_ok": True, "audit_log_problem": None}
    try:
        from core.sentinel_extras import AlertHistory
        cutoff = datetime.now() - timedelta(hours=hours)
        recent = AlertHistory.recent(50)
        for item in recent:
            try:
                ts = datetime.strptime(item.get("ts", ""), "%Y-%m-%d %H:%M:%S")
            except Exception:
                continue
            if ts >= cutoff:
                summary["alerts"].append(item)
        summary["alert_count"] = len(summary["alerts"])
    except Exception as e:
        print(f"[DailyBriefing] AlertHistory unavailable: {e}")

    try:
        from core.audit_log import AuditLog
        ok, problem = AuditLog().verify()
        summary["audit_log_ok"] = ok
        summary["audit_log_problem"] = problem
    except Exception as e:
        print(f"[DailyBriefing] AuditLog verify unavailable: {e}")

    return summary


# ── Composition ──────────────────────────────────────────────────────────

def _compose_text_fallback(sections: dict) -> str:
    """Simple templated narration — used when no Gemini key is available,
    or as a fast, dependency-free default. No external calls."""
    parts = [f"Good morning. Here's your briefing for {datetime.now().strftime('%A, %B %d')}."]

    weather = sections.get("weather")
    if weather:
        parts.append(
            f"Weather: {weather['condition']}, currently {weather.get('current_temp_c')}\u00b0C, "
            f"with a high of {weather.get('high_c')}\u00b0C and low of {weather.get('low_c')}\u00b0C. "
            f"Precipitation chance: {weather.get('precip_chance_pct')}%."
        )
    else:
        parts.append("Weather: unavailable right now.")

    calendar = sections.get("calendar")
    parts.append(f"Calendar: {calendar}" if calendar else "Calendar: nothing on it, or not connected.")

    sec = sections["security"]
    if not sec["audit_log_ok"]:
        parts.append(f"⚠️ Security: the audit log integrity check FAILED — {sec['audit_log_problem']} Please review immediately.")
    elif sec["alert_count"] == 0:
        parts.append("Security: quiet overnight — no alerts.")
    else:
        kinds = ", ".join(sorted({a.get("event_type", "?") for a in sec["alerts"]}))
        parts.append(f"Security: {sec['alert_count']} alert(s) overnight ({kinds}). Check the alert history for details.")

    return " ".join(parts)


def _compose_text_gemini(sections: dict, api_key: str) -> Optional[str]:
    """Optional richer narration via the same Gemini key the rest of the app
    already uses. Falls back to the templated version on any failure."""
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-2.5-flash")
        prompt = (
            "You are a personal assistant giving a short spoken morning briefing. "
            "In 3-5 natural sentences, summarize this data for the user. Be warm but "
            "concise, and if there's a security concern, mention it plainly and first.\n\n"
            f"Data: {json.dumps(sections, default=str)}"
        )
        resp = model.generate_content(prompt)
        text = (resp.text or "").strip()
        return text or None
    except Exception as e:
        print(f"[DailyBriefing] Gemini narration failed, using template: {e}")
        return None


def build_daily_briefing(gemini_api_key: Optional[str] = None,
                          lat: Optional[float] = None,
                          lon: Optional[float] = None) -> dict:
    sections = {
        "weather": get_weather_summary(lat, lon),
        "calendar": get_calendar_summary(),
        "security": get_security_summary(),
        "generated_at": datetime.now().isoformat(),
    }

    text = None
    if gemini_api_key:
        text = _compose_text_gemini(sections, gemini_api_key)
    if not text:
        text = _compose_text_fallback(sections)

    try:
        from core.audit_log import AuditLog
        AuditLog().append("daily_briefing_generated", {"alert_count": sections["security"]["alert_count"]})
    except Exception:
        pass

    return {"text": text, "sections": sections}


# ── Scheduler ────────────────────────────────────────────────────────────

class DailyBriefingScheduler:
    """Fires `callback(text)` once per day at hour:minute local time.
    Follows the same lightweight threading.Event poll pattern as the other
    monitors in core/sentinel_extras.py (BatteryMonitor, WifiGeofenceMonitor)
    rather than adding a new scheduling dependency."""

    def __init__(self, hour: int = 7, minute: int = 30,
                 callback: Optional[Callable[[str], None]] = None,
                 gemini_api_key: Optional[str] = None,
                 poll_interval: float = 30.0):
        self._hour = hour
        self._minute = minute
        self._callback = callback
        self._gemini_key = gemini_api_key
        self._poll = poll_interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_run_date: Optional[str] = None

    def start(self):
        self._thread = threading.Thread(target=self._loop, daemon=True, name="DailyBriefingScheduler")
        self._thread.start()
        print(f"[DailyBriefing] Scheduler active — fires daily at {self._hour:02d}:{self._minute:02d}")

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            now = datetime.now()
            today_str = now.strftime("%Y-%m-%d")
            if (now.hour, now.minute) >= (self._hour, self._minute) and self._last_run_date != today_str:
                self._last_run_date = today_str
                try:
                    result = build_daily_briefing(gemini_api_key=self._gemini_key)
                    if self._callback:
                        self._callback(result["text"])
                except Exception as e:
                    print(f"[DailyBriefing] Generation failed: {e}")
            self._stop.wait(self._poll)