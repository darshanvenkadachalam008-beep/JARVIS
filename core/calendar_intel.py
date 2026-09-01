"""
core/calendar_intel.py — Google Calendar Integration
=====================================================
Reads your Google Calendar and feeds upcoming events into:
  • ProactiveIntelligence: 10-minute meeting reminders (auto-injected)
  • daily_briefing: "You have 3 meetings today" summary
  • Tool: get_calendar_events (direct query from voice)

Setup (one-time):
  1. pip install google-auth google-auth-oauthlib google-api-python-client
  2. Create a Google Cloud project, enable Google Calendar API,
     download OAuth2 credentials as config/google_credentials.json
  3. First run: a browser window opens for you to approve access.
     Token saved to config/google_token.json — never needed again.

If the package or credentials are missing, every method returns graceful
placeholder text so the rest of JARVIS is completely unaffected.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

# ── Paths ──────────────────────────────────────────────────────────────────────
def _base() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent

BASE_DIR    = _base()
CREDS_PATH  = BASE_DIR / "config" / "google_credentials.json"
TOKEN_PATH  = BASE_DIR / "config" / "google_token.json"
SCOPES      = ["https://www.googleapis.com/auth/calendar.readonly"]

_CALENDAR_OK  = False
_service      = None
_service_lock = threading.Lock()

# ── Google API bootstrap ───────────────────────────────────────────────────────

def _build_service():
    global _CALENDAR_OK, _service
    if _CALENDAR_OK:
        return _service
    with _service_lock:
        if _CALENDAR_OK:
            return _service
        try:
            from google.oauth2.credentials import Credentials
            from google_auth_oauthlib.flow import InstalledAppFlow
            from google.auth.transport.requests import Request
            from googleapiclient.discovery import build

            creds = None
            if TOKEN_PATH.exists():
                creds = Credentials.from_authorized_user_file(str(TOKEN_PATH), SCOPES)

            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                elif CREDS_PATH.exists():
                    flow = InstalledAppFlow.from_client_secrets_file(str(CREDS_PATH), SCOPES)
                    creds = flow.run_local_server(port=0, open_browser=True)
                else:
                    print("[Calendar] ⚠️ google_credentials.json not found — calendar disabled")
                    return None

            TOKEN_PATH.write_text(creds.to_json(), encoding="utf-8")
            _service = build("calendar", "v3", credentials=creds, cache_discovery=False)
            _CALENDAR_OK = True
            print("[Calendar] 📅 Google Calendar connected")
            return _service

        except ImportError:
            print("[Calendar] ⚠️ google-api-python-client not installed — "
                  "run: pip install google-auth google-auth-oauthlib google-api-python-client")
            return None
        except Exception as e:
            print(f"[Calendar] ⚠️ Setup failed: {e}")
            return None


# ── Core event fetch ───────────────────────────────────────────────────────────

def get_events(hours_ahead: int = 24) -> list[dict]:
    """
    Return upcoming events within the next `hours_ahead` hours.
    Each dict has: title, start, end, location, description, all_day.
    Returns [] if not configured.
    """
    svc = _build_service()
    if not svc:
        return []
    try:
        now   = datetime.now(timezone.utc)
        until = now + timedelta(hours=hours_ahead)
        result = svc.events().list(
            calendarId="primary",
            timeMin=now.isoformat(),
            timeMax=until.isoformat(),
            singleEvents=True,
            orderBy="startTime",
            maxResults=20,
        ).execute()
        events = []
        for item in result.get("items", []):
            start_raw = item.get("start", {})
            end_raw   = item.get("end",   {})
            all_day   = "date" in start_raw and "dateTime" not in start_raw
            if all_day:
                start_dt = datetime.fromisoformat(start_raw["date"])
                end_dt   = datetime.fromisoformat(end_raw.get("date", start_raw["date"]))
            else:
                start_dt = datetime.fromisoformat(start_raw["dateTime"])
                end_dt   = datetime.fromisoformat(end_raw["dateTime"])
            events.append({
                "title":       item.get("summary", "Untitled event"),
                "start":       start_dt,
                "end":         end_dt,
                "location":    item.get("location", ""),
                "description": item.get("description", ""),
                "all_day":     all_day,
            })
        return events
    except Exception as e:
        print(f"[Calendar] ⚠️ Fetch error: {e}")
        return []


def format_events(events: list[dict], label: str = "Upcoming") -> str:
    """Format event list for JARVIS to speak."""
    if not events:
        return "No upcoming events in the next 24 hours, sir."
    lines = [f"{label} events ({len(events)}):"]
    for ev in events:
        if ev["all_day"]:
            time_str = ev["start"].strftime("all day %A")
        else:
            time_str = ev["start"].strftime("%-I:%M %p")
        loc = f" at {ev['location']}" if ev["location"] else ""
        lines.append(f"  • {time_str} — {ev['title']}{loc}")
    return "\n".join(lines)


def get_today_summary() -> str:
    """Brief today-only summary for the daily briefing."""
    now    = datetime.now()
    events = get_events(hours_ahead=24)
    today  = [e for e in events
              if (e["start"].date() if e["all_day"] else e["start"].astimezone().date())
              == now.date()]
    if not today:
        return ""
    return format_events(today, label="Today's calendar")


# ── Proactive 10-minute reminder ───────────────────────────────────────────────

class CalendarReminder:
    """
    Polls for events every 60 seconds.
    Calls inject_fn(text) when a meeting is ~10 minutes away.
    """

    def __init__(self, inject_fn, remind_minutes: int = 10):
        self._inject      = inject_fn
        self._remind_min  = remind_minutes
        self._reminded    = set()   # event titles + day we already reminded
        self._thread: Optional[threading.Thread] = None

    def start(self):
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="CalendarReminder"
        )
        self._thread.start()
        print("[Calendar] ⏰ Reminder thread started")

    def _loop(self):
        while True:
            try:
                self._check()
            except Exception as e:
                print(f"[Calendar] ⚠️ Reminder check error: {e}")
            time.sleep(60)

    def _check(self):
        events = get_events(hours_ahead=1)
        now = datetime.now(timezone.utc)
        for ev in events:
            if ev["all_day"]:
                continue
            start = ev["start"]
            if start.tzinfo is None:
                start = start.replace(tzinfo=timezone.utc)
            delta_min = (start - now).total_seconds() / 60
            key = f"{ev['title']}_{start.date()}"
            if 0 < delta_min <= self._remind_min and key not in self._reminded:
                self._reminded.add(key)
                mins = int(delta_min)
                loc  = f" at {ev['location']}" if ev["location"] else ""
                msg  = (f"Sir, you have '{ev['title']}'{loc} in {mins} minute"
                        f"{'s' if mins != 1 else ''}.")
                print(f"[Calendar] ⏰ Reminder: {msg}")
                self._inject(msg)