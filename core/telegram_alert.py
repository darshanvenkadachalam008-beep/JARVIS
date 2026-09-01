"""
core/telegram_alert.py — Telegram Push Notifications for JARVIS
================================================================
Sends hacker-themed security alerts to your Telegram bot.
Uses only Python stdlib (urllib) — no extra pip installs needed.

v6: Removed ALL <pre> blocks — they render as grey "COPY CODE" boxes
    in Telegram Mobile. Pure emoji + bold formatting only.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional


CONFIG_PATH  = Path(__file__).parent.parent / "config" / "api_keys.json"
TELEGRAM_API = "https://api.telegram.org/bot{token}/{method}"


class TelegramAlerter:

    def __init__(self, token: Optional[str] = None, chat_id: Optional[str] = None):
        if token and chat_id:
            self._token   = token
            self._chat_id = str(chat_id)
        else:
            self._token, self._chat_id = self._load_config()

        if self._token and self._chat_id:
            print(f"[Telegram] ✅ Configured — alerts will go to chat {self._chat_id}")
        else:
            print("[Telegram] ⚠️ Not configured — add telegram_bot_token and telegram_chat_id to config/api_keys.json")

    @property
    def configured(self) -> bool:
        return bool(self._token and self._chat_id)

    def _load_config(self) -> tuple[Optional[str], Optional[str]]:
        try:
            if not CONFIG_PATH.exists():
                return None, None
            data      = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            token     = data.get("telegram_bot_token") or data.get("TELEGRAM_BOT_TOKEN")
            chat_id   = data.get("telegram_chat_id")   or data.get("TELEGRAM_CHAT_ID")
            return token, str(chat_id) if chat_id else None
        except Exception as e:
            print(f"[Telegram] Config load error: {e}")
            return None, None

    # ── Low-level send helpers ─────────────────────────────────────────────────

    def send_message(self, text: str, parse_mode: str = "HTML") -> bool:
        if not self.configured:
            return False
        try:
            url     = TELEGRAM_API.format(token=self._token, method="sendMessage")
            payload = json.dumps({
                "chat_id":    self._chat_id,
                "text":       text,
                "parse_mode": parse_mode,
            }).encode("utf-8")
            req = urllib.request.Request(
                url, data=payload,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read())
                if result.get("ok"):
                    print("[Telegram] ✅ Message sent")
                    return True
                print(f"[Telegram] ❌ API error: {result}")
                return False
        except urllib.error.URLError as e:
            print(f"[Telegram] ❌ Network error: {e}")
            return False
        except Exception as e:
            print(f"[Telegram] ❌ Send error: {e}")
            return False

    def send_photo(self, jpeg_bytes: bytes, caption: str = "") -> bool:
        if not self.configured or not jpeg_bytes:
            return False
        try:
            boundary = "----JARVISBoundary7MA4YWxkTrZu0gW"
            body     = []

            body.append(f"--{boundary}".encode())
            body.append(b'Content-Disposition: form-data; name="chat_id"')
            body.append(b"")
            body.append(self._chat_id.encode())

            if caption:
                body.append(f"--{boundary}".encode())
                body.append(b'Content-Disposition: form-data; name="caption"')
                body.append(b"Content-Type: text/plain; charset=utf-8")
                body.append(b"")
                body.append(caption.encode("utf-8"))

            body.append(f"--{boundary}".encode())
            body.append(b'Content-Disposition: form-data; name="photo"; filename="alert.jpg"')
            body.append(b"Content-Type: image/jpeg")
            body.append(b"")
            body.append(jpeg_bytes)
            body.append(f"--{boundary}--".encode())

            payload = b"\r\n".join(body)
            url     = TELEGRAM_API.format(token=self._token, method="sendPhoto")
            req     = urllib.request.Request(
                url, data=payload,
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read())
                if result.get("ok"):
                    print("[Telegram] ✅ Photo sent")
                    return True
                print(f"[Telegram] ❌ Photo API error: {result}")
                return False
        except urllib.error.URLError as e:
            print(f"[Telegram] ❌ Network error sending photo: {e}")
            return False
        except Exception as e:
            print(f"[Telegram] ❌ Photo send error: {e}")
            return False

    def send_video(self, video_bytes: bytes, caption: str = "", filename: str = "intruder.mp4") -> bool:
        if not self.configured or not video_bytes:
            return False
        try:
            boundary = "----JARVISBoundaryVideo7MA4YWxkTrZu0gW"
            body     = []

            body.append(f"--{boundary}".encode())
            body.append(b'Content-Disposition: form-data; name="chat_id"')
            body.append(b"")
            body.append(self._chat_id.encode())

            if caption:
                body.append(f"--{boundary}".encode())
                body.append(b'Content-Disposition: form-data; name="caption"')
                body.append(b"Content-Type: text/plain; charset=utf-8")
                body.append(b"")
                body.append(caption.encode("utf-8"))

            content_type = "video/mp4" if filename.endswith(".mp4") else "video/x-msvideo"
            body.append(f"--{boundary}".encode())
            body.append(f'Content-Disposition: form-data; name="video"; filename="{filename}"'.encode())
            body.append(f"Content-Type: {content_type}".encode())
            body.append(b"")
            body.append(video_bytes)
            body.append(f"--{boundary}--".encode())

            payload = b"\r\n".join(body)
            url     = TELEGRAM_API.format(token=self._token, method="sendVideo")
            req     = urllib.request.Request(
                url, data=payload,
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read())
                if result.get("ok"):
                    print("[Telegram] ✅ Video sent")
                    return True
                print(f"[Telegram] ❌ Video API error: {result}")
                return False
        except urllib.error.URLError as e:
            print(f"[Telegram] ❌ Network error sending video: {e}")
            return False
        except Exception as e:
            print(f"[Telegram] ❌ Video send error: {e}")
            return False

    # ── High-level alert ───────────────────────────────────────────────────────

    def send_alert(
        self,
        text: str,
        jpeg_bytes: Optional[bytes] = None,
        hostname: str = "UNKNOWN",
        time_str: str = "",
    ) -> bool:
        """
        Send the full hacker-themed security alert.
        v6: NO <pre> blocks at all — only bold/italic + emojis.
              Telegram Mobile renders these as normal styled text.
        """
        if not self.configured:
            return False

        # ── Photo caption (plain text — captions don't support parse_mode) ──
        photo_caption = (
            "🔴 DANGER 🔴 DANGER 🔴 DANGER\n"
            "\n"
            "☠️  INTRUSION DETECTED  ☠️\n"
            "\n"
            f"Hey Shan, someone is trying\n"
            f"to unlock your system!\n"
            "\n"
            f"🖥  Machine  :  {hostname}\n"
            f"⏱  Time     :  {time_str}\n"
            f"📸  Snapshot :  CAPTURED\n"
            "\n"
            "🔴 DANGER 🔴 DANGER 🔴 DANGER\n"
            "\n"
            "— J.A.R.V.I.S | Stark Industries"
        )

        # ── HTML alert message (NO <pre> = NO grey code boxes) ──────────────
        html_message = (
            "🔴🔴🔴 <b>DANGER  DANGER  DANGER</b> 🔴🔴🔴\n"
            "\n"
            "☠️  <b>SECURITY BREACH DETECTED</b>  ☠️\n"
            "\n"
            "⚠️ <b>Hey Shan,</b>\n"
            "<b>Someone is trying to unlock your system RIGHT NOW!</b>\n"
            "\n"
            "🖥  <b>MACHINE</b>  →  " + hostname + "\n"
            "⏱  <b>TIME</b>     →  " + time_str + "\n"
            "🔒  <b>STATUS</b>   →  INTRUSION DETECTED\n"
            "📸  <b>SNAPSHOT</b> →  CAPTURED\n"
            "🚨  <b>THREAT</b>   →  HIGH\n"
            "\n"
            "🔴 <b>INITIATING SECURITY PROTOCOL...</b>\n"
            "\n"
            "🔴🔴🔴 <b>DANGER  DANGER  DANGER</b> 🔴🔴🔴\n"
            "\n"
            "<i>— J.A.R.V.I.S | Stark Industries\n"
            "Mark-XXXIX-OR Security System</i>"
        )

        if jpeg_bytes:
            photo_ok = self.send_photo(jpeg_bytes, caption=photo_caption)
            self.send_message(html_message)
            return photo_ok
        else:
            return self.send_message(html_message)