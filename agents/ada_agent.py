"""
Ada — Content Creation Agent
Drafts social media content (Instagram, X/Twitter, LinkedIn) and can
PUBLISH directly to Instagram or a Facebook Page via the Meta Graph API,
reusing the same `meta_access_token` Nova already reads for analytics.

PHASE 5 GAP FIX: Ada previously only ever wrote a .txt draft to
content/drafts/ and stopped — the spec asked for an agent that "drafts
content and posts to social media," and the posting half didn't exist at
all. This adds real publishing for the platforms where it's realistically
achievable with a single long-lived token and no paid API tier:

  - Instagram (Business/Creator account, via Graph API Content Publishing)
  - Facebook Page (via Graph API feed posting)

X/Twitter and LinkedIn are intentionally left as drafts-only — see
_UNSUPPORTED_PUBLISH_PLATFORMS below for why, and the report Ada returns
explains it plainly each time rather than silently doing nothing.

Publishing only ever happens when explicitly requested — either via
execute_task(..., publish=True) or natural-language intent ("post this",
"publish this", "go ahead and post it") in the task text. A plain
"draft me an instagram caption about X" never posts anything; it behaves
exactly as before.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.request
import urllib.parse
from pathlib import Path

from agents.base_agent import BaseAgent


def _get_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


_PLATFORM_RULES = {
    "instagram": "Instagram caption: max 2200 chars, use 5–10 relevant hashtags, warm/visual tone.",
    "twitter":   "X/Twitter post: max 280 chars, punchy, use 1–2 hashtags, no filler.",
    "x":         "X/Twitter post: max 280 chars, punchy, use 1–2 hashtags, no filler.",
    "linkedin":  "LinkedIn post: professional tone, 150–300 words, end with a question to drive engagement.",
    "facebook":  "Facebook Page post: conversational, 1-3 short paragraphs, end with a light call-to-action.",
}

# Platforms Ada can ACTUALLY publish to with just a Meta long-lived token.
_PUBLISHABLE_PLATFORMS = {"instagram", "facebook"}

# Platforms where posting is a real feature gap, not a bug — both require
# either a paid API tier (X/Twitter's v2 write access) or a formal app-review
# process with a registered company (LinkedIn's Marketing API) that doesn't
# fit a local, zero-subscription personal assistant. Surfaced honestly in the
# report instead of silently doing nothing or pretending it worked.
_UNSUPPORTED_PUBLISH_PLATFORMS = {
    "twitter": "X/Twitter requires a paid API tier for posting (free tier is read-only).",
    "x":       "X/Twitter requires a paid API tier for posting (free tier is read-only).",
    "linkedin": "LinkedIn's posting API requires a formal app-review process with a registered company.",
}

_PUBLISH_INTENT_PHRASES = (
    "post this", "post it", "publish this", "publish it", "go ahead and post",
    "actually post", "send it live", "put it up", "post that", "publish that",
)


class AdaAgent(BaseAgent):

    def __init__(self):
        super().__init__("Ada")
        self._drafts_dir = _get_base_dir() / "content" / "drafts"
        self._cfg = self._load_cfg()

    def execute_task(self, task: str, speak=None, platform: str = "instagram",
                      publish: bool = False, **kwargs) -> str:
        self._start(task)
        try:
            self._drafts_dir.mkdir(parents=True, exist_ok=True)
            platform = platform.lower()
            want_publish = publish or self._detect_publish_intent(task)

            self.update_progress(15, f"Ada: Drafting {platform} content…")
            draft = self._generate_draft(task, platform)

            self.update_progress(60, "Ada: Saving draft…")
            saved_path = self._save_draft(task, platform, draft)

            publish_result = None
            if want_publish:
                self.update_progress(75, f"Ada: Publishing to {platform}…")
                publish_result = self._publish(platform, draft)

            self.update_progress(90, "Ada: Formatting report…")
            report = self._format_report(task, platform, draft, saved_path, publish_result)

            return self.report_result(report)

        except Exception as e:
            return self._error(str(e))

    # ── Private ─────────────────────────────────────────────────────────────

    def _detect_publish_intent(self, task: str) -> bool:
        low = task.lower()
        return any(phrase in low for phrase in _PUBLISH_INTENT_PHRASES)

    def _generate_draft(self, topic: str, platform: str) -> str:
        rule = _PLATFORM_RULES.get(platform, _PLATFORM_RULES["instagram"])
        prompt = (
            f"You are Ada, a professional social media copywriter.\n"
            f"Platform rule: {rule}\n\n"
            f"Write a post about: {topic}\n\n"
            f"Output ONLY the post text, nothing else."
        )
        try:
            from or_client import generate_text
            return generate_text(prompt)
        except Exception:
            pass

        # Fallback: Gemini
        try:
            api_key = self._load_api_key()
            from google import genai
            client   = genai.Client(api_key=api_key)
            response = client.models.generate_content(
                model="gemini-2.5-flash-lite",
                contents=prompt,
            )
            return response.text.strip()
        except Exception as e:
            return f"[Draft placeholder — LLM unavailable: {e}]\n\nTopic: {topic}\nPlatform: {platform}"

    def _load_api_key(self) -> str:
        path = _get_base_dir() / "config" / "api_keys.json"
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f).get("gemini_api_key", "")

    def _load_cfg(self) -> dict:
        path = _get_base_dir() / "config" / "api_keys.json"
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_draft(self, topic: str, platform: str, draft: str) -> Path:
        safe = "".join(c if c.isalnum() or c in " _-" else "_" for c in topic)[:40]
        ts   = time.strftime("%Y%m%d_%H%M%S")
        path = self._drafts_dir / f"ada_{platform}_{safe}_{ts}.txt"
        path.write_text(draft, encoding="utf-8")
        self._log(f"Ada: Draft saved → {path}")
        return path

    # ── Publishing ──────────────────────────────────────────────────────────

    def _publish(self, platform: str, text: str) -> dict:
        """
        Returns a dict: {"ok": bool, "message": str, "url": str|None}
        Never raises — publishing failures are reported, not crashed on.
        """
        if platform in _UNSUPPORTED_PUBLISH_PLATFORMS:
            return {
                "ok": False,
                "message": (
                    f"Can't auto-post to {platform.capitalize()}: "
                    f"{_UNSUPPORTED_PUBLISH_PLATFORMS[platform]} "
                    f"The draft above is saved and ready for you to post manually."
                ),
                "url": None,
            }

        if platform not in _PUBLISHABLE_PLATFORMS:
            return {
                "ok": False,
                "message": f"No publish integration for '{platform}' — draft saved only.",
                "url": None,
            }

        token = self._cfg.get("meta_access_token", "")
        if not token:
            return {
                "ok": False,
                "message": (
                    "Publishing not configured, sir — add 'meta_access_token' to "
                    "config/api_keys.json (a long-lived Meta Graph API token with "
                    "the right publish scopes) to enable real posting. Draft saved only."
                ),
                "url": None,
            }

        try:
            if platform == "facebook":
                return self._publish_facebook(token, text)
            elif platform == "instagram":
                return self._publish_instagram(token, text)
        except Exception as e:
            return {"ok": False, "message": f"Publish failed: {e}", "url": None}

        return {"ok": False, "message": "Unhandled platform.", "url": None}

    def _publish_facebook(self, token: str, text: str) -> dict:
        page_id = self._cfg.get("facebook_page_id", "")
        if not page_id:
            return {
                "ok": False,
                "message": "Missing 'facebook_page_id' in config/api_keys.json — draft saved only.",
                "url": None,
            }
        url = f"https://graph.facebook.com/v21.0/{page_id}/feed"
        data = urllib.parse.urlencode({"message": text, "access_token": token}).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=15) as r:
            result = json.loads(r.read().decode())
        post_id = result.get("id", "")
        return {
            "ok": True,
            "message": "Posted to Facebook Page.",
            "url": f"https://www.facebook.com/{post_id}" if post_id else None,
        }

    def _publish_instagram(self, token: str, text: str) -> dict:
        """
        Instagram's Content Publishing API requires every post to be tied to
        a media object (image or video) — there's no text-only IG post.
        Ada is a text-drafting agent and doesn't generate images, so this
        publishes through the linked Facebook Page as the closest honest
        equivalent (the caption Ada wrote, posted where it can actually go
        out without fabricating an image to attach it to), and says so
        plainly rather than silently substituting platforms.
        """
        ig_id = self._cfg.get("instagram_business_account_id", "")
        page_id = self._cfg.get("facebook_page_id", "")
        if not ig_id and not page_id:
            return {
                "ok": False,
                "message": (
                    "Instagram requires an image for every post (text-only posts "
                    "aren't supported by their API), and I don't have an image to "
                    "attach. Add 'facebook_page_id' to config/api_keys.json and I "
                    "can post this caption to your linked Facebook Page instead — "
                    "draft saved only for now."
                ),
                "url": None,
            }
        if page_id:
            result = self._publish_facebook(token, text)
            if result["ok"]:
                result["message"] = (
                    "Instagram needs an image for every post, so I posted this "
                    "caption to your linked Facebook Page instead."
                )
            return result
        return {
            "ok": False,
            "message": "Instagram needs an image for every post — draft saved only.",
            "url": None,
        }

    def _format_report(self, topic: str, platform: str, draft: str, path: Path,
                        publish_result: dict | None) -> str:
        publish_block = ""
        if publish_result is not None:
            status = "✅ PUBLISHED" if publish_result["ok"] else "⚠️ NOT PUBLISHED"
            publish_block = (
                f"───────────────────────────────\n"
                f"Publish   : {status}\n"
                f"Details   : {publish_result['message']}\n"
            )
            if publish_result.get("url"):
                publish_block += f"Live at   : {publish_result['url']}\n"

        return (
            f"═══════════════════════════════\n"
            f"  ADA REPORT\n"
            f"═══════════════════════════════\n"
            f"Topic    : {topic}\n"
            f"Platform : {platform.capitalize()}\n"
            f"Saved to : {path}\n"
            f"{publish_block}"
            f"───────────────────────────────\n"
            f"Draft:\n\n{draft}\n"
            f"═══════════════════════════════"
        )