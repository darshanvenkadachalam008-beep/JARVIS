"""
Nova — Analytics Agent
Supports: YouTube Data API, GitHub API, Google Analytics 4, Meta API.
Never crashes. Always demo mode if API keys missing.
Saves reports to reports/nova/.
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


class NovaAgent(BaseAgent):

    def __init__(self):
        super().__init__("Nova")
        self._reports_dir = _get_base_dir() / "reports" / "nova"
        self._cfg: dict   = {}
        self._load_cfg()

    # ── Public ──────────────────────────────────────────────────────────────

    def execute_task(self, task: str, speak=None, source: str = "auto", **kwargs) -> str:
        self._start(task)
        try:
            self._reports_dir.mkdir(parents=True, exist_ok=True)
            self.update_progress(10, "Nova: Identifying source…")
            src = source if source != "auto" else self._detect_source(task)

            self.update_progress(30, f"Nova: Fetching {src} data…")
            data = self._fetch(src, task)

            self.update_progress(80, "Nova: Building report…")
            report = self._format_report(task, src, data)

            self.update_progress(90, "Nova: Saving…")
            self._save_report(task, src, report)

            return self.report_result(report)
        except Exception as e:
            return self._error(str(e))

    # ── Source detection ─────────────────────────────────────────────────────

    def _detect_source(self, task: str) -> str:
        t = task.lower()
        if any(k in t for k in ("youtube", "video", "channel", "views", "subscribers", "yt")):
            return "youtube"
        if any(k in t for k in ("github", "repo", "stars", "forks", "commits", "issues", "pull")):
            return "github"
        if any(k in t for k in ("google analytics", "ga4", "sessions", "traffic", "pageview")):
            return "ga4"
        if any(k in t for k in ("instagram", "ig followers", "insta", "reels", "ig post")):
            return "instagram"
        if any(k in t for k in ("meta", "facebook", "ads", "roas", "ad spend")):
            return "meta"
        return "github"   # sensible free-tier default

    # ── Dispatcher ───────────────────────────────────────────────────────────

    def _fetch(self, source: str, task: str) -> dict:
        fetchers = {
            "youtube":   self._fetch_youtube,
            "github":    self._fetch_github,
            "ga4":       self._fetch_ga4,
            "meta":      self._fetch_meta,
            "instagram": self._fetch_instagram,
        }
        fn = fetchers.get(source, self._fetch_github)
        try:
            return fn(task)
        except Exception as e:
            return {"_demo": True, "error": str(e),
                    "message": f"{source.upper()} API error — demo mode"}

    # ── YouTube ──────────────────────────────────────────────────────────────

    def _fetch_youtube(self, task: str) -> dict:
        key = self._cfg.get("youtube_api_key", "")
        if not key:
            return {
                "_demo": True,
                "message": "YouTube API not configured - demo mode",
                "channel": "Demo Channel",
                "subscribers": "12,400",
                "total_views": "284,000",
                "video_count": "47",
                "status": "Demo",
            }
        try:
            url = (
                "https://www.googleapis.com/youtube/v3/channels"
                f"?part=snippet,statistics&mine=true&key={key}"
            )
            data = self._http_get_json(url)
            items = data.get("items", [])
            if not items:
                return {"_demo": False, "message": "No channel found for this key.", "status": "Connected"}
            item  = items[0]
            stats = item.get("statistics", {})
            snip  = item.get("snippet", {})
            return {
                "_demo": False,
                "status":       "Connected",
                "channel":      snip.get("title", "Unknown"),
                "subscribers":  stats.get("subscriberCount", "hidden"),
                "total_views":  stats.get("viewCount", "0"),
                "video_count":  stats.get("videoCount", "0"),
                "country":      snip.get("country", "N/A"),
            }
        except Exception as e:
            return {"_demo": True, "message": f"YouTube API error: {e}", "status": "Demo"}

    # ── GitHub ───────────────────────────────────────────────────────────────

    def _fetch_github(self, task: str) -> dict:
        token = self._cfg.get("github_token", "")
        # Try to extract a repo name from the task
        import re
        match = re.search(r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", task)
        repo  = match.group(1) if match else None

        if repo:
            return self._fetch_github_repo(repo, token)
        if token:
            return self._fetch_github_user(token)

        # Fully public demo — no key needed
        try:
            data = self._http_get_json(
                "https://api.github.com/repos/anthropics/anthropic-sdk-python",
                token=token,
            )
            return {
                "_demo": True,
                "message": "No repo specified — showing public demo repo",
                "status":  "Public API",
                "repo":    data.get("full_name", "N/A"),
                "stars":   data.get("stargazers_count", 0),
                "forks":   data.get("forks_count", 0),
                "issues":  data.get("open_issues_count", 0),
                "language": data.get("language", "N/A"),
                "watchers": data.get("watchers_count", 0),
            }
        except Exception as e:
            return {"_demo": True, "message": f"GitHub API error: {e}", "status": "Demo"}

    def _fetch_github_repo(self, repo: str, token: str) -> dict:
        try:
            data = self._http_get_json(
                f"https://api.github.com/repos/{repo}",
                token=token,
            )
            # Try contributors count
            contribs = 0
            try:
                c = self._http_get_json(
                    f"https://api.github.com/repos/{repo}/contributors?per_page=1&anon=true",
                    token=token,
                )
                contribs = len(c) if isinstance(c, list) else 0
            except Exception:
                pass
            return {
                "_demo": False,
                "status":       "Connected" if token else "Public API",
                "repo":         data.get("full_name", repo),
                "stars":        data.get("stargazers_count", 0),
                "forks":        data.get("forks_count", 0),
                "open_issues":  data.get("open_issues_count", 0),
                "language":     data.get("language", "N/A"),
                "contributors": contribs,
                "watchers":     data.get("watchers_count", 0),
                "license":      (data.get("license") or {}).get("spdx_id", "N/A"),
            }
        except Exception as e:
            return {"_demo": True, "message": f"GitHub repo error: {e}", "status": "Demo"}

    def _fetch_github_user(self, token: str) -> dict:
        try:
            user  = self._http_get_json("https://api.github.com/user", token=token)
            repos = self._http_get_json(
                "https://api.github.com/user/repos?sort=updated&per_page=5",
                token=token,
            )
            top = [r.get("name", "") for r in repos] if isinstance(repos, list) else []
            return {
                "_demo": False,
                "status":     "Connected",
                "user":       user.get("login", "N/A"),
                "public_repos": user.get("public_repos", 0),
                "followers":  user.get("followers", 0),
                "following":  user.get("following", 0),
                "top_repos":  ", ".join(top[:5]),
            }
        except Exception as e:
            return {"_demo": True, "message": f"GitHub user error: {e}", "status": "Demo"}

    # ── Google Analytics 4 ───────────────────────────────────────────────────

    def _fetch_ga4(self, task: str) -> dict:
        key = self._cfg.get("google_analytics_key", "")
        if not key:
            return {
                "_demo": True,
                "message": "Google Analytics 4 not configured - demo mode",
                "status": "Demo",
                "users_7d":    "3,240",
                "sessions_7d": "4,810",
                "bounce_rate": "42.1%",
                "top_page":    "/home",
                "events_7d":   "18,900",
            }
        # GA4 Data API requires OAuth2; with only a key we return demo + hint
        return {
            "_demo": True,
            "status":  "Key present — OAuth2 required for live data",
            "message": "GA4 requires service account OAuth2 — demo mode",
            "users_7d":    "3,240",
            "sessions_7d": "4,810",
            "bounce_rate": "42.1%",
            "top_page":    "/home",
        }

    # ── Meta ─────────────────────────────────────────────────────────────────

    def _fetch_meta(self, task: str) -> dict:
        token = self._cfg.get("meta_access_token", "")
        if not token:
            return {
                "_demo": True,
                "message": "Meta API not configured",
                "status":  "Demo",
                "spend":        "$1,240",
                "impressions":  "84,000",
                "clicks":       "3,120",
                "ctr":          "3.7%",
                "roas":         "2.8x",
            }
        try:
            url  = f"https://graph.facebook.com/v21.0/me?access_token={token}"
            data = self._http_get_json(url)
            return {
                "_demo": False,
                "status": "Connected",
                "account": data.get("name", "N/A"),
                "id":      data.get("id", "N/A"),
                "note":    "For ad metrics, configure an Ad Account ID",
            }
        except Exception as e:
            return {"_demo": True, "message": f"Meta API error: {e}", "status": "Demo"}

    # ── Instagram (Graph API) ────────────────────────────────────────────────
    #
    # Requirements (set in config/api_keys.json):
    #   meta_access_token              — long-lived token from Meta Graph API
    #                                     Explorer / OAuth, with the
    #                                     instagram_basic +
    #                                     instagram_manage_insights scopes.
    #   instagram_business_account_id  — OPTIONAL. The numeric IG Business
    #                                     Account ID. If omitted, Nova will
    #                                     try to auto-resolve it from the
    #                                     Facebook Pages connected to the
    #                                     token (one extra API call).
    #
    # The Instagram account MUST be a Business or Creator account linked to
    # a Facebook Page — personal accounts are not supported by this API.

    def _fetch_instagram(self, task: str) -> dict:
        token = self._cfg.get("meta_access_token", "")
        if not token:
            return {
                "_demo": True,
                "message": "Instagram API not configured - demo mode",
                "status": "Demo",
                "username":       "demo_account",
                "followers":      "8,420",
                "media_count":    "212",
                "reach_28d":      "31,500",
                "impressions_28d": "47,800",
                "profile_views_28d": "1,960",
                "top_post_engagement": "1,340 likes/comments",
            }

        ig_id = self._cfg.get("instagram_business_account_id", "")
        try:
            if not ig_id:
                ig_id = self._resolve_ig_account_id(token)
            if not ig_id:
                return {
                    "_demo": True,
                    "status": "Token present — no linked Instagram Business account found",
                    "message": (
                        "Couldn't find an Instagram Business/Creator account linked to a "
                        "Facebook Page on this token. Make sure your Instagram account is "
                        "converted to Business/Creator and connected to a Facebook Page."
                    ),
                    "followers": "8,420",
                    "media_count": "212",
                }

            profile  = self._ig_get(ig_id, token, "username,followers_count,media_count,name")
            insights = self._ig_account_insights(ig_id, token)
            top_post = self._ig_top_post(ig_id, token)

            result = {
                "_demo": False,
                "status":     "Connected",
                "account_id": ig_id,
                "username":   profile.get("username", "N/A"),
                "followers":  profile.get("followers_count", "N/A"),
                "media_count": profile.get("media_count", "N/A"),
            }
            result.update(insights)
            if top_post:
                result["top_post"] = top_post
            return result

        except Exception as e:
            return {"_demo": True, "message": f"Instagram API error: {e}", "status": "Demo"}

    def _resolve_ig_account_id(self, token: str) -> str:
        """
        Auto-resolve the Instagram Business Account ID from the Facebook
        Pages connected to this token — saves the user from having to dig
        up the numeric ID manually via Graph API Explorer.
        """
        url  = f"https://graph.facebook.com/v21.0/me/accounts?access_token={token}"
        data = self._http_get_json(url)
        for page in data.get("data", []):
            page_id = page.get("id", "")
            if not page_id:
                continue
            detail_url = (
                f"https://graph.facebook.com/v21.0/{page_id}"
                f"?fields=instagram_business_account&access_token={token}"
            )
            detail = self._http_get_json(detail_url)
            ig = detail.get("instagram_business_account", {}).get("id", "")
            if ig:
                return ig
        return ""

    def _ig_get(self, ig_id: str, token: str, fields: str) -> dict:
        url = f"https://graph.facebook.com/v21.0/{ig_id}?fields={fields}&access_token={token}"
        return self._http_get_json(url)

    def _ig_account_insights(self, ig_id: str, token: str) -> dict:
        """
        Account-level insights over the last 28 days: reach, impressions,
        profile views. Falls back to an empty dict (not a crash) if the
        token lacks instagram_manage_insights, since insights require an
        extra permission beyond basic profile read access.
        """
        try:
            url = (
                f"https://graph.facebook.com/v21.0/{ig_id}/insights"
                f"?metric=reach,impressions,profile_views&period=days_28&access_token={token}"
            )
            data = self._http_get_json(url)
            out  = {}
            for entry in data.get("data", []):
                name   = entry.get("name", "")
                values = entry.get("values", [])
                total  = sum(v.get("value", 0) for v in values) if values else 0
                if name == "reach":
                    out["reach_28d"] = f"{total:,}"
                elif name == "impressions":
                    out["impressions_28d"] = f"{total:,}"
                elif name == "profile_views":
                    out["profile_views_28d"] = f"{total:,}"
            return out
        except Exception:
            # Insights permission missing or not yet available for this
            # account — return profile stats alone rather than failing.
            return {"insights_note": "Add instagram_manage_insights scope for reach/impressions"}

    def _ig_top_post(self, ig_id: str, token: str) -> str:
        """Most recent media item's engagement, as a quick snapshot."""
        try:
            url = (
                f"https://graph.facebook.com/v21.0/{ig_id}/media"
                f"?fields=caption,like_count,comments_count,timestamp&limit=5&access_token={token}"
            )
            data  = self._http_get_json(url)
            items = data.get("data", [])
            if not items:
                return ""
            best = max(items, key=lambda m: m.get("like_count", 0) + m.get("comments_count", 0))
            caption = (best.get("caption") or "")[:60].replace("\n", " ")
            return (
                f"{best.get('like_count', 0)} likes, {best.get('comments_count', 0)} comments "
                f"— \"{caption}{'…' if len(best.get('caption') or '') > 60 else ''}\""
            )
        except Exception:
            return ""

    # ── Formatting ───────────────────────────────────────────────────────────

    def _format_report(self, task: str, source: str, data: dict) -> str:
        demo    = data.get("_demo", False)
        status  = data.get("status", "Demo" if demo else "Connected")
        notice  = "\n⚠️  DEMO MODE — add API key to config/api_keys.json\n" if demo else "\n✅  LIVE DATA\n"
        rows    = "\n".join(
            f"  {k:<22}: {v}"
            for k, v in data.items()
            if not k.startswith("_") and k not in ("status", "message")
        )
        msg = data.get("message", "")
        return (
            f"═══════════════════════════════\n"
            f"  NOVA REPORT\n"
            f"═══════════════════════════════\n"
            f"Task    : {task}\n"
            f"Source  : {source.upper()}\n"
            f"Status  : {status}\n"
            f"{notice}"
            f"───────────────────────────────\n"
            f"{f'Note    : {msg}' + chr(10) if msg else ''}"
            f"{rows}\n"
            f"═══════════════════════════════"
        )

    def _save_report(self, task: str, source: str, report: str) -> None:
        safe = "".join(c if c.isalnum() or c in " _-" else "_" for c in task)[:40]
        ts   = time.strftime("%Y%m%d_%H%M%S")
        path = self._reports_dir / f"nova_{source}_{safe}_{ts}.txt"
        path.write_text(report, encoding="utf-8")
        self._log(f"Nova: Report saved → {path}")

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _load_cfg(self) -> None:
        path = _get_base_dir() / "config" / "api_keys.json"
        try:
            with open(path, "r", encoding="utf-8") as f:
                self._cfg = json.load(f)
        except Exception:
            self._cfg = {}

    def _http_get_json(self, url: str, token: str = "") -> dict | list:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "JARVIS-Nova/1.0")
        if token:
            req.add_header("Authorization", f"token {token}")
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode())