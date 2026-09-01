import json
import sys
import time
import base64
import logging
from pathlib import Path
from typing import Optional

import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("openrouter_client")

def _get_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent


BASE_DIR     = _get_base_dir()
API_KEY_PATH = BASE_DIR / "config" / "api_keys.json"

def _load_api_key() -> str:
    try:
        with open(API_KEY_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        key = data.get("openrouter_api_key", "").strip()
        if not key:
            raise ValueError("openrouter_api_key is empty in api_keys.json")
        return key
    except FileNotFoundError:
        raise RuntimeError(f"api_keys.json not found at: {API_KEY_PATH}")
    except Exception as e:
        raise RuntimeError(f"Failed to load OpenRouter API key: {e}")

# ── BUG FIX (root cause of the "All models failed" storm) ────────────────────
# The previous version hardcoded ~22 model slugs as a Python list. OpenRouter's
# free-model catalog is NOT stable — providers add/remove ":free" routes
# regularly (confirmed: several slugs that were in the old list, e.g.
# "minimax/minimax-m2.5:free", "google/gemma-4-31b-it:free",
# "google/gemma-4-26b-a4b-it:free", "arcee-ai/trinity-large-preview:free",
# returned HTTP 404 — they simply don't exist as written). A hardcoded list
# goes stale and then EVERY call walks the entire dead list before failing,
# which is exactly the multi-minute fallback storm seen in the logs.
#
# Fix: fetch the live catalog from OpenRouter's own /models endpoint, filter
# for slugs ending in ":free", and cache the result for FREE_MODELS_TTL
# seconds. Falls back to a small set of historically-stable slugs only if the
# live fetch itself fails (e.g. no network at all).
MODELS_URL          = "https://openrouter.ai/api/v1/models"
FREE_MODELS_TTL      = 3600   # re-fetch the catalog once per hour
_FALLBACK_TEXT_MODELS: list[str] = [
    "meta-llama/llama-3.3-70b-instruct:free",
    "google/gemma-3-27b-it:free",
]
_FALLBACK_VISION_MODELS: list[str] = [
    "meta-llama/llama-3.3-70b-instruct:free",
]

_model_cache: dict = {"text": [], "vision": [], "ts": 0.0}


def _fetch_live_models() -> tuple[list[str], list[str]]:
    """Pull the current model catalog from OpenRouter and split into
    text-capable and vision-capable free model slug lists."""
    try:
        resp = requests.get(MODELS_URL, timeout=10)
        resp.raise_for_status()
        data = resp.json().get("data", [])
    except Exception as e:
        logger.warning(f"[OpenRouter] Could not fetch live model list: {e}")
        return [], []

    text_models:   list[str] = []
    vision_models: list[str] = []

    for m in data:
        slug = m.get("id", "")
        if not slug.endswith(":free"):
            continue
        modality = (m.get("architecture") or {}).get("input_modalities", [])
        text_models.append(slug)
        if "image" in modality:
            vision_models.append(slug)

    return text_models, vision_models


def _get_model_pools() -> tuple[list[str], list[str]]:
    """Return (text_models, vision_models), refreshing from the live
    catalog if the cache is stale or empty."""
    now = time.time()
    if not _model_cache["text"] or (now - _model_cache["ts"]) > FREE_MODELS_TTL:
        text, vision = _fetch_live_models()
        if text:
            _model_cache["text"]   = text
            _model_cache["vision"] = vision or _FALLBACK_VISION_MODELS
            _model_cache["ts"]     = now
            logger.info(
                f"[OpenRouter] Refreshed model catalog: "
                f"{len(text)} text, {len(vision)} vision free models"
            )
        elif not _model_cache["text"]:
            # Live fetch failed AND we have nothing cached yet — use the
            # small hardcoded fallback so the app can still function.
            logger.warning("[OpenRouter] Using static fallback model list")
            _model_cache["text"]   = _FALLBACK_TEXT_MODELS
            _model_cache["vision"] = _FALLBACK_VISION_MODELS
            _model_cache["ts"]     = now
        # else: fetch failed but we still have a (possibly old) cache —
        # keep using it rather than falling back, since "stale but real"
        # beats "small hardcoded list".

    return _model_cache["text"], _model_cache["vision"]


API_URL               = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MAX_TOKENS    = 4096
DEFAULT_TEMPERATURE   = 0.7
REQUEST_TIMEOUT       = 12   # seconds per request — kept well under Gemini Live's ~60s
                              # session-silence timeout so slow models fail fast and
                              # the fallback pool cycles before the WebSocket drops.
                              # Lowered from 18s: with a larger live-fetched pool,
                              # a long per-model timeout makes worst-case fallback
                              # latency unacceptably high (was up to ~6 min).
MAX_RETRIES_PER_MODEL = 1    # 1 attempt per model — with a short timeout a retry
                              # wastes time; just move to the next model instead.
RETRY_DELAY           = 1    # seconds between retries

# ── BUG FIX: rate-limit handling ──────────────────────────────────────────────
# The previous RATE_LIMIT_COOLDOWN (60s) marked models rate-limited one at a
# time, as each was individually tried. On OpenRouter's free tier the rate
# limit is typically applied per-key across ALL free models, not per-model —
# so a single burst of calls poisoned the entire pool within seconds, and the
# 60s cooldown wasn't enough to recover before the next caller tried again
# (visible in the logs as every model in the list reporting 429 back-to-back).
# Fix: track a single global "cooled down until" timestamp set on the FIRST
# 429 seen in a burst, so we stop wasting calls on a pool we already know is
# rate-limited, and increase the cooldown to give the shared limit time to
# actually reset.
RATE_LIMIT_COOLDOWN     = 90   # seconds — per-model cooldown (kept for genuine
                                # per-model 429s from non-shared limits)
GLOBAL_RATE_LIMIT_COOLDOWN = 30  # seconds — short-circuit ALL calls after the
                                   # first 429 in a burst, since the free tier
                                   # limit is usually shared across the pool

_rate_limited: dict[str, float] = {}
_global_rate_limited_until: float = 0.0


class OpenRouterClient:

    def __init__(self) -> None:
        self.api_key  = _load_api_key()
        self._headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type":  "application/json",
            "HTTP-Referer":  "https://github.com/mark-xxv",
            "X-Title":       "MARK XXV",
        }

    def _is_rate_limited(self, model: str) -> bool:
        ts = _rate_limited.get(model)
        if ts is None:
            return False
        if time.time() - ts > RATE_LIMIT_COOLDOWN:
            del _rate_limited[model]
            return False
        return True

    def _mark_rate_limited(self, model: str) -> None:
        global _global_rate_limited_until
        _rate_limited[model] = time.time()
        # First 429 in a burst trips the short global circuit-breaker too —
        # see GLOBAL_RATE_LIMIT_COOLDOWN note above.
        _global_rate_limited_until = time.time() + GLOBAL_RATE_LIMIT_COOLDOWN
        logger.warning(
            f"[OpenRouter] Rate limited: {model} — "
            f"cooling down for {RATE_LIMIT_COOLDOWN}s "
            f"(global cooldown {GLOBAL_RATE_LIMIT_COOLDOWN}s)"
        )

    def _globally_rate_limited(self) -> bool:
        return time.time() < _global_rate_limited_until

    def _call(
        self,
        model: str,
        messages: list[dict],
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float = DEFAULT_TEMPERATURE,
        response_format: Optional[dict] = None,
    ) -> Optional[str]:
        payload: dict = {
            "model":       model,
            "messages":    messages,
            "max_tokens":  max_tokens,
            "temperature": temperature,
        }
        if response_format:
            payload["response_format"] = response_format

        for attempt in range(1, MAX_RETRIES_PER_MODEL + 1):
            try:
                resp = requests.post(
                    API_URL,
                    headers=self._headers,
                    json=payload,
                    timeout=REQUEST_TIMEOUT,
                )

                if resp.status_code == 429:
                    self._mark_rate_limited(model)
                    return None

                if resp.status_code == 200:
                    data    = resp.json()
                    content = (
                        data.get("choices", [{}])[0]
                            .get("message", {})
                            .get("content", "")
                    )
                    return content.strip() if content else None

                if resp.status_code == 404:
                    # Model slug doesn't exist (anymore). Don't just log and
                    # keep retrying it forever on every future call — drop it
                    # from the live cache for the rest of this process run so
                    # subsequent calls skip it immediately.
                    logger.warning(f"[OpenRouter] {model} → HTTP 404 (removing from pool)")
                    if model in _model_cache.get("text", []):
                        _model_cache["text"].remove(model)
                    if model in _model_cache.get("vision", []):
                        _model_cache["vision"].remove(model)
                    return None

                logger.warning(
                    f"[OpenRouter] {model} → HTTP {resp.status_code} "
                    f"(attempt {attempt}/{MAX_RETRIES_PER_MODEL})"
                )

            except requests.exceptions.Timeout:
                logger.warning(
                    f"[OpenRouter] {model} → Timeout "
                    f"(attempt {attempt}/{MAX_RETRIES_PER_MODEL})"
                )
            except Exception as e:
                logger.error(f"[OpenRouter] {model} → Unexpected error: {e}")

            if attempt < MAX_RETRIES_PER_MODEL:
                time.sleep(RETRY_DELAY)

        return None

    def _call_with_fallback(
        self,
        pool: list[str],
        messages: list[dict],
        model: Optional[str] = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float = DEFAULT_TEMPERATURE,
        response_format: Optional[dict] = None,
    ) -> str:
        # If we already know the whole pool is cooling down from a recent
        # 429 burst, fail fast instead of walking the entire list again —
        # this is what turned single calls into multi-minute stalls.
        if self._globally_rate_limited() and not (model and not self._is_rate_limited(model)):
            wait_left = round(_global_rate_limited_until - time.time(), 1)
            raise RuntimeError(
                f"[OpenRouter] All free models are cooling down from a recent "
                f"rate limit. Try again in ~{wait_left}s."
            )

        if model and not self._is_rate_limited(model):
            result = self._call(model, messages, max_tokens, temperature, response_format)
            if result:
                return result
            logger.info(
                f"[OpenRouter] Requested model failed, "
                f"falling back to pool: {model}"
            )

        for m in pool:
            if self._is_rate_limited(m):
                continue
            if self._globally_rate_limited():
                break
            logger.info(f"[OpenRouter] Trying: {m}")
            result = self._call(m, messages, max_tokens, temperature, response_format)
            if result:
                logger.info(f"[OpenRouter] ✓ Success: {m}")
                return result

        raise RuntimeError(
            "[OpenRouter] All models failed or are rate-limited. "
            "Check your API key and network connection."
        )

    def chat(
        self,
        prompt: str,
        system: str = (
            "You are a component of MARK XXV, an AI assistant inspired by JARVIS. "
            "Be concise, helpful, and precise."
        ),
        model: Optional[str] = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float = DEFAULT_TEMPERATURE,
    ) -> str:
        text_models, _ = _get_model_pools()
        messages = [
            {"role": "system", "content": system},
            {"role": "user",   "content": prompt},
        ]
        return self._call_with_fallback(
            text_models, messages, model, max_tokens, temperature
        )

    def chat_json(
        self,
        prompt: str,
        system: str = (
            "Return ONLY valid JSON. "
            "No markdown fences, no extra text, no explanation."
        ),
        model: Optional[str] = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> dict:
        text_models, _ = _get_model_pools()
        messages = [
            {"role": "system", "content": system},
            {"role": "user",   "content": prompt},
        ]
        raw = self._call_with_fallback(
            text_models, messages, model, max_tokens, temperature=0.2
        )

        clean = raw.strip()
        if clean.startswith("```"):
            parts = clean.split("```")
            clean = parts[1] if len(parts) > 1 else clean
            if clean.startswith("json"):
                clean = clean[4:]
        clean = clean.strip().rstrip("`").strip()

        try:
            return json.loads(clean)
        except json.JSONDecodeError as e:
            logger.error(
                f"[OpenRouter] JSON parse failed: {e}\n"
                f"Raw response (first 300 chars): {raw[:300]}"
            )
            raise ValueError(
                f"Model returned unparseable JSON: {e}\n"
                f"Raw output: {raw[:200]}"
            )

    def vision(
        self,
        prompt: str,
        image_b64: str,
        mime: str = "image/png",
        system: str = "Analyze the image and describe what you see clearly and concisely.",
        model: Optional[str] = None,
        max_tokens: int = 1024,
    ) -> str:
        _, vision_models = _get_model_pools()
        messages = [
            {"role": "system", "content": system},
            {
                "role": "user",
                "content": [
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:{mime};base64,{image_b64}"
                        },
                    },
                    {"type": "text", "text": prompt},
                ],
            },
        ]
        return self._call_with_fallback(
            vision_models, messages, model, max_tokens, temperature=0.2
        )

    def vision_from_file(
        self,
        prompt: str,
        image_path: str,
        system: str = "Analyze the image and describe what you see clearly and concisely.",
        model: Optional[str] = None,
        max_tokens: int = 1024,
    ) -> str:
        path = Path(image_path)
        mime_map = {
            ".png":  "image/png",
            ".jpg":  "image/jpeg",
            ".jpeg": "image/jpeg",
            ".webp": "image/webp",
            ".gif":  "image/gif",
        }
        mime = mime_map.get(path.suffix.lower(), "image/png")

        with open(path, "rb") as f:
            image_b64 = base64.b64encode(f.read()).decode("utf-8")

        return self.vision(prompt, image_b64, mime, system, model, max_tokens)

    def multi_turn(
        self,
        messages: list[dict],
        model: Optional[str] = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float = DEFAULT_TEMPERATURE,
    ) -> str:
        text_models, _ = _get_model_pools()
        return self._call_with_fallback(
            text_models, messages, model, max_tokens, temperature
        )

    def available_models(self) -> dict:
        text_models, vision_models = _get_model_pools()
        return {
            "text_models":   text_models,
            "vision_models": vision_models,
            "rate_limited":  list(_rate_limited.keys()),
            "total_text":    len(text_models),
            "total_vision":  len(vision_models),
            "globally_cooling_down": self._globally_rate_limited(),
        }

client = OpenRouterClient()

if __name__ == "__main__":
    print("=" * 55)
    print("  MARK XXV — OpenRouter Client Self-Test")
    print("=" * 55)

    print("\n[TEST 1] Basic chat...")
    try:
        reply = client.chat("Introduce yourself in one sentence.")
        print(f"  Response : {reply}")
        print(f"  Status   : PASS ✓")
    except Exception as e:
        print(f"  Status   : FAIL ✗ — {e}")

    print("\n[TEST 2] JSON mode...")
    try:
        data = client.chat_json(
            'List 3 programming languages. Format: {"languages": ["a", "b", "c"]}',
            system="Return only valid JSON. No extra text."
        )
        print(f"  Response : {data}")
        print(f"  Status   : PASS ✓")
    except Exception as e:
        print(f"  Status   : FAIL ✗ — {e}")

    print("\n[TEST 3] Multi-turn conversation...")
    try:
        history = [
            {"role": "system",    "content": "You are a helpful assistant. Be brief."},
            {"role": "user",      "content": "My name is Tony."},
            {"role": "assistant", "content": "Hello Tony, how can I help you?"},
            {"role": "user",      "content": "What is my name?"},
        ]
        reply = client.multi_turn(history)
        print(f"  Response : {reply}")
        print(f"  Status   : PASS ✓")
    except Exception as e:
        print(f"  Status   : FAIL ✗ — {e}")

    print("\n[TEST 4] Model pool info...")
    info = client.available_models()
    print(f"  Text models   : {info['total_text']}")
    print(f"  Vision models : {info['total_vision']}")
    print(f"  Rate limited  : {info['rate_limited'] or 'none'}")
    print(f"  Status        : PASS ✓")

    print("\n" + "=" * 55)
    print("  All tests complete.")
    print("=" * 55)