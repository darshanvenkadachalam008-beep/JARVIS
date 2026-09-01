"""
memory/memory_manager.py — Phase 3: Long-Term Brain
=====================================================
Structured memory system for JARVIS.  Stores and recalls:
  • identity      — name, age, city, job, etc.
  • preferences   — favourites, likes, dislikes
  • projects      — ongoing work and goals
  • relationships — people in the user's life
  • wishes        — future plans and wants
  • habits        — routines, schedules, patterns
  • goals         — short and long-term objectives
  • notes         — anything else

New in Phase 3:
  • conversation_summaries  — timestamped summaries run via Gemini
  • search_memory()         — keyword/category search across all facts
  • summarise_conversation() — Gemini-powered conversation summarisation
"""

import json
import re
from datetime import datetime
from threading import Lock
from pathlib import Path
import sys
import os

# ── Optional semantic search (sentence-transformers + numpy) ──────────────────
# Falls back gracefully to keyword search if not installed.
# Install with: pip install sentence-transformers
_SEMANTIC_OK = False
_embedder    = None
_embed_cache: dict = {}   # key → embedding vector (numpy array)

def _try_load_semantic():
    global _SEMANTIC_OK, _embedder
    if _SEMANTIC_OK:
        return True
    try:
        from sentence_transformers import SentenceTransformer
        import numpy as _np
        _embedder   = SentenceTransformer("all-MiniLM-L6-v2")
        _SEMANTIC_OK = True
        print("[Memory] 🧠 Semantic search active (sentence-transformers loaded)")
        return True
    except Exception:
        return False

def _embed(text: str):
    """Return embedding for text; cached by text content."""
    import numpy as _np
    if text in _embed_cache:
        return _embed_cache[text]
    vec = _embedder.encode(text, normalize_embeddings=True)
    _embed_cache[text] = vec
    return vec

def _cosine(a, b) -> float:
    import numpy as _np
    return float(_np.dot(a, b))  # already normalised


def get_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


BASE_DIR         = get_base_dir()
MEMORY_PATH      = BASE_DIR / "memory" / "long_term.json"
SUMMARIES_PATH   = BASE_DIR / "memory" / "conversation_summaries.json"
_lock            = Lock()
MAX_VALUE_LENGTH = 380
MEMORY_MAX_CHARS = 4000          # raised from 2200 for richer Phase 3 data
MAX_SUMMARIES    = 50            # rolling window of past conversation summaries


# ── Schema ───────────────────────────────────────────────────────────────────

def _empty_memory() -> dict:
    return {
        "identity":      {},
        "preferences":   {},
        "projects":      {},
        "relationships": {},
        "wishes":        {},
        "habits":        {},
        "goals":         {},
        "notes":         {},
    }


# ── Load / Save ───────────────────────────────────────────────────────────────

def load_memory() -> dict:
    if not MEMORY_PATH.exists():
        return _empty_memory()
    with _lock:
        try:
            data = json.loads(MEMORY_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                base = _empty_memory()
                for key in base:
                    if key not in data:
                        data[key] = {}
                return data
            return _empty_memory()
        except Exception as e:
            print(f"[Memory] ⚠️ Load error: {e}")
            return _empty_memory()


def _all_entries(memory: dict) -> list:
    entries = []
    for cat, items in memory.items():
        if not isinstance(items, dict):
            continue
        for key, entry in items.items():
            if isinstance(entry, dict) and "value" in entry:
                entries.append((cat, key, entry))
    return entries


def _trim_to_limit(memory: dict) -> dict:
    serialized = json.dumps(memory, ensure_ascii=False)
    if len(serialized) <= MEMORY_MAX_CHARS:
        return memory
    entries = _all_entries(memory)
    entries.sort(key=lambda t: t[2].get("updated", "0000-00-00"))
    for cat, key, _ in entries:
        if len(json.dumps(memory, ensure_ascii=False)) <= MEMORY_MAX_CHARS:
            break
        del memory[cat][key]
        print(f"[Memory] 🗑️  Trimmed {cat}/{key}")
    return memory


def save_memory(memory: dict) -> None:
    if not isinstance(memory, dict):
        return
    memory = _trim_to_limit(memory)
    MEMORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        MEMORY_PATH.write_text(
            json.dumps(memory, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )


def _truncate_value(val: str) -> str:
    if isinstance(val, str) and len(val) > MAX_VALUE_LENGTH:
        return val[:MAX_VALUE_LENGTH].rstrip() + "…"
    return val


def _recursive_update(target: dict, updates: dict) -> bool:
    changed = False
    for key, value in updates.items():
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        if isinstance(value, dict) and "value" not in value:
            if key not in target or not isinstance(target[key], dict):
                target[key] = {}
                changed = True
            if _recursive_update(target[key], value):
                changed = True
        else:
            if isinstance(value, dict) and "value" in value:
                new_val = _truncate_value(str(value["value"]))
            else:
                new_val = _truncate_value(str(value))
            entry    = {"value": new_val, "updated": datetime.now().strftime("%Y-%m-%d")}
            existing = target.get(key, {})
            if not isinstance(existing, dict) or existing.get("value") != new_val:
                target[key] = entry
                changed = True
    return changed


def update_memory(memory_update: dict) -> dict:
    if not isinstance(memory_update, dict) or not memory_update:
        return load_memory()
    memory = load_memory()
    if _recursive_update(memory, memory_update):
        save_memory(memory)
        print(f"[Memory] 💾 Saved: {list(memory_update.keys())}")
    return memory


# ── Conversation Summaries ────────────────────────────────────────────────────

def load_summaries() -> list:
    if not SUMMARIES_PATH.exists():
        return []
    try:
        data = json.loads(SUMMARIES_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def save_summaries(summaries: list) -> None:
    SUMMARIES_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Keep a rolling window
    summaries = summaries[-MAX_SUMMARIES:]
    SUMMARIES_PATH.write_text(
        json.dumps(summaries, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )


def store_conversation_summary(summary: str, topics: list = None) -> None:
    """Append a new conversation summary with timestamp."""
    summaries = load_summaries()
    summaries.append({
        "timestamp": datetime.now().isoformat(),
        "date":      datetime.now().strftime("%A, %B %d %Y at %I:%M %p"),
        "summary":   summary,
        "topics":    topics or [],
    })
    save_summaries(summaries)
    print(f"[Memory] 📝 Summary stored ({len(summary)} chars)")


def summarise_conversation(user_text: str, jarvis_text: str, api_key: str) -> str:
    """
    Run a Gemini Flash call to summarise a conversation exchange and
    extract key topics.  Stores the result automatically.
    Returns the summary string (or "" on failure).
    """
    if not user_text or len(user_text) < 20:
        return ""
    try:
        from google import genai

        client = genai.Client(
            api_key=api_key,
            http_options={"api_version": "v1beta"}
        )

        prompt = (
            "Summarise this conversation exchange in 1-2 concise sentences "
            "that JARVIS can use later to say 'last time you asked about X…'. "
            "Then on a new line write: TOPICS: comma-separated keywords.\n\n"
            f"User: {user_text[:800]}\n"
            f"JARVIS: {jarvis_text[:400]}"
        )

        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
        )
        raw = (response.text or "").strip()
        if not raw:
            return ""

        # Parse topics line
        topics = []
        summary = raw
        if "TOPICS:" in raw.upper():
            parts  = re.split(r"TOPICS\s*:", raw, flags=re.IGNORECASE, maxsplit=1)
            summary = parts[0].strip()
            topics  = [t.strip() for t in parts[1].split(",") if t.strip()]

        store_conversation_summary(summary, topics)
        return summary

    except Exception as e:
        if "429" not in str(e):
            print(f"[Memory] ⚠️ Summarise failed: {e}")
        return ""


# ── Memory Search ─────────────────────────────────────────────────────────────

def search_memory(query: str) -> dict:
    """
    Search all memory categories and conversation summaries for the query.

    Uses semantic (embedding-based) search when sentence-transformers is
    installed, falling back to keyword search otherwise.  Semantic search
    finds "my sister's birthday" even when you ask "family event" or
    "when is the party" — it understands meaning, not just exact words.

    Returns a dict:
      {
        "facts":     [(category, key, value, updated), ...],
        "summaries": [(date, summary, topics), ...],
      }
    """
    q = query.lower().strip()
    if not q:
        return {"facts": [], "summaries": []}

    memory    = load_memory()
    summaries = load_summaries()

    use_semantic = _try_load_semantic()

    if use_semantic:
        # ── Semantic search ───────────────────────────────────────────────
        q_vec = _embed(query)
        THRESHOLD = 0.35  # cosine similarity floor (0=unrelated, 1=identical)

        scored_facts = []
        for cat, items in memory.items():
            if not isinstance(items, dict):
                continue
            for key, entry in items.items():
                if not isinstance(entry, dict):
                    continue
                val  = str(entry.get("value", ""))
                text = f"{cat} {key.replace('_',' ')} {val}"
                score = _cosine(q_vec, _embed(text))
                if score >= THRESHOLD:
                    scored_facts.append((score, cat, key, val, entry.get("updated", "")))

        scored_facts.sort(key=lambda x: x[0], reverse=True)
        matched_facts = [(c, k, v, u) for _, c, k, v, u in scored_facts[:12]]

        scored_sums = []
        for s in summaries:
            text  = s.get("summary", "") + " " + " ".join(s.get("topics", []))
            score = _cosine(q_vec, _embed(text))
            if score >= THRESHOLD:
                scored_sums.append((score, s.get("date", ""), s.get("summary", ""), s.get("topics", [])))
        scored_sums.sort(key=lambda x: x[0], reverse=True)
        matched_summaries = [(d, sm, t) for _, d, sm, t in scored_sums[:6]]

    else:
        # ── Keyword fallback ──────────────────────────────────────────────
        matched_facts = []
        for cat, items in memory.items():
            if not isinstance(items, dict):
                continue
            for key, entry in items.items():
                if not isinstance(entry, dict):
                    continue
                val = str(entry.get("value", ""))
                if (q in key.lower() or q in val.lower() or q in cat.lower() or
                        any(q in word for word in key.lower().split("_"))):
                    matched_facts.append((cat, key, val, entry.get("updated", "")))

        matched_summaries = []
        for s in reversed(summaries):
            text = s.get("summary", "") + " " + " ".join(s.get("topics", []))
            if q in text.lower():
                matched_summaries.append((s.get("date",""), s.get("summary",""), s.get("topics",[])))

    return {"facts": matched_facts, "summaries": matched_summaries}


def format_search_results(query: str, results: dict) -> str:
    """Format search results for JARVIS to speak."""
    facts     = results.get("facts", [])
    summaries = results.get("summaries", [])

    if not facts and not summaries:
        return f"I found nothing in my memory about '{query}', sir."

    lines = [f"Here is what I remember about '{query}':"]

    if facts:
        lines.append("")
        lines.append(f"Stored facts ({len(facts)}):")
        for cat, key, val, updated in facts[:8]:
            label = key.replace("_", " ").title()
            lines.append(f"  • [{cat}] {label}: {val}")

    if summaries:
        lines.append("")
        lines.append(f"Past conversations ({len(summaries)}):")
        for date, summary, topics in summaries[:5]:
            lines.append(f"  • {date} — {summary}")

    return "\n".join(lines)


# ── Memory Extraction (existing, unchanged from Phase 2) ─────────────────────

def should_extract_memory(user_text: str, jarvis_text: str, api_key: str = "") -> bool:
    try:
        from or_client import client

        combined = f"User: {user_text[:300]}\nJarvis: {jarvis_text[:1000]}"
        result = client.chat(
            f"Does this conversation contain ANY of the following?\n"
            f"- Personal facts (name, age, city, job, birthday, nationality)\n"
            f"- Preferences or favorites (food, color, music, sport, game, film, book, etc.)\n"
            f"- Active projects or goals the user is working on\n"
            f"- People in the user's life (friends, family, partner, colleagues)\n"
            f"- Things the user wants to do or buy in the future\n"
            f"- Habits, routines, or regular patterns\n"
            f"- Short-term or long-term goals\n"
            f"- Any other fact worth remembering long-term\n\n"
            f"Reply only YES or NO.\n\nConversation:\n{combined}",
            system="You are a memory relevance checker. Reply only YES or NO.",
            max_tokens=5,
            temperature=0.0,
        )
        return "YES" in result.upper()
    except Exception as e:
        print(f"[Memory] ⚠️ Stage1 check failed: {e}")
        return False


def extract_memory(user_text: str, jarvis_text: str, api_key: str = "") -> dict:
    try:
        from or_client import client

        combined = f"User: {user_text[:600]}\nJarvis: {jarvis_text[:300]}"
        raw = client.chat(
            f"Extract ALL memorable personal facts from this conversation. Any language.\n"
            f"Return ONLY valid JSON. Use {{}} if truly nothing is worth saving.\n\n"
            f"Category guide:\n"
            f"  identity      → name, age, birthday, city, country, job, school, nationality, language\n"
            f"  preferences   → ANY favorite or preferred thing: food, color, music, film, game, sport, book, etc.\n"
            f"  projects      → projects being built, ongoing work, goals, ideas in progress\n"
            f"  relationships → people mentioned: friends, family, partner, colleagues\n"
            f"  wishes        → future plans, things to buy, travel plans, dreams\n"
            f"  habits        → routines, schedules, recurring patterns (e.g. works_at_night, morning_gym)\n"
            f"  goals         → specific short or long-term objectives (e.g. learn_spanish, lose_10kg)\n"
            f"  notes         → anything else worth remembering\n\n"
            f"Format:\n"
            f'{{\"identity\":{{\"name\":{{\"value\":\"Ali\"}}}},\n'
            f' \"habits\":{{\"works_at_night\":{{\"value\":\"usually active late at night\"}}}},\n'
            f' \"goals\":{{\"learn_spanish\":{{\"value\":\"wants to reach B2 level by end of year\"}}}}}}\n\n'
            f"Conversation:\n{combined}\n\nJSON:",
            system="Return ONLY valid JSON. No markdown, no explanation, no extra text.",
            max_tokens=1024,
            temperature=0.2,
        )

        clean = raw.strip()
        clean = re.sub(r"```(?:json)?", "", clean).strip().rstrip("`").strip()
        if not clean or clean == "{}":
            return {}
        return json.loads(clean)

    except json.JSONDecodeError:
        return {}
    except Exception as e:
        if "429" not in str(e):
            print(f"[Memory] ⚠️ Extract failed: {e}")
        return {}


# ── Prompt Formatter ──────────────────────────────────────────────────────────

def format_memory_for_prompt(memory: dict | None) -> str:
    if not memory:
        return ""

    lines = []

    # Identity
    identity  = memory.get("identity", {})
    id_fields = ["name", "age", "birthday", "city", "job", "language", "school", "nationality"]
    for field in id_fields:
        entry = identity.get(field)
        if entry:
            val = entry.get("value") if isinstance(entry, dict) else entry
            if val:
                lines.append(f"{field.title()}: {val}")
    for key, entry in identity.items():
        if key in id_fields:
            continue
        val = entry.get("value") if isinstance(entry, dict) else entry
        if val:
            lines.append(f"{key.replace('_', ' ').title()}: {val}")

    # Preferences
    prefs = memory.get("preferences", {})
    if prefs:
        lines.append("")
        lines.append("Preferences:")
        for key, entry in list(prefs.items())[:15]:
            val = entry.get("value") if isinstance(entry, dict) else entry
            if val:
                lines.append(f"  - {key.replace('_', ' ').title()}: {val}")

    # Projects
    projects = memory.get("projects", {})
    if projects:
        lines.append("")
        lines.append("Active Projects / Goals:")
        for key, entry in list(projects.items())[:8]:
            val = entry.get("value") if isinstance(entry, dict) else entry
            if val:
                lines.append(f"  - {key.replace('_', ' ').title()}: {val}")

    # Relationships
    rels = memory.get("relationships", {})
    if rels:
        lines.append("")
        lines.append("People in their life:")
        for key, entry in list(rels.items())[:10]:
            val = entry.get("value") if isinstance(entry, dict) else entry
            if val:
                lines.append(f"  - {key.replace('_', ' ').title()}: {val}")

    # Wishes
    wishes = memory.get("wishes", {})
    if wishes:
        lines.append("")
        lines.append("Wishes / Plans / Wants:")
        for key, entry in list(wishes.items())[:8]:
            val = entry.get("value") if isinstance(entry, dict) else entry
            if val:
                lines.append(f"  - {key.replace('_', ' ').title()}: {val}")

    # Habits
    habits = memory.get("habits", {})
    if habits:
        lines.append("")
        lines.append("Habits / Routines:")
        for key, entry in list(habits.items())[:8]:
            val = entry.get("value") if isinstance(entry, dict) else entry
            if val:
                lines.append(f"  - {key.replace('_', ' ').title()}: {val}")

    # Goals
    goals = memory.get("goals", {})
    if goals:
        lines.append("")
        lines.append("Goals:")
        for key, entry in list(goals.items())[:8]:
            val = entry.get("value") if isinstance(entry, dict) else entry
            if val:
                lines.append(f"  - {key.replace('_', ' ').title()}: {val}")

    # Recent conversation summaries (last 3)
    summaries = load_summaries()
    if summaries:
        lines.append("")
        lines.append("Recent conversation context:")
        for s in summaries[-3:]:
            lines.append(f"  - [{s.get('date', '')}] {s.get('summary', '')}")

    # Notes
    notes = memory.get("notes", {})
    if notes:
        lines.append("")
        lines.append("Other notes:")
        for key, entry in list(notes.items())[:8]:
            val = entry.get("value") if isinstance(entry, dict) else entry
            if val:
                lines.append(f"  - {key}: {val}")

    if not lines:
        return ""

    header = "[WHAT YOU KNOW ABOUT THIS PERSON — use naturally, never recite like a list]\n"
    result = header + "\n".join(lines)
    if len(result) > 3000:
        result = result[:2997] + "…"

    return result + "\n"


# ── Simple helpers ────────────────────────────────────────────────────────────

def remember(key: str, value: str, category: str = "notes") -> str:
    valid = {"identity", "preferences", "projects", "relationships",
             "wishes", "habits", "goals", "notes"}
    if category not in valid:
        category = "notes"
    update_memory({category: {key: {"value": value}}})
    return f"Remembered: {category}/{key} = {value}"


def forget(key: str, category: str = "notes") -> str:
    memory = load_memory()
    cat    = memory.get(category, {})
    if key in cat:
        del cat[key]
        memory[category] = cat
        save_memory(memory)
        return f"Forgotten: {category}/{key}"
    return f"Not found: {category}/{key}"


forget_memory = forget