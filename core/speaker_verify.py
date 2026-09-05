"""
core/speaker_verify.py — Offline speaker verification for JARVIS
===================================================================
Wake-word detection (core/wake_word.py) proves someone SAID "Hey Jarvis" —
it says nothing about WHO said it. Right now any voice in mic range that
matches the phrase gets JARVIS's full attention, and everything downstream
(typed/spoken commands, PIN prompts) implicitly assumes it's already you at
the keyboard. This module closes that gap: it turns the audio captured at
wake-word time into a fixed-length voice fingerprint and compares it against
your enrolled profile — fully offline, on-device, no API call involved.

Uses Resemblyzer (https://github.com/resemble-ai/Resemblyzer, Apache-2.0), a
lightweight speaker-embedding model. Its pretrained weights ship bundled
inside the pip package itself, so — same philosophy as core/wake_word.py's
openWakeWord integration — no download step and no internet connection is
needed after `pip install resemblyzer`.

THIS IS A TRUST SIGNAL, NOT A REPLACEMENT FOR THE PIN GATE
------------------------------------------------------------
- It does NOT replace core/access_control.py. A PIN is still required for
  destructive actions regardless of voice match — voice verification is an
  additional layer, not a substitute.
- Its job is to flag "this wake word was NOT spoken in your enrolled voice"
  so the caller can raise friction for the rest of that session: refuse to
  relax PIN requirements, log it, and optionally alert.
- Voice embeddings are imperfect. A cold, a bad mic day, or background noise
  can drop the score. Callers should treat a rejection as "don't extend
  extra trust" rather than "lock the user out of their own assistant" —
  typed/PIN-gated access must always remain available regardless of this
  module's verdict.

Usage
-----
    from core.speaker_verify import SpeakerVerifier

    sv = SpeakerVerifier()
    if not sv.is_enrolled():
        sv.enroll([clip1, clip2, clip3, clip4], sample_rate=16000)

    result = sv.verify(captured_audio, sample_rate=16000)
    if result.enrolled and not result.accepted:
        # wake word was spoken, but not by the enrolled voice
        ...
"""
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import numpy as np

from core.audit_log import AuditLog

# Cosine similarity threshold. Resemblyzer same-speaker utterances typically
# score ~0.75-0.9; different speakers ~0.5-0.65 on short clips — 0.72 is a
# reasonable starting point, but MIC/ROOM DEPENDENT. Run calibrate() (bottom
# of this file) against your own enrolled voice vs. a couple of other
# speakers before trusting this for anything more than logging, and adjust
# via SpeakerVerifier(threshold=...) or the "threshold" field in
# memory/voice_profile.json once enrolled.
DEFAULT_THRESHOLD = 0.72
MIN_ENROLL_CLIPS = 3
MIN_USABLE_SECONDS = 0.4  # clips shorter than this can't be embedded reliably


def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


@dataclass
class VerifyResult:
    enrolled: bool   # was there a profile to compare against at all
    accepted: bool   # score >= threshold (always False if not enrolled)
    score: float      # cosine similarity, roughly -1..1 (0.0 if N/A)
    reason: str = ""


class SpeakerVerifier:
    """
    Offline voice-identity check backed by Resemblyzer embeddings.

    The encoder is loaded lazily on first real use (enroll/verify), not on
    import or __init__ — most app startups shouldn't pay a torch-import
    cost just because this module exists in the codebase.
    """

    def __init__(self, path: Optional[Path] = None, threshold: Optional[float] = None, bridge: Optional[Any] = None):
        self.path = path or (_base_dir() / "memory" / "voice_profile.json")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._explicit_threshold = threshold
        self._audit = AuditLog()
        self._encoder = None  # lazy-loaded resemblyzer.VoiceEncoder
        self._bridge = bridge

    def set_bridge(self, bridge: Optional[Any]) -> None:
        self._bridge = bridge

    def trigger_voice_auth_alert(
        self,
        action: str = "voice_auth",
        score: Optional[float] = None,
        snapshot_bytes: Optional[bytes] = None,
        bridge: Optional[Any] = None,
    ) -> dict:
        """Dispatches a unified security alert for voice verification failure."""
        try:
            from core.unified_security_alert import dispatch_security_alert
            return dispatch_security_alert(
                trigger_type="jarvis_voice_auth_failure",
                actor="user",
                details={"action": action, "score": score, "threshold": self.threshold},
                snapshot_bytes=snapshot_bytes,
                bridge=bridge or getattr(self, "_bridge", None),
            )
        except Exception as e:
            print(f"[SpeakerVerify] Voice auth alert dispatch error: {e}")
            return {}

    @property
    def threshold(self) -> float:
        if self._explicit_threshold is not None:
            return self._explicit_threshold
        # fall back to whatever was recorded at enrollment time, if any
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                return float(data.get("threshold", DEFAULT_THRESHOLD))
            except Exception:
                pass
        return DEFAULT_THRESHOLD

    # ── encoder lifecycle (dependency injectable for testing) ────────────

    def _get_encoder(self):
        if self._encoder is None:
            from resemblyzer import VoiceEncoder  # heavy import, deferred
            self._encoder = VoiceEncoder()
        return self._encoder

    def _embed(self, audio: np.ndarray, sample_rate: int) -> Optional[np.ndarray]:
        """Raw PCM -> 256-dim embedding. Returns None (never raises) on a
        too-short/silent/corrupt clip so callers in a live audio pipeline
        degrade gracefully instead of crashing."""
        try:
            from resemblyzer import preprocess_wav
            wav = np.asarray(audio).astype(np.float32)
            if wav.size == 0:
                return None
            if wav.max() > 1.0 or wav.min() < -1.0:
                wav = wav / 32768.0  # int16 range -> float32 [-1, 1]
            wav = preprocess_wav(wav, source_sr=sample_rate)
            if wav.size < sample_rate * MIN_USABLE_SECONDS:
                return None
            return self._get_encoder().embed_utterance(wav)
        except Exception as e:
            print(f"[SpeakerVerify] embedding failed: {type(e).__name__}: {e}")
            return None

    # ── persistence ──────────────────────────────────────────────────────

    def is_enrolled(self) -> bool:
        return self.path.exists()

    def _save(self, embedding: np.ndarray, n_clips: int, threshold: float) -> None:
        data = {
            "embedding": embedding.tolist(),
            "dim": int(embedding.shape[0]),
            "enrolled_at": time.time(),
            "n_clips": n_clips,
            "threshold": threshold,
        }
        self.path.write_text(json.dumps(data), encoding="utf-8")
        try:
            os.chmod(self.path, 0o600)
        except Exception:
            pass

    def _load_embedding(self) -> Optional[np.ndarray]:
        if not self.path.exists():
            return None
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return np.array(data["embedding"], dtype=np.float32)
        except Exception:
            return None

    # ── enrollment ──────────────────────────────────────────────────────

    def enroll(self, clips: List[np.ndarray], sample_rate: int = 16000) -> bool:
        """
        clips: MIN_ENROLL_CLIPS+ short recordings of you speaking — ideally
        the wake phrase itself plus a couple of ordinary sentences, recorded
        at different times/distances from the mic. More phrasing variety
        makes the profile robust to more than one fixed phrase.
        """
        if len(clips) < MIN_ENROLL_CLIPS:
            raise ValueError(f"Need at least {MIN_ENROLL_CLIPS} clips to enroll (got {len(clips)}).")

        embeddings = [e for e in (self._embed(c, sample_rate) for c in clips) if e is not None]

        if len(embeddings) < MIN_ENROLL_CLIPS:
            self._audit.append("speaker_enroll", {
                "result": "failed", "reason": "too_few_usable_clips",
                "usable": len(embeddings), "submitted": len(clips),
            })
            raise ValueError(
                f"Only {len(embeddings)}/{len(clips)} clips were usable (too short/silent). "
                f"Record clearer, ~2s+ samples and try again."
            )

        centroid = np.mean(embeddings, axis=0)
        centroid = centroid / np.linalg.norm(centroid)
        used_threshold = self.threshold
        self._save(centroid, n_clips=len(embeddings), threshold=used_threshold)
        self._audit.append("speaker_enroll", {"result": "success", "n_clips": len(embeddings),
                                                "threshold": used_threshold})
        return True

    def reset(self) -> None:
        """Deletes the enrolled profile (e.g. before re-enrolling)."""
        if self.path.exists():
            self.path.unlink()
        self._audit.append("speaker_enroll_reset", {})

    # ── verification ────────────────────────────────────────────────────

    def verify(self, audio: np.ndarray, sample_rate: int = 16000, action: str = "wake") -> VerifyResult:
        profile = self._load_embedding()
        if profile is None:
            # Fail-open at THIS layer only: no enrolled profile means voice
            # verification was never set up, so don't block wake-up itself
            # (that would brick the assistant for anyone who hasn't
            # enrolled yet). Callers must treat enrolled=False as "no extra
            # trust granted" — not as a green light — and keep relying on
            # the PIN gate for anything sensitive.
            return VerifyResult(enrolled=False, accepted=False, score=0.0, reason="not_enrolled")

        emb = self._embed(audio, sample_rate)
        if emb is None:
            self._audit.append("speaker_verify", {"action": action, "result": "no_usable_audio", "score": None})
            return VerifyResult(enrolled=True, accepted=False, score=0.0, reason="unusable_audio")

        score = float(np.dot(profile, emb) / (np.linalg.norm(profile) * np.linalg.norm(emb) + 1e-9))
        accepted = score >= self.threshold
        self._audit.append("speaker_verify", {
            "action": action,
            "result": "accepted" if accepted else "rejected",
            "score": round(score, 4),
            "threshold": self.threshold,
        })
        return VerifyResult(enrolled=True, accepted=accepted, score=score,
                             reason="" if accepted else "below_threshold")


# ── Calibration helper ────────────────────────────────────────────────────
def calibrate(own_clips: List[np.ndarray], other_clips: List[np.ndarray], sample_rate: int = 16000) -> dict:
    """
    Feed this a handful of your own clips and a handful of clips from other
    voices (a family member, a YouTube clip, anything) to see where genuine
    vs. impostor scores actually land on YOUR mic/room before trusting the
    default threshold. Returns summary stats — does not modify any profile.
    """
    sv = SpeakerVerifier()
    own_embs = [e for e in (sv._embed(c, sample_rate) for c in own_clips) if e is not None]
    other_embs = [e for e in (sv._embed(c, sample_rate) for c in other_clips) if e is not None]
    if len(own_embs) < 2:
        raise ValueError("Need at least 2 usable clips of your own voice to calibrate.")

    centroid = np.mean(own_embs, axis=0)
    centroid = centroid / np.linalg.norm(centroid)

    def sim(e):
        return float(np.dot(centroid, e) / (np.linalg.norm(centroid) * np.linalg.norm(e) + 1e-9))

    genuine_scores = [sim(e) for e in own_embs]
    impostor_scores = [sim(e) for e in other_embs] if other_embs else []

    return {
        "genuine_min": min(genuine_scores), "genuine_max": max(genuine_scores),
        "genuine_mean": sum(genuine_scores) / len(genuine_scores),
        "impostor_max": max(impostor_scores) if impostor_scores else None,
        "impostor_mean": (sum(impostor_scores) / len(impostor_scores)) if impostor_scores else None,
        "suggested_threshold": (
            round((min(genuine_scores) + max(impostor_scores)) / 2, 3)
            if impostor_scores else round(min(genuine_scores) - 0.05, 3)
        ),
    }