"""
core/face_verify.py — Offline face IDENTITY verification for JARVIS
========================================================================
core/sentinel_extras.py's detect_face_present() answers "is there a face
in this frame at all" using an OpenCV Haar cascade — that's DETECTION, not
recognition. It can't tell you from a stranger; any face in frame reads the
same. This module closes that gap: it recognizes WHOSE face it is, using
OpenCV's built-in LBPH (Local Binary Patterns Histograms) face recognizer.

Why LBPH instead of the more commonly-referenced `face_recognition`/dlib
stack: this project's own docs (core/sentinel_extras.py's module docstring)
already flagged dlib as "finicky to build in a Windows venv" and deliberately
left recognition unimplemented for that reason. LBPH ships inside
opencv-contrib-python (a drop-in superset of opencv-python — same `import
cv2`, prebuilt Windows wheels, no compiler needed) so this adds real
identity matching without introducing the exact dependency pain that was
avoided before.

THIS IS A TRUST SIGNAL, NOT A LOCK
------------------------------------
Same philosophy as core/speaker_verify.py:
- Never blocks anything by itself — it only tells the caller (currently
  core/intruder_alert.py) whether the face in an already-captured webcam
  snapshot matches the enrolled owner, so the alert can be worded/escalated
  accordingly ("looks like you" vs. "does NOT look like you" vs. "no face
  visible").
- LBPH confidence is a DISTANCE, not a similarity — LOWER is a better match.
  This is the opposite direction from speaker_verify's cosine similarity;
  don't copy that threshold logic by analogy.
- Lighting, camera angle, and enrollment photo quality all matter a lot.
  Calibrate the threshold against your own webcam before trusting this for
  anything beyond alert wording.

Usage
-----
    from core.face_verify import FaceVerifier

    fv = FaceVerifier()
    if not fv.is_enrolled():
        fv.enroll([jpeg1, jpeg2, jpeg3, jpeg4, jpeg5])

    result = fv.identify(webcam_jpeg_bytes)
    if result.enrolled and result.face_found and not result.accepted:
        # a face was captured, but it does NOT match the owner
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

from core.audit_log import AuditLog

# LBPH confidence is roughly 0 (identical) upward; there's no fixed upper
# bound like cosine similarity's [-1,1]. In practice, on a normal webcam:
#   < 50   : usually a strong match
#   50-80  : ambiguous — lighting/angle dependent
#   > 80   : usually a different person
# 75.0 is a reasonable starting point, NOT a calibrated value for your
# specific camera/lighting. See the module docstring.
DEFAULT_CONFIDENCE_THRESHOLD = 75.0
MIN_ENROLL_IMAGES = 5
OWNER_LABEL = 0  # LBPH needs an integer label per identity; single-owner setup


# Default Laplacian variance threshold for single-frame anti-spoofing heuristic.
# Real camera captures with genuine skin texture and high-frequency edge detail
# typically yield a Laplacian variance > 50-100 on a 200x200 face crop.
# Recaptured 2D printouts or screen displays subjected to blur/compression
# typically yield lower variance (< 30-50).
# NOTE: This is a heuristic trust signal, NOT a certainty. It must be calibrated
# against the specific webcam, sensor resolution, and lighting in use.
DEFAULT_SPOOF_LAPLACIAN_THRESHOLD = 50.0


def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


@dataclass
class IdentifyResult:
    enrolled: bool     # was there a trained profile to compare against
    face_found: bool   # did a face detector find anything in the frame
    accepted: bool      # face_found AND enrolled AND confidence <= threshold
    confidence: Optional[float] = None  # LBPH distance; lower = better match; None if N/A
    spoof_suspected: bool = False       # True if single-frame texture variance heuristic flags flat/recaptured image
    spoof_score: Optional[float] = None # Raw metric (Laplacian variance on cropped face patch)
    reason: str = ""


class FaceVerifier:
    """
    Offline face-identity check backed by OpenCV's LBPH recognizer.

    Model + metadata live as a pair of files (LBPH's own binary format
    doesn't do JSON, so the trained model and its metadata are split):
      memory/face_model.yml   — the trained LBPH model (OpenCV's own format)
      memory/face_profile.json — enrollment metadata + threshold
    """

    def __init__(
        self,
        base_path: Optional[Path] = None,
        threshold: Optional[float] = None,
        spoof_threshold: Optional[float] = None,
        access_control: Optional[Any] = None,
    ):
        base = base_path or (_base_dir() / "memory")
        base.mkdir(parents=True, exist_ok=True)
        self.model_path = base / "face_model.yml"
        self.meta_path = base / "face_profile.json"
        self._explicit_threshold = threshold
        self._explicit_spoof_threshold = spoof_threshold
        self._audit = AuditLog(path=base / "audit_log.jsonl")
        self._recognizer = None   # lazy-loaded cv2.face.LBPHFaceRecognizer
        self._cascade = None      # lazy-loaded cv2.CascadeClassifier
        self._access_control = access_control

    def _get_access_control(self):
        if self._access_control is None:
            from core.access_control import AccessControl
            self._access_control = AccessControl()
        return self._access_control

    def _verify_pin_gate(self, pin: Optional[str], action: str) -> None:
        """
        Enforces PIN verification before allowing face profile creation, overwrite, or deletion.
        If AccessControl is configured:
          - Requires valid PIN via AccessControl.verify_pin().
          - Fails loud with audit entry and raises PermissionError on invalid PIN, lockout, or missing PIN.
        If AccessControl credentials were deleted after initialization (tampered):
          - Fails closed with critical audit entry and raises PermissionError.
        If AccessControl is not configured (fresh install):
          - Allows operation with a warning in audit log.
        """
        ac = self._get_access_control()
        if getattr(ac, "is_tampered", lambda: False)():
            self._audit.append(f"{action}_failed_tampered", {
                "result": "denied",
                "reason": "credentials_deleted_tampering_detected",
            })
            raise PermissionError(f"Face profile {action} rejected: Security credentials tampered (missing after initialization).")

        if not ac.is_configured():
            self._audit.append(f"{action}_ungated_unconfigured", {
                "warning": "No Security PIN configured; face profile modification allowed without PIN gate"
            })
            return

        if not pin:
            self._audit.append(f"{action}_failed_no_pin", {
                "result": "denied",
                "reason": "missing_pin",
            })
            raise PermissionError(f"Face profile {action} rejected: Security PIN is required.")

        if not ac.verify_pin(pin, action=action):
            self._audit.append(f"{action}_failed_invalid_pin", {
                "result": "denied",
                "reason": "invalid_pin_or_locked",
            })
            raise PermissionError(f"Face profile {action} rejected: Invalid Security PIN or lockout active.")

    @property
    def threshold(self) -> float:
        if self._explicit_threshold is not None:
            return self._explicit_threshold
        if self.meta_path.exists():
            try:
                data = json.loads(self.meta_path.read_text(encoding="utf-8"))
                return float(data.get("threshold", DEFAULT_CONFIDENCE_THRESHOLD))
            except Exception:
                pass
        return DEFAULT_CONFIDENCE_THRESHOLD

    @property
    def spoof_threshold(self) -> float:
        if self._explicit_spoof_threshold is not None:
            return self._explicit_spoof_threshold
        if self.meta_path.exists():
            try:
                data = json.loads(self.meta_path.read_text(encoding="utf-8"))
                return float(data.get("spoof_threshold", DEFAULT_SPOOF_LAPLACIAN_THRESHOLD))
            except Exception:
                pass
        return DEFAULT_SPOOF_LAPLACIAN_THRESHOLD

    # ── lazy backends (dependency-injectable for testing) ────────────────

    def _get_cascade(self):
        if self._cascade is None:
            import cv2
            cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
            self._cascade = cv2.CascadeClassifier(cascade_path)
        return self._cascade

    def _get_recognizer(self):
        if self._recognizer is None:
            import cv2
            if not hasattr(cv2, "face") or not hasattr(cv2.face, "LBPHFaceRecognizer_create"):
                raise RuntimeError(
                    "cv2.face not found — this needs opencv-contrib-python, not "
                    "opencv-python. Run: pip uninstall opencv-python -y && "
                    "pip install opencv-contrib-python"
                )
            self._recognizer = cv2.face.LBPHFaceRecognizer_create()
        return self._recognizer

    def _detect_and_crop(self, jpeg_bytes: bytes):
        """Returns the largest detected face as a grayscale numpy array
        (resized to a fixed size for consistent LBPH training/prediction),
        or None if no face is found / the image can't be decoded."""
        if not jpeg_bytes:
            return None
        try:
            import cv2
            import numpy as np
            arr = np.frombuffer(jpeg_bytes, dtype="uint8")
            img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
            if img is None:
                return None
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            faces = self._get_cascade().detectMultiScale(
                gray, scaleFactor=1.1, minNeighbors=5, minSize=(60, 60)
            )
            if len(faces) == 0:
                return None
            # largest face = whoever is closest to the camera, i.e. most
            # likely the person actually at the keyboard
            x, y, w, h = max(faces, key=lambda f: f[2] * f[3])
            face = gray[y:y + h, x:x + w]
            return cv2.resize(face, (200, 200))
        except Exception as e:
            print(f"[FaceVerify] detect/crop failed: {type(e).__name__}: {e}")
            return None

    def _compute_spoof_metrics(self, face_patch) -> tuple[bool, float]:
        """
        Computes single-frame texture / sharpness metric using Laplacian variance.
        Returns (spoof_suspected, score).
        Lower variance indicates flat texture / blur characteristic of a 2D photo or screen recapture.
        """
        try:
            import cv2
            score = float(cv2.Laplacian(face_patch, cv2.CV_64F).var())
            spoof_suspected = score < self.spoof_threshold
            return spoof_suspected, score
        except Exception as e:
            print(f"[FaceVerify] spoof check failed: {type(e).__name__}: {e}")
            return False, 0.0

    # ── persistence ──────────────────────────────────────────────────────

    def is_enrolled(self) -> bool:
        return self.model_path.exists() and self.meta_path.exists()

    def reset(self, pin: Optional[str] = None) -> None:
        self._verify_pin_gate(pin, action="face_enroll_reset")
        for p in (self.model_path, self.meta_path):
            if p.exists():
                p.unlink()
        self._recognizer = None
        self._audit.append("face_enroll_reset", {"result": "success"})

    # ── enrollment ──────────────────────────────────────────────────────

    def enroll(self, jpeg_images: List[bytes], pin: Optional[str] = None) -> bool:
        """
        jpeg_images: MIN_ENROLL_IMAGES+ photos of you, ideally varying
        lighting/angle/distance from the webcam actually being used —
        LBPH generalizes better across conditions it's seen examples of.
        pin: Security PIN required if AccessControl is configured.
        """
        self._verify_pin_gate(pin, action="face_enroll")
        if len(jpeg_images) < MIN_ENROLL_IMAGES:
            raise ValueError(f"Need at least {MIN_ENROLL_IMAGES} images to enroll (got {len(jpeg_images)}).")

        import numpy as np
        faces = [f for f in (self._detect_and_crop(img) for img in jpeg_images) if f is not None]

        if len(faces) < MIN_ENROLL_IMAGES:
            self._audit.append("face_enroll", {
                "result": "failed", "reason": "too_few_usable_images",
                "usable": len(faces), "submitted": len(jpeg_images),
            })
            raise ValueError(
                f"Only {len(faces)}/{len(jpeg_images)} images had a detectable face. "
                f"Retake with better lighting, facing the camera, and try again."
            )

        recognizer = self._get_recognizer()
        labels = np.full(len(faces), OWNER_LABEL, dtype=np.int32)
        recognizer.train(faces, labels)
        recognizer.write(str(self.model_path))

        used_threshold = self.threshold
        used_spoof_threshold = self.spoof_threshold
        self.meta_path.write_text(json.dumps({
            "enrolled_at": time.time(),
            "n_images": len(faces),
            "threshold": used_threshold,
            "spoof_threshold": used_spoof_threshold,
        }), encoding="utf-8")
        try:
            os.chmod(self.meta_path, 0o600)
            os.chmod(self.model_path, 0o600)
        except Exception:
            pass

        self._audit.append("face_enroll", {
            "result": "success",
            "n_images": len(faces),
            "threshold": used_threshold,
            "spoof_threshold": used_spoof_threshold,
        })
        return True

    # ── identification ──────────────────────────────────────────────────

    def identify(self, jpeg_bytes: bytes, action: str = "intruder_alert") -> IdentifyResult:
        if not self.is_enrolled():
            # Same fail-open-at-this-layer contract as speaker_verify:
            # no profile means never set up, not a green light. Callers
            # must not treat enrolled=False as "assume it's the owner."
            face = self._detect_and_crop(jpeg_bytes)
            if face is None:
                return IdentifyResult(enrolled=False, face_found=False, accepted=False, reason="not_enrolled")
            spoof_suspected, spoof_score = self._compute_spoof_metrics(face)
            return IdentifyResult(
                enrolled=False,
                face_found=True,
                accepted=False,
                spoof_suspected=spoof_suspected,
                spoof_score=round(spoof_score, 2),
                reason="not_enrolled",
            )

        face = self._detect_and_crop(jpeg_bytes)
        if face is None:
            self._audit.append("face_identify", {"action": action, "result": "no_face_found"})
            return IdentifyResult(
                enrolled=True,
                face_found=False,
                accepted=False,
                reason="no_face_found",
            )

        # Compute liveness / anti-spoofing heuristic metric before LBPH prediction
        spoof_suspected, spoof_score = self._compute_spoof_metrics(face)

        try:
            recognizer = self._get_recognizer()
            recognizer.read(str(self.model_path))
            label, confidence = recognizer.predict(face)
        except Exception as e:
            print(f"[FaceVerify] predict failed: {type(e).__name__}: {e}")
            self._audit.append("face_identify", {
                "action": action,
                "result": "predict_error",
                "spoof_suspected": spoof_suspected,
                "spoof_score": round(spoof_score, 2),
            })
            return IdentifyResult(
                enrolled=True,
                face_found=True,
                accepted=False,
                confidence=None,
                spoof_suspected=spoof_suspected,
                spoof_score=round(spoof_score, 2),
                reason="predict_error",
            )

        # Lower confidence = better match, for LBPH specifically.
        # Note: accepted strictly reflects identity recognition (face_found AND enrolled AND confidence <= threshold).
        # Anti-spoofing signal is reported independently via spoof_suspected / spoof_score.
        accepted = (label == OWNER_LABEL) and (confidence <= self.threshold)
        self._audit.append("face_identify", {
            "action": action,
            "result": "accepted" if accepted else "rejected",
            "confidence": round(float(confidence), 2),
            "threshold": self.threshold,
            "spoof_suspected": spoof_suspected,
            "spoof_score": round(spoof_score, 2),
            "spoof_threshold": self.spoof_threshold,
        })
        return IdentifyResult(
            enrolled=True,
            face_found=True,
            accepted=accepted,
            confidence=float(confidence),
            spoof_suspected=spoof_suspected,
            spoof_score=round(spoof_score, 2),
            reason="" if accepted else "below_match_quality",
        )