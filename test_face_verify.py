"""
test_face_verify.py — Functional test of face verification logic
=====================================================================
Uses the REAL cv2.face.LBPHFaceRecognizer (not mocked — opencv-contrib-python
actually trains/predicts here) but mocks _detect_and_crop() to return
synthetic, deterministic face-sized patches instead of running Haar-cascade
detection on real photos, since there are no real face images to test with
in this environment. This exercises the real recognizer math while keeping
the test self-contained and deterministic.

Run: python test_face_verify.py
"""
import shutil
import sys
import tempfile
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent))

from core.face_verify import FaceVerifier, OWNER_LABEL


def make_synthetic_face(identity_seed: int, variant_seed: int, size: int = 200) -> np.ndarray:
    """Deterministic synthetic face-sized patch with a genuinely distinct
    LOCAL TEXTURE STRUCTURE per identity_seed (not just different random
    noise — LBPH keys off spatial texture patterns, and different draws of
    pure noise turn out to have very similar LBP histograms to each other,
    which made an earlier version of this test falsely pass an impostor as
    a match). Each identity gets its own combination of stripe frequency +
    orientation + a radial gradient, which produces a stable, distinct local
    binary pattern structure. variant_seed adds small per-photo jitter
    (brightness/noise) to simulate different shots of the same person."""
    rng = np.random.RandomState(identity_seed * 1000 + variant_seed)
    yy, xx = np.mgrid[0:size, 0:size]
    freq = 0.15 + (identity_seed % 5) * 0.08
    angle = (identity_seed % 4) * (np.pi / 4)
    stripes = np.sin(freq * (xx * np.cos(angle) + yy * np.sin(angle)))
    cx, cy = size / 2, size / 2
    radial = np.sqrt((xx - cx) ** 2 + (yy - cy) ** 2) / size
    base = (stripes * 0.5 + (1 - radial) * 0.5)
    jitter = rng.normal(0, 0.03, size=(size, size))
    img = np.clip((base + jitter) * 127 + 128, 0, 255).astype(np.uint8)
    return img


def fake_detect_and_crop_factory(image_map):
    """image_map: dict mapping a marker byte string (used as a stand-in
    'jpeg_bytes' key) -> the synthetic face array to return."""
    def _detect_and_crop(self, jpeg_bytes):
        return image_map.get(jpeg_bytes)
    return _detect_and_crop


def run():
    tmpdir = tempfile.mkdtemp()
    base = Path(tmpdir)

    # "Owner" face: same identity_seed (0), different variant_seed per shot
    # (simulates several different photos of the same person). "Impostor"
    # face: a different identity_seed, producing a genuinely different
    # texture structure, not just different noise.
    owner_variants = [make_synthetic_face(identity_seed=0, variant_seed=s) for s in range(6)]
    impostor_face = make_synthetic_face(identity_seed=2, variant_seed=0)

    owner_keys = [f"owner_{i}".encode() for i in range(len(owner_variants))]
    image_map = dict(zip(owner_keys, owner_variants))
    image_map[b"impostor"] = impostor_face
    image_map[b"no_face"] = None  # simulates a frame with nothing detected

    FaceVerifier._detect_and_crop = fake_detect_and_crop_factory(image_map)

    passed, failed = 0, 0

    def check(label, cond):
        nonlocal passed, failed
        if cond:
            print(f"  [PASS] {label}")
            passed += 1
        else:
            print(f"  [FAIL] {label}")
            failed += 1

    # ── 1. Identify before enrollment
    print("\n[1] Pre-enrollment behavior")
    fv = FaceVerifier(base_path=base)
    result = fv.identify(owner_keys[0], action="test")
    check("not enrolled -> enrolled=False", result.enrolled is False)
    check("not enrolled -> accepted=False (never a green light)", result.accepted is False)

    # ── 2. Enrollment requires minimum image count
    print("\n[2] Enrollment minimum-images guard")
    try:
        fv.enroll(owner_keys[:2])  # only 2, need MIN_ENROLL_IMAGES (5)
        check("rejects too-few images", False)
    except ValueError:
        check("rejects too-few images", True)

    # ── 3. Successful enrollment
    print("\n[3] Successful enrollment")
    ok = fv.enroll(owner_keys)  # all 6 owner variants
    check("enroll() returns True", ok is True)
    check("model file created", fv.model_path.exists())
    check("metadata file created", fv.meta_path.exists())
    import os
    mode = oct(os.stat(fv.meta_path).st_mode)[-3:]
    check(f"metadata file permissions restricted (got {mode})", mode in ("600", "644") or sys.platform == "win32")

    # ── 4. Identify with an owner variant -> should match
    print("\n[4] Genuine-face identification")
    result = fv.identify(owner_keys[0], action="test")
    check("enrolled=True", result.enrolled is True)
    check("face_found=True", result.face_found is True)
    check(f"accepted=True (confidence={result.confidence:.1f})", result.accepted is True)

    # ── 5. Identify with a clearly different face -> should reject
    print("\n[5] Impostor-face identification")
    result = fv.identify(b"impostor", action="test")
    check("enrolled=True", result.enrolled is True)
    check("face_found=True", result.face_found is True)
    check(f"accepted=False (confidence={result.confidence:.1f})", result.accepted is False)
    check("reason explains rejection", result.reason == "below_match_quality")

    # ── 6. No face detected in frame -> clean non-crash result
    print("\n[6] No-face-in-frame handling")
    result = fv.identify(b"no_face", action="test")
    check("face_found=False", result.face_found is False)
    check("accepted=False", result.accepted is False)
    check("reason flags missing face", result.reason == "no_face_found")

    # ── 7. Audit trail
    print("\n[7] Audit trail")
    from core.audit_log import AuditLog
    fv2 = FaceVerifier(base_path=base / "second_profile")
    fv2._audit = AuditLog(path=base / "audit2.jsonl")
    fv2.enroll(owner_keys)
    fv2.identify(owner_keys[0], action="test")
    entries = fv2._audit.read_all()
    check("enroll + identify both logged", len(entries) == 2)
    check("log integrity verifies clean", fv2._audit.verify()[0] is True)

    # ── 8. Reset removes the profile
    print("\n[8] Reset")
    fv.reset()
    check("model file removed after reset()", not fv.model_path.exists())
    check("metadata file removed after reset()", not fv.meta_path.exists())
    result = fv.identify(owner_keys[0], action="test")
    check("post-reset identify() is enrolled=False again", result.enrolled is False)

    shutil.rmtree(tmpdir, ignore_errors=True)

    print(f"\n{'='*50}\n{passed} passed, {failed} failed\n{'='*50}")
    return failed == 0


if __name__ == "__main__":
    ok = run()
    sys.exit(0 if ok else 1)