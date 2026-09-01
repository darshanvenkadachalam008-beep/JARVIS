"""
enroll_face.py — One-time face enrollment for face identity verification
============================================================================
Captures a handful of webcam photos and trains the LBPH profile that
core/face_verify.py compares future intruder-alert snapshots against.
Run this once (re-run with --reset to replace it).

Usage
-----
    python enroll_face.py                 # interactive, captures via webcam
    python enroll_face.py --reset         # deletes the existing profile
    python enroll_face.py --camera 1      # use a specific camera index

Notes
-----
- Vary lighting, angle, and distance across shots — a profile trained on
  five identical photos generalizes worse than one trained on five
  different real conditions.
- This only builds the face profile. It does NOT touch your PIN
  (core/access_control.py), vault (core/secure_vault.py), or voice profile
  (core/speaker_verify.py) — those stay exactly as configured.
- Needs opencv-contrib-python (not plain opencv-python) for cv2.face —
  see requirements.txt.
"""
from __future__ import annotations

import argparse
import getpass
import sys
import time

from core.face_verify import FaceVerifier, MIN_ENROLL_IMAGES
from core.access_control import AccessControl


def verify_identity_for_reset(ac: AccessControl) -> bool:
    """
    Verifies owner identity before allowing face profile deletion or replacement.
    If AccessControl has a PIN configured, prompts for PIN using getpass and verifies it.
    If no PIN is configured, allows reset but displays a warning.
    """
    if not ac.is_configured():
        print("WARNING: No security PIN is configured. Face enrollment reset is proceeding ungated.")
        return True

    pin = getpass.getpass("Enter current Security PIN to authorize face profile reset: ")
    if not pin or not ac.verify_pin(pin, action="face_enrollment_reset"):
        print("FAILED: Incorrect PIN or lockout active. Face profile was NOT modified.")
        return False

    print("OK: PIN verified. Proceeding with face profile reset.")
    return True


def capture_photo(camera_index: int):
    import cv2
    cap = cv2.VideoCapture(camera_index)
    try:
        if not cap.isOpened():
            print(f"Could not open camera index {camera_index}.")
            return None
        for _ in range(5):  # let auto-exposure settle
            cap.read()
        ok, frame = cap.read()
        if not ok or frame is None:
            print("Webcam read failed.")
            return None
        ok, buf = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 90])
        return bytes(buf) if ok else None
    finally:
        cap.release()


def main():
    parser = argparse.ArgumentParser(description="Enroll your face for JARVIS face verification.")
    parser.add_argument("--reset", action="store_true", help="Delete the existing face profile and exit.")
    parser.add_argument("--camera", type=int, default=0, help="Camera device index (default 0).")
    parser.add_argument("--images", type=int, default=max(MIN_ENROLL_IMAGES, 6),
                         help=f"How many photos to capture (min {MIN_ENROLL_IMAGES}).")
    args = parser.parse_args()

    fv = FaceVerifier()
    ac = AccessControl()

    if args.reset:
        if not verify_identity_for_reset(ac):
            sys.exit(1)
        fv.reset()
        print("Face profile deleted. Run without --reset to enroll again.")
        return

    if fv.is_enrolled():
        answer = input("A face profile already exists. Replace it? [y/N]: ").strip().lower()
        if answer != "y":
            print("Cancelled - existing profile kept.")
            return
        if not verify_identity_for_reset(ac):
            sys.exit(1)
        fv.reset()

    n_images = max(args.images, MIN_ENROLL_IMAGES)
    print(f"\nCapturing {n_images} photos. Look at the camera; move slightly between shots.\n")

    images = []
    for i in range(n_images):
        input(f"[{i + 1}/{n_images}] Position yourself, then press Enter to capture...")
        print("    Capturing...", end="", flush=True)
        photo = capture_photo(args.camera)
        if photo is None:
            print(" failed - retrying this shot.")
            continue
        print(" done.")
        images.append(photo)
        time.sleep(0.3)

    if len(images) < MIN_ENROLL_IMAGES:
        print(f"\nOnly captured {len(images)} usable photos - need at least {MIN_ENROLL_IMAGES}. Try again.")
        sys.exit(1)

    print("\nTraining face profile...")
    try:
        fv.enroll(images)
    except ValueError as e:
        print(f"\nEnrollment failed: {e}")
        sys.exit(1)

    print(
        f"\nDone. Face profile saved to {fv.model_path}\n"
        f"Default match threshold: {fv.threshold:.1f} (LBPH distance - LOWER is a better\n"
        f"match, opposite direction from the voice verifier's cosine similarity).\n"
        f"This is a starting point, not calibrated to your camera/lighting. If\n"
        f"core/intruder_alert.py logs mismatches for you, or matches for someone\n"
        f"else, adjust via FaceVerifier(threshold=...) - try raising it if you're\n"
        f"getting false 'does NOT match' results, lowering it if a stranger is\n"
        f"getting matched as you.\n"
    )


if __name__ == "__main__":
    main()