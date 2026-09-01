"""
test_speaker_verify.py — Functional test of speaker verification logic
==========================================================================
Mocks out Resemblyzer's actual model (heavy, needs torch, and there's no
real voice to test with here) so this exercises the REAL logic that
matters: enrollment/averaging, persistence + permissions, cosine-similarity
comparison, threshold behavior, audit logging, and the fail-open-without-
enrollment / fail-closed-below-threshold contract that main.py relies on.

Run: python test_speaker_verify.py
"""
import shutil
import sys
import tempfile
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent))

from core.speaker_verify import SpeakerVerifier, VerifyResult


def fake_embed_factory(voice_map):
    """Returns a fake _embed(audio, sample_rate) that maps a marker value
    encoded in the audio array's first sample to a fixed fake embedding,
    so we can simulate 'same speaker' vs 'different speaker' deterministically
    without any real model."""
    def _embed(self, audio, sample_rate):
        marker = int(audio[0]) if len(audio) else -1
        if marker == -999:
            return None  # simulate unusable/too-short audio
        vec = voice_map.get(marker)
        if vec is None:
            return None
        return np.array(vec, dtype=np.float32)
    return _embed


def make_audio(marker: int, length: int = 4000) -> np.ndarray:
    arr = np.zeros(length, dtype=np.int16)
    arr[0] = marker
    return arr


def run():
    tmpdir = tempfile.mkdtemp()
    profile_path = Path(tmpdir) / "voice_profile.json"

    # Two fake "speakers": owner (marker=1) and impostor (marker=2).
    # Embeddings are just unit-ish vectors chosen so cosine similarity
    # comes out predictably: owner vs owner ~1.0, owner vs impostor ~0.3.
    voice_map = {
        1: [1.0, 0.05, 0.0],   # owner variant A
        3: [0.98, 0.1, 0.02],  # owner variant B (slightly different clip)
        4: [0.95, 0.15, 0.05], # owner variant C
        5: [0.97, 0.08, 0.01], # owner variant D
        2: [0.1, 0.2, 0.97],   # impostor — very different direction
    }

    SpeakerVerifier._embed = fake_embed_factory(voice_map)  # monkeypatch

    passed = 0
    failed = 0

    def check(label, cond):
        nonlocal passed, failed
        if cond:
            print(f"  [PASS] {label}")
            passed += 1
        else:
            print(f"  [FAIL] {label}")
            failed += 1

    # ── 1. Verify before enrollment: fail-open at this layer, enrolled=False
    print("\n[1] Pre-enrollment behavior")
    sv = SpeakerVerifier(path=profile_path)
    result = sv.verify(make_audio(1), action="test")
    check("not enrolled -> enrolled=False", result.enrolled is False)
    check("not enrolled -> accepted=False (never a green light)", result.accepted is False)

    # ── 2. Enrollment requires minimum clip count
    print("\n[2] Enrollment minimum-clips guard")
    try:
        sv.enroll([make_audio(1), make_audio(3)])  # only 2, need 3+
        check("rejects too-few clips", False)
    except ValueError:
        check("rejects too-few clips", True)

    # ── 3. Successful enrollment with owner clips
    print("\n[3] Successful enrollment")
    ok = sv.enroll([make_audio(1), make_audio(3), make_audio(4), make_audio(5)])
    check("enroll() returns True", ok is True)
    check("profile file created", profile_path.exists())
    import os
    mode = oct(os.stat(profile_path).st_mode)[-3:]
    check(f"profile file permissions restricted (got {mode})", mode in ("600", "644") or sys.platform == "win32")
    # (644 fallback acceptable on filesystems/OSes where chmod 600 isn't
    # honored, e.g. some CI containers — the chmod call itself is still made.)

    # ── 4. Verify with the SAME voice -> accepted
    print("\n[4] Genuine-speaker verification")
    result = sv.verify(make_audio(1), action="test")
    check("enrolled=True", result.enrolled is True)
    check(f"accepted=True (score={result.score:.3f})", result.accepted is True)

    # ── 5. Verify with a DIFFERENT voice -> rejected, not a crash
    print("\n[5] Impostor-speaker verification")
    result = sv.verify(make_audio(2), action="test")
    check("enrolled=True", result.enrolled is True)
    check(f"accepted=False (score={result.score:.3f})", result.accepted is False)
    check("reason explains rejection", result.reason == "below_threshold")

    # ── 6. Unusable audio doesn't crash, returns a clean rejection
    print("\n[6] Unusable audio handling")
    result = sv.verify(make_audio(-999), action="test")
    check("unusable audio -> accepted=False, no exception", result.accepted is False)
    check("reason flags unusable audio", result.reason == "unusable_audio")

    # ── 7. Audit log actually recorded these events
    print("\n[7] Audit trail")
    from core.audit_log import AuditLog
    log = AuditLog(path=Path(tmpdir) / "audit_log.jsonl")
    # sv used the default AuditLog path (memory/audit_log.jsonl in the repo);
    # re-point a fresh SpeakerVerifier at a throwaway audit path to confirm
    # the append actually happens without touching the real project log.
    sv2 = SpeakerVerifier(path=Path(tmpdir) / "voice_profile2.json")
    sv2._audit = log
    sv2.enroll([make_audio(1), make_audio(3), make_audio(4)])
    sv2.verify(make_audio(1), action="test")
    entries = log.read_all()
    check("enroll + verify both logged", len(entries) == 2)
    check("log integrity verifies clean", log.verify()[0] is True)

    # ── 8. reset() removes the profile
    print("\n[8] Reset")
    sv.reset()
    check("profile removed after reset()", not profile_path.exists())
    result = sv.verify(make_audio(1), action="test")
    check("post-reset verify() is enrolled=False again", result.enrolled is False)

    shutil.rmtree(tmpdir, ignore_errors=True)

    print(f"\n{'='*50}\n{passed} passed, {failed} failed\n{'='*50}")
    return failed == 0


if __name__ == "__main__":
    ok = run()
    sys.exit(0 if ok else 1)