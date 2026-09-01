"""
tests/test_integrity_manifest.py — Comprehensive Test Suite for Signed Integrity Manifest (C10)
================================================================================================
Verifies:
1. Manifest signed with valid Ed25519 private key verifies successfully against pinned public key.
2. File content modifications (hash mismatches) fail verification and report the tampered file.
3. Deleted/missing files fail verification.
4. Untracked/backdoor files injected into monitored directories fail verification.
5. Signature tampering / forging fails verification.
6. Manifest payload tampering with unchanged signature fails verification.
7. Missing pinned public key strictly fails closed.
8. Corrupted pinned public key strictly fails closed.
9. Missing manifest file strictly fails closed.
10. Self-integrity: core/integrity_monitor.py itself is covered in the manifest.
"""

import json
import pytest
from pathlib import Path

from core.integrity_monitor import (
    IntegrityMonitor,
    generate_keypair,
    export_public_key_pem,
    export_private_key_pem,
    load_public_key,
    load_private_key,
    _compute_file_sha256,
)


@pytest.fixture
def test_codebase(tmp_path):
    """Sets up an isolated mock codebase structure with monitored directories."""
    base = tmp_path / "app"
    base.mkdir()
    (base / "core").mkdir()
    (base / "sentinel").mkdir()
    (base / "agent").mkdir()
    (base / "actions").mkdir()
    (base / "memory").mkdir()

    # Create mock python source files
    (base / "core" / "integrity_monitor.py").write_text("def verify(): pass\n", encoding="utf-8")
    (base / "core" / "auth.py").write_text("class Auth: pass\n", encoding="utf-8")
    (base / "sentinel" / "detector.py").write_text("class Detector: pass\n", encoding="utf-8")
    (base / "agent" / "runner.py").write_text("def run(): pass\n", encoding="utf-8")
    (base / "actions" / "system.py").write_text("def action(): pass\n", encoding="utf-8")

    manifest_path = base / "memory" / "integrity_manifest.json"
    pubkey_path = base / "memory" / "integrity_pubkey.pem"

    return {
        "base": base,
        "manifest_path": manifest_path,
        "pubkey_path": pubkey_path,
    }


def test_integrity_valid_signed_manifest_passes(test_codebase):
    """Confirms that a valid codebase signed with an Ed25519 private key passes verification."""
    priv, pub = generate_keypair()
    monitor = IntegrityMonitor(
        manifest_path=test_codebase["manifest_path"],
        public_key_path=test_codebase["pubkey_path"],
        base_dir=test_codebase["base"],
    )

    # Generate baseline using the private key
    payload = monitor.generate_baseline(private_key=priv)
    assert payload["algorithm"] == "Ed25519"
    assert "signature" in payload
    assert test_codebase["manifest_path"].exists()
    assert test_codebase["pubkey_path"].exists()

    alerts = []
    report = monitor.verify_integrity(alert_callback=lambda msg: alerts.append(msg))
    assert report.is_valid is True
    assert len(report.tampered_files) == 0
    assert len(report.missing_files) == 0
    assert len(report.new_untracked_files) == 0
    assert len(alerts) == 0


def test_integrity_tampered_file_fails_verification(test_codebase):
    """Confirms that modifying any monitored file causes verification failure."""
    priv, pub = generate_keypair()
    monitor = IntegrityMonitor(
        manifest_path=test_codebase["manifest_path"],
        public_key_path=test_codebase["pubkey_path"],
        base_dir=test_codebase["base"],
    )
    monitor.generate_baseline(private_key=priv)

    # Tamper with core/auth.py
    auth_file = test_codebase["base"] / "core" / "auth.py"
    auth_file.write_text("class Auth:\n    # INJECTED BACKDOOR\n    pass\n", encoding="utf-8")

    alerts = []
    report = monitor.verify_integrity(alert_callback=lambda msg: alerts.append(msg))
    assert report.is_valid is False
    assert "core/auth.py" in report.tampered_files
    assert len(alerts) == 1
    assert "core/auth.py" in alerts[0]


def test_integrity_missing_file_fails_verification(test_codebase):
    """Confirms that deleting a covered file causes verification failure."""
    priv, pub = generate_keypair()
    monitor = IntegrityMonitor(
        manifest_path=test_codebase["manifest_path"],
        public_key_path=test_codebase["pubkey_path"],
        base_dir=test_codebase["base"],
    )
    monitor.generate_baseline(private_key=priv)

    # Delete sentinel/detector.py
    detector_file = test_codebase["base"] / "sentinel" / "detector.py"
    detector_file.unlink()

    alerts = []
    report = monitor.verify_integrity(alert_callback=lambda msg: alerts.append(msg))
    assert report.is_valid is False
    assert "sentinel/detector.py" in report.missing_files
    assert len(alerts) == 1


def test_integrity_untracked_injected_file_fails_verification(test_codebase):
    """Confirms that injecting a new untracked python file causes verification failure."""
    priv, pub = generate_keypair()
    monitor = IntegrityMonitor(
        manifest_path=test_codebase["manifest_path"],
        public_key_path=test_codebase["pubkey_path"],
        base_dir=test_codebase["base"],
    )
    monitor.generate_baseline(private_key=priv)

    # Inject unauthorized backdoor script
    injected_file = test_codebase["base"] / "agent" / "backdoor_tool.py"
    injected_file.write_text("def backdoor(): pass\n", encoding="utf-8")

    alerts = []
    report = monitor.verify_integrity(alert_callback=lambda msg: alerts.append(msg))
    assert report.is_valid is False
    assert "agent/backdoor_tool.py" in report.new_untracked_files
    assert len(alerts) == 1


def test_integrity_tampered_signature_fails_verification(test_codebase):
    """Confirms that signature corruption or forgery causes immediate signature verification failure."""
    priv, pub = generate_keypair()
    monitor = IntegrityMonitor(
        manifest_path=test_codebase["manifest_path"],
        public_key_path=test_codebase["pubkey_path"],
        base_dir=test_codebase["base"],
    )
    monitor.generate_baseline(private_key=priv)

    # Tamper with signature in manifest file
    manifest_data = json.loads(test_codebase["manifest_path"].read_text(encoding="utf-8"))
    manifest_data["signature"] = "deadbeef" * 16  # 64-byte invalid hex signature
    test_codebase["manifest_path"].write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    alerts = []
    report = monitor.verify_integrity(alert_callback=lambda msg: alerts.append(msg))
    assert report.is_valid is False
    assert "manifest.signature" in report.tampered_files
    assert len(alerts) == 1
    assert "signature is INVALID" in alerts[0]


def test_integrity_signed_with_untrusted_key_fails_verification(test_codebase):
    """Confirms that a manifest signed by an unauthorized/untrusted key is rejected."""
    priv_trusted, pub_trusted = generate_keypair()
    priv_attacker, pub_attacker = generate_keypair()

    monitor = IntegrityMonitor(
        manifest_path=test_codebase["manifest_path"],
        public_key_path=test_codebase["pubkey_path"],
        base_dir=test_codebase["base"],
    )

    # Pin the trusted public key
    test_codebase["pubkey_path"].write_text(export_public_key_pem(pub_trusted), encoding="utf-8")

    # Attacker attempts to sign a manifest with their own untrusted private key
    monitor.generate_baseline(private_key=priv_attacker)
    # Restore trusted public key on disk (in case generate_baseline overwrote it)
    test_codebase["pubkey_path"].write_text(export_public_key_pem(pub_trusted), encoding="utf-8")

    alerts = []
    report = monitor.verify_integrity(alert_callback=lambda msg: alerts.append(msg))
    assert report.is_valid is False
    assert "manifest.signature" in report.tampered_files
    assert len(alerts) == 1


def test_integrity_tampered_manifest_contents_fails_verification(test_codebase):
    """Confirms that modifying manifest hashes without re-signing fails signature verification."""
    priv, pub = generate_keypair()
    monitor = IntegrityMonitor(
        manifest_path=test_codebase["manifest_path"],
        public_key_path=test_codebase["pubkey_path"],
        base_dir=test_codebase["base"],
    )
    monitor.generate_baseline(private_key=priv)

    # Attacker alters the hash in manifest to match modified file without possessing private key
    manifest_data = json.loads(test_codebase["manifest_path"].read_text(encoding="utf-8"))
    manifest_data["manifest"]["hashes"]["core/auth.py"] = "0000000000000000000000000000000000000000000000000000000000000000"
    test_codebase["manifest_path"].write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    alerts = []
    report = monitor.verify_integrity(alert_callback=lambda msg: alerts.append(msg))
    assert report.is_valid is False
    assert "manifest.signature" in report.tampered_files


def test_integrity_missing_public_key_fails_closed(test_codebase):
    """Confirms fail-closed behavior when pinned public key file is absent."""
    priv, pub = generate_keypair()
    monitor = IntegrityMonitor(
        manifest_path=test_codebase["manifest_path"],
        public_key_path=test_codebase["pubkey_path"],
        base_dir=test_codebase["base"],
    )
    monitor.generate_baseline(private_key=priv)

    # Delete public key file
    test_codebase["pubkey_path"].unlink()

    alerts = []
    report = monitor.verify_integrity(alert_callback=lambda msg: alerts.append(msg))
    assert report.is_valid is False
    assert "public_key_missing" in report.tampered_files
    assert "missing" in report.details.lower()
    assert len(alerts) == 1


def test_integrity_corrupted_public_key_fails_closed(test_codebase):
    """Confirms fail-closed behavior when pinned public key file is corrupted."""
    priv, pub = generate_keypair()
    monitor = IntegrityMonitor(
        manifest_path=test_codebase["manifest_path"],
        public_key_path=test_codebase["pubkey_path"],
        base_dir=test_codebase["base"],
    )
    monitor.generate_baseline(private_key=priv)

    # Corrupt public key file
    test_codebase["pubkey_path"].write_text("-----BEGIN PUBLIC KEY-----\ncorrupted_data\n-----END PUBLIC KEY-----\n", encoding="utf-8")

    alerts = []
    report = monitor.verify_integrity(alert_callback=lambda msg: alerts.append(msg))
    assert report.is_valid is False
    assert "public_key.pem" in report.tampered_files
    assert len(alerts) == 1


def test_integrity_missing_manifest_fails_closed(test_codebase):
    """Confirms fail-closed behavior when manifest file does not exist."""
    priv, pub = generate_keypair()
    monitor = IntegrityMonitor(
        manifest_path=test_codebase["manifest_path"],
        public_key_path=test_codebase["pubkey_path"],
        base_dir=test_codebase["base"],
    )
    test_codebase["pubkey_path"].write_text(export_public_key_pem(pub), encoding="utf-8")

    # Ensure manifest file does not exist
    if test_codebase["manifest_path"].exists():
        test_codebase["manifest_path"].unlink()

    report = monitor.verify_integrity()
    assert report.is_valid is False
    assert "integrity_manifest.json" in report.missing_files


def test_integrity_verifier_file_itself_is_monitored(test_codebase):
    """Confirms that core/integrity_monitor.py itself is covered in the signed manifest."""
    priv, pub = generate_keypair()
    monitor = IntegrityMonitor(
        manifest_path=test_codebase["manifest_path"],
        public_key_path=test_codebase["pubkey_path"],
        base_dir=test_codebase["base"],
    )
    payload = monitor.generate_baseline(private_key=priv)
    assert "core/integrity_monitor.py" in payload["manifest"]["hashes"]


def test_verify_on_startup_failure_blocks_daemon_startup(monkeypatch):
    """
    Confirms that when verify_on_startup() fails (integrity check fails or key/manifest missing):
    1. verify_on_startup() returns False.
    2. The caller (e.g. main() or jarvis_service startup) exits immediately with code 1,
       halting the daemon before UI or background services initialize.
    """
    from unittest.mock import patch, MagicMock
    import core.integrity_monitor
    import main

    # Simulate integrity check failure in verify_on_startup
    with patch("core.integrity_monitor.verify_on_startup", return_value=False):
        with pytest.raises(SystemExit) as exc_info:
            main.main()
        assert exc_info.value.code == 1


def test_verify_on_startup_success_allows_daemon_startup(monkeypatch):
    """
    Confirms that when verify_on_startup() returns True,
    startup proceeds to initialize components normally.
    """
    from unittest.mock import patch, MagicMock
    import main

    mock_ui = MagicMock()
    with patch("core.integrity_monitor.verify_on_startup", return_value=True):
        with patch("main.JarvisUI", return_value=mock_ui):
            with patch("threading.Thread") as mock_thread:
                main.main()
                # Confirm UI mainloop was called and thread was started
                mock_ui.root.mainloop.assert_called_once()
                mock_thread.return_value.start.assert_called_once()

