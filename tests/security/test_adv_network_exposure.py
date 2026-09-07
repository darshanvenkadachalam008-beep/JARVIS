"""
tests/security/test_adv_network_exposure.py
============================================
Verifies firewall private profile verification and paired IP allowlist caching.
"""
import pytest
from pathlib import Path
from mobile_server import (
    _ensure_windows_firewall_rule,
    _load_paired_ips,
    _save_paired_ip,
    _PAIRED_IPS,
)


def test_firewall_rule_execution_safety():
    """Verifies _ensure_windows_firewall_rule runs without uncaught exceptions."""
    _ensure_windows_firewall_rule()


def test_paired_ip_allowlist_caching(tmp_path, monkeypatch):
    """Verifies that paired IPs are persisted and loaded correctly with localhost defaults."""
    import mobile_server
    fake_cache = tmp_path / ".paired_ips.json"
    monkeypatch.setattr(mobile_server, "_PAIRED_IPS_PATH", fake_cache)
    monkeypatch.setattr(mobile_server, "_PAIRED_IPS", set())

    ips = mobile_server._load_paired_ips()
    assert "127.0.0.1" in ips
    assert "::1" in ips

    mobile_server._save_paired_ip("192.168.1.150")
    assert "192.168.1.150" in mobile_server._PAIRED_IPS

    # Reload from disk
    monkeypatch.setattr(mobile_server, "_PAIRED_IPS", set())
    reloaded = mobile_server._load_paired_ips()
    assert "192.168.1.150" in reloaded
    assert "127.0.0.1" in reloaded


def test_pairing_window_lifecycle(tmp_path, monkeypatch):
    """Verifies opening, validity, and expiration of the time-boxed pairing window."""
    import mobile_server
    import time
    fake_window_file = tmp_path / ".pairing_window"
    monkeypatch.setattr(mobile_server, "_PAIRING_WINDOW_FILE", fake_window_file)

    assert not mobile_server.is_pairing_window_open()

    # Open 2-second window
    expires_at = mobile_server.open_pairing_window(duration_sec=2)
    assert expires_at > time.time()
    assert mobile_server.is_pairing_window_open()

    # Wait for expiration
    time.sleep(2.1)
    assert not mobile_server.is_pairing_window_open()

