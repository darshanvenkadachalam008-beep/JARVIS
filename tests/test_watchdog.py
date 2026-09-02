"""
tests/test_watchdog.py — Comprehensive tests for Watchdog Self-Protection (Layer 1 & Layer 2)
=============================================================================================
Verifies:
1. Watchdog writes watchdog_heartbeat.json atomically on its cycle.
2. jarvis_service companion check: missing/stale heartbeat triggers watchdog relaunch.
3. INTENTIONAL_EXIT_PATH presence suppresses watchdog relaunch.
4. Cooldown window prevents restart storms (only 1 relaunch per grace period).
5. Layer 2 Task Scheduler setup script idempotency and XML generation.
"""
import json
import os
import time
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

import jarvis_watchdog
import setup_watchdog_task
from jarvis_service import _check_and_heal_watchdog, _read_watchdog_heartbeat


def test_watchdog_atomic_heartbeat_write(tmp_path, monkeypatch):
    """Verifies that jarvis_watchdog writes its own heartbeat file atomically with valid PID and timestamp."""
    hb_file = tmp_path / "memory" / "watchdog_heartbeat.json"
    monkeypatch.setattr(jarvis_watchdog, "WATCHDOG_HEARTBEAT_PATH", hb_file)

    jarvis_watchdog._write_heartbeat()

    assert hb_file.exists()
    data = json.loads(hb_file.read_text(encoding="utf-8"))
    assert "pid" in data
    assert "ts" in data
    assert time.time() - data["ts"] < 2.0


def test_companion_check_missing_heartbeat_triggers_relaunch(tmp_path):
    """Verifies that when watchdog heartbeat is missing (past startup grace), companion check relaunches it."""
    hb_file = tmp_path / "memory" / "watchdog_heartbeat.json"
    exit_marker = tmp_path / "memory" / "jarvis_intentional_exit.marker"

    relaunch_mock = MagicMock()
    last_relaunch = 0.0
    startup_deadline = time.time() - 10.0  # past startup grace
    have_seen_first_hb = False

    new_last, new_dl, new_seen = _check_and_heal_watchdog(
        last_watchdog_relaunch_time=last_relaunch,
        startup_deadline=startup_deadline,
        have_seen_first_hb=have_seen_first_hb,
        heartbeat_path=hb_file,
        intentional_exit_path=exit_marker,
        stale_secs=90.0,
        grace_secs=60.0,
        relaunch_fn=relaunch_mock,
    )

    relaunch_mock.assert_called_once()
    assert new_last > 0.0
    assert new_seen is False


def test_companion_check_stale_heartbeat_triggers_relaunch(tmp_path):
    """Verifies that when watchdog heartbeat is older than stale_secs, companion check relaunches it."""
    hb_file = tmp_path / "memory" / "watchdog_heartbeat.json"
    hb_file.parent.mkdir(parents=True, exist_ok=True)
    stale_ts = time.time() - 120.0  # 120s old > 90s threshold
    hb_file.write_text(json.dumps({"pid": 1234, "ts": stale_ts}), encoding="utf-8")
    exit_marker = tmp_path / "memory" / "jarvis_intentional_exit.marker"

    relaunch_mock = MagicMock()
    last_relaunch = 0.0
    startup_deadline = time.time() + 60.0
    have_seen_first_hb = True

    new_last, new_dl, new_seen = _check_and_heal_watchdog(
        last_watchdog_relaunch_time=last_relaunch,
        startup_deadline=startup_deadline,
        have_seen_first_hb=have_seen_first_hb,
        heartbeat_path=hb_file,
        intentional_exit_path=exit_marker,
        stale_secs=90.0,
        grace_secs=60.0,
        relaunch_fn=relaunch_mock,
    )

    relaunch_mock.assert_called_once()
    assert new_last > 0.0
    assert new_seen is True


def test_companion_check_intentional_exit_marker_suppresses_relaunch(tmp_path):
    """Verifies that when a valid authenticated INTENTIONAL_EXIT_PATH marker exists, no relaunch is triggered even if heartbeat is missing."""
    from core.watchdog_auth import write_authenticated_exit_marker

    hb_file = tmp_path / "memory" / "watchdog_heartbeat.json"
    exit_marker = tmp_path / "memory" / "jarvis_intentional_exit.marker"
    key_file = tmp_path / "memory" / ".watchdog_auth.key"

    write_authenticated_exit_marker(exit_marker, reason="user_quit", key_path=key_file)

    relaunch_mock = MagicMock()
    last_relaunch = 0.0
    startup_deadline = time.time() - 10.0
    have_seen_first_hb = False

    new_last, new_dl, new_seen = _check_and_heal_watchdog(
        last_watchdog_relaunch_time=last_relaunch,
        startup_deadline=startup_deadline,
        have_seen_first_hb=have_seen_first_hb,
        heartbeat_path=hb_file,
        intentional_exit_path=exit_marker,
        stale_secs=90.0,
        grace_secs=60.0,
        relaunch_fn=relaunch_mock,
        key_path=key_file,
    )

    relaunch_mock.assert_not_called()
    assert new_last == 0.0


def test_companion_check_cooldown_prevents_restart_storm(tmp_path):
    """Verifies that multiple stale checks within the grace window only trigger a single relaunch attempt."""
    hb_file = tmp_path / "memory" / "watchdog_heartbeat.json"
    hb_file.parent.mkdir(parents=True, exist_ok=True)
    stale_ts = time.time() - 150.0
    hb_file.write_text(json.dumps({"pid": 1234, "ts": stale_ts}), encoding="utf-8")
    exit_marker = tmp_path / "memory" / "jarvis_intentional_exit.marker"

    relaunch_mock = MagicMock()
    last_relaunch = 0.0
    startup_deadline = time.time() - 10.0
    have_seen_first_hb = True

    # First check: triggers relaunch
    last_1, dl_1, seen_1 = _check_and_heal_watchdog(
        last_watchdog_relaunch_time=last_relaunch,
        startup_deadline=startup_deadline,
        have_seen_first_hb=have_seen_first_hb,
        heartbeat_path=hb_file,
        intentional_exit_path=exit_marker,
        stale_secs=90.0,
        grace_secs=60.0,
        relaunch_fn=relaunch_mock,
    )
    assert relaunch_mock.call_count == 1

    # Second check immediately after (within 60s cooldown): suppressed
    last_2, dl_2, seen_2 = _check_and_heal_watchdog(
        last_watchdog_relaunch_time=last_1,
        startup_deadline=dl_1,
        have_seen_first_hb=seen_1,
        heartbeat_path=hb_file,
        intentional_exit_path=exit_marker,
        stale_secs=90.0,
        grace_secs=60.0,
        relaunch_fn=relaunch_mock,
    )
    assert relaunch_mock.call_count == 1  # Still 1, cooldown held
    assert last_2 == last_1


def test_layer2_task_xml_structure():
    """Verifies that the generated Task Scheduler XML contains LogonTrigger, RestartOnFailure, and PT0S limits."""
    py_path = Path("C:/Python310/pythonw.exe")
    script = Path("D:/Mark/jarvis_watchdog.py")
    cwd = Path("D:/Mark")

    xml = setup_watchdog_task.build_task_xml(py_path, script, cwd)

    assert "<LogonTrigger>" in xml
    assert "<RestartOnFailure>" in xml
    assert "<Interval>PT1M</Interval>" in xml
    assert "<Count>3</Count>" in xml
    assert "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>" in xml
    assert str(py_path) in xml
    assert str(script) in xml


def test_layer2_setup_task_idempotency_check_and_create():
    """Verifies that install_watchdog_task checks for existing task and calls schtasks."""
    with patch("setup_watchdog_task.is_task_installed", return_value=True) as mock_query:
        with patch("subprocess.run") as mock_subproc:
            mock_subproc.return_value = MagicMock(returncode=0)

            success = setup_watchdog_task.install_watchdog_task("TEST_TASK")

            mock_query.assert_called_once_with("TEST_TASK")
            assert success is True
            assert mock_subproc.called
            # Verify schtasks /Create was executed with /F flag
            cmd_args = mock_subproc.call_args[0][0]
            assert cmd_args[0] == "schtasks"
            assert cmd_args[1] == "/Create"
            assert "/F" in cmd_args


def test_service_detects_watchdog_killed_triggers_relaunch_and_alert(tmp_path):
    """
    Simulates the watchdog process disappearing/killed.
    Confirms the main service companion monitor detects the missing heartbeat,
    triggers watchdog relaunch, and emits a high-priority alert.
    """
    hb_file = tmp_path / "memory" / "watchdog_heartbeat.json"
    exit_marker = tmp_path / "memory" / "jarvis_intentional_exit.marker"

    relaunch_mock = MagicMock()
    alert_mock = MagicMock()
    last_relaunch = 0.0
    startup_deadline = time.time() - 10.0  # past startup grace
    have_seen_first_hb = True

    new_last, new_dl, new_seen = _check_and_heal_watchdog(
        last_watchdog_relaunch_time=last_relaunch,
        startup_deadline=startup_deadline,
        have_seen_first_hb=have_seen_first_hb,
        heartbeat_path=hb_file,
        intentional_exit_path=exit_marker,
        stale_secs=90.0,
        grace_secs=60.0,
        relaunch_fn=relaunch_mock,
        alert_fn=alert_mock,
    )

    relaunch_mock.assert_called_once()
    alert_mock.assert_called_once()
    assert "heartbeat file missing" in alert_mock.call_args[0][0]
    assert new_last > 0.0


def test_watchdog_detects_service_killed_restarts_and_rapid_restart_storm_alerts(tmp_path, monkeypatch):
    """
    Simulates the main service dying multiple times in quick succession.
    Confirms the watchdog performs restart recovery and raises a security alert
    when the rapid restart storm threshold (>= 3 in 5 min) is breached.
    """
    monkeypatch.setattr(jarvis_watchdog, "_restart_history", [])
    alert_mock = MagicMock()
    launch_mock = MagicMock()
    monkeypatch.setattr(jarvis_watchdog, "_launch_jarvis", launch_mock)
    monkeypatch.setattr(jarvis_watchdog, "_kill_pids_on_ports", MagicMock())
    monkeypatch.setattr(jarvis_watchdog, "_clear_stale_lock", MagicMock())
    monkeypatch.setattr(time, "sleep", lambda s: None)

    # 1st restart: normal
    jarvis_watchdog._restart("service died 1", alert_fn=alert_mock)
    assert launch_mock.call_count == 1
    alert_mock.assert_not_called()

    # 2nd restart: normal
    jarvis_watchdog._restart("service died 2", alert_fn=alert_mock)
    assert launch_mock.call_count == 2
    alert_mock.assert_not_called()

    # 3rd restart within window: triggers restart storm alert
    jarvis_watchdog._restart("service died 3", alert_fn=alert_mock)
    assert launch_mock.call_count == 3
    alert_mock.assert_called_once_with(3, jarvis_watchdog.RESTART_STORM_WINDOW_SECS)


def test_heartbeat_intentional_brief_restart_does_not_false_positive(tmp_path):
    """
    Confirms that during an intentional, planned restart (e.g. software update),
    writing a valid authenticated intentional exit marker cleanly suppresses false-positive watchdog
    restarts and companion monitoring alarms.
    """
    from core.watchdog_auth import write_authenticated_exit_marker

    hb_file = tmp_path / "memory" / "watchdog_heartbeat.json"
    exit_marker = tmp_path / "memory" / "jarvis_intentional_exit.marker"
    key_file = tmp_path / "memory" / ".watchdog_auth.key"

    write_authenticated_exit_marker(exit_marker, reason="restart", key_path=key_file)

    relaunch_mock = MagicMock()
    alert_mock = MagicMock()

    new_last, new_dl, new_seen = _check_and_heal_watchdog(
        last_watchdog_relaunch_time=0.0,
        startup_deadline=time.time() - 100.0,
        have_seen_first_hb=True,
        heartbeat_path=hb_file,
        intentional_exit_path=exit_marker,
        stale_secs=90.0,
        grace_secs=60.0,
        relaunch_fn=relaunch_mock,
        alert_fn=alert_mock,
        key_path=key_file,
    )

    relaunch_mock.assert_not_called()
    alert_mock.assert_not_called()


def test_attacker_created_unauthenticated_exit_marker_is_rejected(tmp_path):
    """
    Simulates an attacker forging a bare intentional-exit marker to disable watchdog monitoring.
    Proves that the unauthenticated file is rejected, cleaned up, and companion relaunch + alert fires.
    """
    hb_file = tmp_path / "memory" / "watchdog_heartbeat.json"
    exit_marker = tmp_path / "memory" / "jarvis_intentional_exit.marker"
    key_file = tmp_path / "memory" / ".watchdog_auth.key"
    exit_marker.parent.mkdir(parents=True, exist_ok=True)

    # Attacker touches / writes a fake marker without valid HMAC
    exit_marker.write_text("1700000000.0", encoding="utf-8")

    relaunch_mock = MagicMock()
    alert_mock = MagicMock()

    new_last, new_dl, new_seen = _check_and_heal_watchdog(
        last_watchdog_relaunch_time=0.0,
        startup_deadline=time.time() - 100.0,
        have_seen_first_hb=True,
        heartbeat_path=hb_file,
        intentional_exit_path=exit_marker,
        stale_secs=90.0,
        grace_secs=60.0,
        relaunch_fn=relaunch_mock,
        alert_fn=alert_mock,
        key_path=key_file,
    )

    # Relaunch and alert were NOT suppressed by the forged marker
    relaunch_mock.assert_called_once()
    alert_mock.assert_called_once()
    assert not exit_marker.exists()  # Forged file unlinked


def test_authenticated_exit_marker_bounded_lifetime_and_expiry(tmp_path):
    """
    Verifies that an authenticated intentional-exit marker is strictly time-bounded (5 min TTL):
    once expired, monitoring resumes automatically and watchdog alerts fire if heartbeat is absent.
    """
    from core.watchdog_auth import write_authenticated_exit_marker, verify_authenticated_exit_marker, _get_or_create_watchdog_key

    exit_marker = tmp_path / "memory" / "jarvis_intentional_exit.marker"
    key_file = tmp_path / "memory" / ".watchdog_auth.key"

    write_authenticated_exit_marker(exit_marker, reason="user_quit", key_path=key_file)
    assert verify_authenticated_exit_marker(exit_marker, max_age_secs=300.0, key_path=key_file) is True

    # Simulate marker exceeding 300s TTL
    data = json.loads(exit_marker.read_text(encoding="utf-8"))
    data["payload"]["ts"] = time.time() - 301.0
    # Re-sign with expired timestamp using real unwrapped key
    import hmac, hashlib
    key = _get_or_create_watchdog_key(key_file)
    canonical_data = json.dumps(data["payload"], sort_keys=True).encode("utf-8")
    data["hmac"] = hmac.new(key, canonical_data, hashlib.sha256).hexdigest()
    exit_marker.write_text(json.dumps(data), encoding="utf-8")

    # Verification fails due to TTL expiration
    assert verify_authenticated_exit_marker(exit_marker, max_age_secs=300.0, key_path=key_file) is False
    assert not exit_marker.exists()  # Expired marker cleaned up


def test_attacker_reading_raw_dpapi_ciphertext_key_cannot_forge_marker(tmp_path):
    """
    Proves that an attacker reading the raw .watchdog_auth.key on disk (which is encrypted with DPAPI)
    cannot forge a valid marker by attempting to sign directly with that raw ciphertext file content.
    """
    import hmac, hashlib
    from core.watchdog_auth import write_authenticated_exit_marker, verify_authenticated_exit_marker

    exit_marker = tmp_path / "memory" / "jarvis_intentional_exit.marker"
    key_file = tmp_path / "memory" / ".watchdog_auth.key"

    # Initialize DPAPI protected key
    write_authenticated_exit_marker(exit_marker, reason="initial", key_path=key_file)
    raw_disk_bytes = key_file.read_bytes()

    # Attacker reads raw disk bytes without DPAPI unprotect
    attacker_payload = {"pid": os.getpid(), "ts": time.time(), "reason": "user_quit"}
    attacker_canonical = json.dumps(attacker_payload, sort_keys=True).encode("utf-8")
    attacker_sig = hmac.new(raw_disk_bytes, attacker_canonical, hashlib.sha256).hexdigest()
    forged_marker = {"payload": attacker_payload, "hmac": attacker_sig}

    exit_marker.write_text(json.dumps(forged_marker), encoding="utf-8")

    # System verifies marker with real DPAPI unprotect -> rejects forged signature
    assert verify_authenticated_exit_marker(exit_marker, key_path=key_file) is False


def test_service_heartbeat_has_dacl_protection(tmp_path, monkeypatch):
    """
    Verifies that executing the real _write_service_heartbeat() production function
    applies owner-only DACL protection to HEARTBEAT_PATH.
    """
    import jarvis_service

    hb_path = tmp_path / "memory" / "jarvis_heartbeat.json"

    with patch("sentinel.security_utils.apply_owner_only_dacl") as mock_dacl:
        # Call the real production heartbeat write function directly
        jarvis_service._write_service_heartbeat(hb_path)

        assert hb_path.exists()
        mock_dacl.assert_called_once_with(hb_path)


def test_fail_closed_heartbeat_deletion_scenario(tmp_path):
    """
    Proves fail-closed behavior on heartbeat file deletion:
    Once a process has been observed healthy (have_seen_first_hb=True),
    deleting its heartbeat file mid-run does NOT reset the system into unmonitored grace;
    it immediately triggers relaunch and alert upon the next check.
    """
    hb_file = tmp_path / "memory" / "watchdog_heartbeat.json"
    hb_file.parent.mkdir(parents=True, exist_ok=True)
    hb_file.write_text(json.dumps({"pid": 555, "ts": time.time()}), encoding="utf-8")
    exit_marker = tmp_path / "memory" / "jarvis_intentional_exit.marker"

    relaunch_mock = MagicMock()
    alert_mock = MagicMock()

    # Initial check: healthy
    last_1, dl_1, seen_1 = _check_and_heal_watchdog(
        last_watchdog_relaunch_time=0.0,
        startup_deadline=time.time() + 60.0,
        have_seen_first_hb=False,
        heartbeat_path=hb_file,
        intentional_exit_path=exit_marker,
        relaunch_fn=relaunch_mock,
        alert_fn=alert_mock,
    )
    assert seen_1 is True
    relaunch_mock.assert_not_called()

    # Attacker deletes heartbeat file mid-session
    hb_file.unlink()
    assert not hb_file.exists()

    # Next check: because have_seen_first_hb is True, deletion immediately triggers relaunch + alert
    last_2, dl_2, seen_2 = _check_and_heal_watchdog(
        last_watchdog_relaunch_time=last_1,
        startup_deadline=dl_1,
        have_seen_first_hb=seen_1,
        heartbeat_path=hb_file,
        intentional_exit_path=exit_marker,
        grace_secs=0.0,  # simulate cooldown expired
        relaunch_fn=relaunch_mock,
        alert_fn=alert_mock,
    )

    relaunch_mock.assert_called_once()
    alert_mock.assert_called_once()
    assert "heartbeat file missing" in alert_mock.call_args[0][0]
    assert seen_2 is False
