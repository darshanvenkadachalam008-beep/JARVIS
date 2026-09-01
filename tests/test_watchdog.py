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
    """Verifies that when INTENTIONAL_EXIT_PATH marker exists, no relaunch is triggered even if heartbeat is missing."""
    hb_file = tmp_path / "memory" / "watchdog_heartbeat.json"
    exit_marker = tmp_path / "memory" / "jarvis_intentional_exit.marker"
    exit_marker.parent.mkdir(parents=True, exist_ok=True)
    exit_marker.write_text(str(time.time()), encoding="utf-8")

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
