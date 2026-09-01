import json
import os
import shutil
import tempfile
from pathlib import Path
import pytest
import yaml

from core.security_status import (
    aggregate_audit_history,
    get_security_dashboard_data,
    get_security_status_lines,
    render_cli_report,
    render_html_report,
    SecurityMetrics,
)


@pytest.fixture
def populated_security_env():
    temp_dir = Path(tempfile.mkdtemp(prefix="jarvis_dash_test_"))
    sentinel_audit_dir = temp_dir / "sentinel" / "data" / "audit"
    sentinel_audit_dir.mkdir(parents=True, exist_ok=True)
    audit_file = sentinel_audit_dir / "audit.jsonl"

    events = [
        {"event_type": "enrollment_failed_invalid_current_pin", "timestamp": "2026-09-01T10:00:00Z", "details": {"attempt": 1}},
        {"event_type": "enrollment_failed_invalid_current_pin", "timestamp": "2026-09-01T10:01:00Z", "details": {"reason": "bad_pin"}},
        {"event_type": "lockout_soft_entered", "timestamp": "2026-09-01T10:02:00Z", "details": {"duration": 60}},
        {"event_type": "enrollment_failed_invalid_current_pin", "timestamp": "2026-09-01T10:03:00Z", "details": {"attempt": 3}},
        {"event_type": "primary_hard_lockout_triggered", "timestamp": "2026-09-01T10:04:00Z", "details": {"reason": "max_attempts"}},
        {"event_type": "auth_anomaly_friction_elevated", "timestamp": "2026-09-01T10:05:00Z", "details": {"score": 0.85}},
        {"event_type": "auth_anomaly_baseline_reset", "timestamp": "2026-09-01T10:06:00Z", "details": {"reason": "pin_change"}},
        {"event_type": "integrity_violation", "timestamp": "2026-09-01T10:07:00Z", "details": {"tampered": ["core/auth.py"]}},
        {"event_type": "integrity_check_failure", "timestamp": "2026-09-01T10:08:00Z", "details": {"error": "sig_mismatch"}},
        {"event_type": "vault_master_key_rotated", "timestamp": "2026-09-01T10:09:00Z", "details": {"status": "ok"}},
        {"event_type": "audit_hmac_key_rotated", "timestamp": "2026-09-01T10:10:00Z", "details": {"version": 2}},
        {"event_type": "duress_logon_success", "timestamp": "2026-09-01T10:11:00Z", "details": {"pin_type": "duress"}},
        {"event_type": "alert:wipe", "timestamp": "2026-09-01T10:12:00Z", "details": {"targets": 5}},
        {"event_type": "identity_enrolled", "timestamp": "2026-09-01T10:13:00Z", "details": {"user": "owner"}},
        {"event_type": "custom_event", "timestamp": "2026-09-01T10:14:00Z", "details": {}},
    ]

    with open(audit_file, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    # Baseline file
    baseline_dir = temp_dir / "sentinel" / "data" / "auth"
    baseline_dir.mkdir(parents=True, exist_ok=True)
    baseline_file = baseline_dir / "anomaly_baseline.json"
    baseline_file.write_text(json.dumps({"total_observations": 42}), encoding="utf-8")

    yield {
        "base": temp_dir,
        "audit_file": audit_file,
        "baseline_file": baseline_file,
        "expected_total": len(events),
    }

    shutil.rmtree(temp_dir, ignore_errors=True)


def test_security_dashboard_aggregates_accurate_historical_counts(populated_security_env):
    env = populated_security_env
    data = get_security_dashboard_data(
        audit_files=[env["audit_file"]],
        base_dir=env["base"],
    )
    m = data.metrics

    assert m.total_audit_events == 15
    assert m.auth_failures == 3
    assert m.lockout_events == 2
    assert m.anomaly_elevations == 2
    assert m.integrity_violations == 2
    assert m.key_rotations == 2
    assert m.duress_alerts == 1
    assert m.wipe_events == 1
    assert m.first_event_ts == "2026-09-01T10:00:00Z"
    assert m.last_event_ts == "2026-09-01T10:14:00Z"

    # Overall posture should be CRITICAL due to integrity violations
    assert data.overall_posture == "CRITICAL"
    assert data.overall_color == "red"
    assert "42 observations" in data.anomaly_status


def test_security_dashboard_read_only_side_effect_free(populated_security_env):
    env = populated_security_env
    audit_file = env["audit_file"]
    baseline_file = env["baseline_file"]

    # Capture initial file state
    audit_content_before = audit_file.read_bytes()
    baseline_content_before = baseline_file.read_bytes()
    audit_mtime_before = os.path.getmtime(audit_file)
    baseline_mtime_before = os.path.getmtime(baseline_file)

    # Perform multiple dashboard operations
    data = get_security_dashboard_data(audit_files=[audit_file], base_dir=env["base"])
    cli_rep = render_cli_report(data)
    html_out = env["base"] / "dashboard.html"
    html_rep = render_html_report(output_path=html_out, dashboard_data=data)
    status_lines = get_security_status_lines()

    # Assert no modification occurred
    assert audit_file.read_bytes() == audit_content_before
    assert baseline_file.read_bytes() == baseline_content_before
    assert os.path.getmtime(audit_file) == audit_mtime_before
    assert os.path.getmtime(baseline_file) == baseline_mtime_before
    assert html_out.exists()


def test_security_dashboard_render_cli_and_html_structure(populated_security_env):
    env = populated_security_env
    data = get_security_dashboard_data(audit_files=[env["audit_file"]], base_dir=env["base"])

    # Test CLI rendering
    cli_text = render_cli_report(data)
    assert "JARVIS / SENTINEL SECURITY DASHBOARD" in cli_text
    assert "LIVE SUBSYSTEM POSTURE:" in cli_text
    assert "HISTORICAL AUDIT" in cli_text
    assert "Total Audit Entries:     15" in cli_text

    # Test HTML rendering
    html_text = render_html_report(dashboard_data=data)
    assert "<!DOCTYPE html>" in html_text
    assert "Security Posture Dashboard" in html_text
    assert "enrollment_failed_invalid_current_pin" in html_text
    assert "CRITICAL" in html_text


def test_ci_workflow_yaml_syntax_and_structure():
    ci_file = Path(".github/workflows/ci.yml")
    assert ci_file.exists(), "CI workflow file .github/workflows/ci.yml must exist"

    with open(ci_file, "r", encoding="utf-8") as f:
        parsed = yaml.safe_load(f)

    assert "name" in parsed
    assert "on" in parsed
    assert "jobs" in parsed
    assert "test-and-verify" in parsed["jobs"]

    job = parsed["jobs"]["test-and-verify"]
    assert job.get("runs-on") == "windows-latest"

    step_names = [s.get("name", "") for s in job.get("steps", [])]
    assert any("Run Full Security Test Suite" in n for n in step_names)
    assert any("Generate Security Status Dashboard" in n for n in step_names)
