"""
core/security_status.py — Security Telemetry & Historical Posture Dashboard (C11)
================================================================================
Comprehensive, strictly read-only security telemetry and posture analytics:
1. Real-time snapshot metrics: Vault encryption state, Audit chain cryptographic health,
   Access Control / Lockout posture, Anomaly baseline status, and Codebase integrity.
2. Historical trend analytics: Aggregates events across the audit chain:
   - Authentication failures and Lockout escalations
   - Anomaly friction elevations and baseline shifts
   - Codebase integrity check passes, failures, and tampering alerts
   - Cryptographic key rotation history (Vault master key & Audit HMAC keys)
   - Duress alerts and emergency kill-switch wipe invocations
3. Multi-channel reporting:
   - Compact status lines for the UI Status Panel (get_security_status_lines())
   - Rich ANSI/ASCII terminal CLI report (render_cli_report())
   - Self-contained, zero-dependency local HTML dashboard (render_html_report())
4. Strict Read-Only Guarantee: Viewing or rendering the dashboard never modifies audit logs,
   baseline models, lockout counters, or encryption keys.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional

ColorKey = str  # "green" | "amber" | "red"


def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


@dataclass
class SecurityMetrics:
    total_audit_events: int = 0
    auth_failures: int = 0
    lockout_events: int = 0
    anomaly_elevations: int = 0
    integrity_violations: int = 0
    key_rotations: int = 0
    duress_alerts: int = 0
    wipe_events: int = 0
    first_event_ts: Optional[str] = None
    last_event_ts: Optional[str] = None
    event_type_breakdown: Dict[str, int] = field(default_factory=dict)


@dataclass
class SecurityDashboardData:
    generated_at: str
    overall_posture: str  # "SECURE", "WARNING", "CRITICAL"
    overall_color: ColorKey
    status_lines: List[Tuple[str, ColorKey]]
    metrics: SecurityMetrics
    vault_status: str
    audit_chain_status: str
    access_control_status: str
    integrity_status: str
    anomaly_status: str


def get_security_status_lines() -> List[Tuple[str, ColorKey]]:
    """
    Returns live snapshot status lines for ui.py status-panel refresh timer.
    Strictly read-only: does not unlock vault or mutate state.
    """
    lines: List[Tuple[str, ColorKey]] = []

    # ── Vault ────────────────────────────────────────────────────────────
    try:
        from core.secure_vault import SecureVault, _vault_singleton
        vault = SecureVault()
        if not vault.exists():
            lines.append(("VAULT NOT SET UP", "amber"))
        elif _vault_singleton is not None:
            lines.append(("VAULT UNLOCKED", "green"))
        else:
            lines.append(("VAULT LOCKED", "amber"))
    except Exception:
        lines.append(("VAULT UNAVAILABLE", "amber"))

    # ── Audit log integrity ─────────────────────────────────────────────
    try:
        from core.audit_log import AuditLog
        ok, problem = AuditLog().verify()
        if ok:
            lines.append(("AUDIT CHAIN OK", "green"))
        else:
            lines.append(("AUDIT CHAIN TAMPERED", "red"))
    except Exception:
        lines.append(("AUDIT LOG UNAVAILABLE", "amber"))

    # ── PIN / access control ────────────────────────────────────────────
    try:
        from core.access_control import AccessControl
        ac = AccessControl()
        if not ac.is_configured():
            lines.append(("PIN NOT SET", "amber"))
        else:
            locked_for = ac._seconds_locked()
            if locked_for > 0:
                lines.append((f"PIN LOCKED {int(locked_for)}s", "red"))
            else:
                lines.append(("PIN ARMED", "green"))
    except Exception:
        lines.append(("ACCESS CONTROL UNAVAILABLE", "amber"))

    # ── Codebase integrity ──────────────────────────────────────────────
    try:
        from core.integrity_monitor import IntegrityMonitor
        monitor = IntegrityMonitor()
        if not monitor.manifest_path.exists() or not monitor.public_key_path.exists():
            lines.append(("INTEGRITY BASELINE MISSING", "amber"))
        else:
            rep = monitor.verify_integrity()
            if rep.is_valid:
                lines.append(("CODEBASE INTEGRITY VERIFIED", "green"))
            else:
                lines.append(("CODEBASE INTEGRITY TAMPERED", "red"))
    except Exception:
        lines.append(("INTEGRITY CHECK UNAVAILABLE", "amber"))

    return lines


def aggregate_audit_history(
    audit_files: Optional[List[Path]] = None,
) -> SecurityMetrics:
    """
    Scans existing audit chain logs read-only and calculates historical event metrics.
    Guarantees no modifications to audit logs or system state.
    """
    base = _base_dir()
    if audit_files is None:
        audit_files = [
            base / "sentinel" / "data" / "audit" / "audit.jsonl",
            base / "memory" / "audit_log.jsonl",
            base / "data" / "audit" / "audit.jsonl",
        ]

    metrics = SecurityMetrics()
    seen_timestamps: List[str] = []

    for path in audit_files:
        if not path.exists():
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except Exception:
                        continue

                    metrics.total_audit_events += 1
                    event_type = (
                        record.get("event_type")
                        or record.get("action")
                        or record.get("event")
                        or "unknown"
                    )
                    ts = (
                        record.get("timestamp")
                        or record.get("ts")
                        or record.get("created_at")
                    )
                    if ts and isinstance(ts, str):
                        seen_timestamps.append(ts)

                    metrics.event_type_breakdown[event_type] = (
                        metrics.event_type_breakdown.get(event_type, 0) + 1
                    )

                    # Categorize events by substring containment against lowercased event_type.
                    # This cleanly matches real emitter event types across both core and sentinel:
                    # - auth_failures: 'primary_auth_failed', 'enrollment_failed_invalid_current_pin', 'login_failed'
                    # - lockout_events: 'lockout_soft_entered', 'lockout_hard_entered', 'primary_hard_lockout_triggered'
                    # - anomaly_elevations: 'auth_anomaly_friction_elevated', 'auth_anomaly_baseline_reset'
                    # - integrity_violations: 'integrity_violation', 'integrity_check_failure', 'audit_tamper_detected'
                    # - key_rotations: 'vault_key_rotated', 'audit_hmac_key_rotated'
                    # - duress_alerts: 'duress_login_detected', 'intruder_alert', 'duress_alert_dispatched'
                    # - wipe_events: 'wipe_initiated', 'wipe_confirmed', 'wipe_failed'
                    ev_lower = event_type.lower()
                    if any(k in ev_lower for k in ("auth_failed", "login_failed", "primary_auth_failed", "invalid_current_pin")):
                        metrics.auth_failures += 1
                    if any(k in ev_lower for k in ("lockout", "locked")):
                        metrics.lockout_events += 1
                    if any(k in ev_lower for k in ("anomaly", "friction_elevated")):
                        metrics.anomaly_elevations += 1
                    if any(k in ev_lower for k in ("integrity_violation", "tamper", "tampered", "integrity_check_failure")):
                        metrics.integrity_violations += 1
                    if any(k in ev_lower for k in ("rotated", "rotation")):
                        metrics.key_rotations += 1
                    if any(k in ev_lower for k in ("duress", "intruder")):
                        metrics.duress_alerts += 1
                    if any(k in ev_lower for k in ("wipe",)):
                        metrics.wipe_events += 1
        except Exception:
            pass

    if seen_timestamps:
        seen_timestamps.sort()
        metrics.first_event_ts = seen_timestamps[0]
        metrics.last_event_ts = seen_timestamps[-1]

    return metrics


def get_security_dashboard_data(
    audit_files: Optional[List[Path]] = None,
    base_dir: Optional[Path] = None,
) -> SecurityDashboardData:
    """
    Compiles complete security posture dashboard data (snapshot status + historical trends).
    Completely read-only.
    """
    base = base_dir or _base_dir()
    status_lines = get_security_status_lines()
    metrics = aggregate_audit_history(audit_files)

    # Determine overall posture
    colors = [color for _, color in status_lines]
    if "red" in colors or metrics.integrity_violations > 0:
        overall_posture = "CRITICAL"
        overall_color = "red"
    elif "amber" in colors:
        overall_posture = "WARNING"
        overall_color = "amber"
    else:
        overall_posture = "SECURE"
        overall_color = "green"

    # Extract component statuses
    def find_status(prefix: str, default: str = "UNKNOWN") -> str:
        for lbl, _ in status_lines:
            if prefix in lbl:
                return lbl
        return default

    vault_status = find_status("VAULT", "VAULT STATUS UNKNOWN")
    audit_status = find_status("AUDIT", "AUDIT CHAIN UNKNOWN")
    pin_status = find_status("PIN", find_status("ACCESS", "PIN STATUS UNKNOWN"))
    integrity_status = find_status("INTEGRITY", "INTEGRITY UNKNOWN")

    anomaly_baseline_file = base / "sentinel" / "data" / "auth" / "anomaly_baseline.json"
    if anomaly_baseline_file.exists():
        try:
            data = json.loads(anomaly_baseline_file.read_text(encoding="utf-8"))
            obs = data.get("total_observations", 0)
            anomaly_status = f"ANOMALY BASELINE CALIBRATED ({obs} observations)"
        except Exception:
            anomaly_status = "ANOMALY BASELINE CORRUPTED"
    else:
        anomaly_status = "ANOMALY BASELINE PENDING"

    return SecurityDashboardData(
        generated_at=datetime.now(timezone.utc).isoformat(),
        overall_posture=overall_posture,
        overall_color=overall_color,
        status_lines=status_lines,
        metrics=metrics,
        vault_status=vault_status,
        audit_chain_status=audit_status,
        access_control_status=pin_status,
        integrity_status=integrity_status,
        anomaly_status=anomaly_status,
    )


def render_cli_report(dashboard_data: Optional[SecurityDashboardData] = None) -> str:
    """Renders a structured, ANSI-formatted security dashboard report for the terminal."""
    data = dashboard_data or get_security_dashboard_data()
    m = data.metrics

    badge_map = {
        "green": "[SECURE]",
        "amber": "[WARNING]",
        "red": "[CRITICAL]",
    }
    badge = badge_map.get(data.overall_color, f"[{data.overall_posture}]")

    lines = [
        "+==================================================================================+",
        "|                       JARVIS / SENTINEL SECURITY DASHBOARD                       |",
        "+==================================================================================+",
        f"| Overall Status: {badge:<25} Generated: {data.generated_at[:19]:<24} |",
        "+----------------------------------------------------------------------------------+",
        "| LIVE SUBSYSTEM POSTURE:                                                          |",
        f"|   - Vault Status:            {data.vault_status:<49} |",
        f"|   - Audit Chain:             {data.audit_chain_status:<49} |",
        f"|   - Access Control:          {data.access_control_status:<49} |",
        f"|   - Codebase Integrity:      {data.integrity_status:<49} |",
        f"|   - Anomaly Engine:          {data.anomaly_status:<49} |",
        "+----------------------------------------------------------------------------------+",
        "| HISTORICAL AUDIT & SECURITY METRICS:                                             |",
        f"|   - Total Audit Entries:     {m.total_audit_events:<49} |",
        f"|   - Auth Failures:           {m.auth_failures:<49} |",
        f"|   - Lockout Events:          {m.lockout_events:<49} |",
        f"|   - Anomaly Friction Steps:  {m.anomaly_elevations:<49} |",
        f"|   - Tamper Detections:       {m.integrity_violations:<49} |",
        f"|   - Key Rotations:           {m.key_rotations:<49} |",
        f"|   - Duress / Intruder Events:{m.duress_alerts:<49} |",
        f"|   - Emergency Wipe Events:   {m.wipe_events:<49} |",
        "+==================================================================================+",
    ]
    return "\n".join(lines)


def render_html_report(
    output_path: Optional[Path] = None,
    dashboard_data: Optional[SecurityDashboardData] = None,
) -> str:
    """
    Renders a standalone, zero-dependency local HTML security dashboard report.
    If output_path is provided, writes the HTML file to disk.
    """
    data = dashboard_data or get_security_dashboard_data()
    m = data.metrics

    color_map = {
        "green": "#10b981",
        "amber": "#f59e0b",
        "red": "#ef4444",
    }
    overall_hex = color_map.get(data.overall_color, "#6b7280")

    status_items_html = "".join(
        f"""<div class="card status-card">
            <span class="status-indicator" style="background-color: {color_map.get(c, '#6b7280')};"></span>
            <span class="status-label">{label}</span>
        </div>"""
        for label, c in data.status_lines
    )

    top_events_html = "".join(
        f"<tr><td><code>{k}</code></td><td><strong>{v}</strong></td></tr>"
        for k, v in sorted(m.event_type_breakdown.items(), key=lambda x: x[1], reverse=True)[:10]
    ) or "<tr><td colspan='2'>No audit events recorded</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JARVIS / Sentinel Security Posture Dashboard</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border-color: #334155;
            --accent-color: {overall_hex};
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            padding: 24px;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }}
        h1 {{
            margin: 0;
            font-size: 24px;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .badge {{
            padding: 6px 14px;
            border-radius: 9999px;
            font-weight: bold;
            font-size: 14px;
            text-transform: uppercase;
            background-color: {overall_hex}22;
            color: {overall_hex};
            border: 1px solid {overall_hex};
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
        }}
        .status-card {{
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 13px;
            font-weight: 600;
        }}
        .status-indicator {{
            width: 10px;
            height: 10px;
            border-radius: 50%;
            display: inline-block;
        }}
        .metric-card h3 {{
            margin: 0 0 8px 0;
            color: var(--text-muted);
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .metric-card .value {{
            font-size: 28px;
            font-weight: bold;
            color: var(--text-main);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 8px;
        }}
        th, td {{
            text-align: left;
            padding: 8px 12px;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            color: var(--text-muted);
            font-size: 12px;
            text-transform: uppercase;
        }}
        code {{
            background: #0f172a;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 12px;
            color: #38bdf8;
        }}
        footer {{
            margin-top: 32px;
            text-align: center;
            color: var(--text-muted);
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>🛡️ Security Posture Dashboard</h1>
                <div style="color: var(--text-muted); font-size: 13px; margin-top: 4px;">
                    Target: Local Host | Generated: {data.generated_at[:19]} UTC
                </div>
            </div>
            <div class="badge">{data.overall_posture}</div>
        </header>

        <h2 style="font-size: 16px; margin-bottom: 12px;">Live Subsystems</h2>
        <div class="grid">
            {status_items_html}
        </div>

        <h2 style="font-size: 16px; margin-bottom: 12px;">Historical Audit Metrics</h2>
        <div class="grid">
            <div class="card metric-card">
                <h3>Total Audit Events</h3>
                <div class="value">{m.total_audit_events}</div>
            </div>
            <div class="card metric-card">
                <h3>Auth Failures</h3>
                <div class="value" style="color: {'#ef4444' if m.auth_failures > 0 else 'inherit'}">{m.auth_failures}</div>
            </div>
            <div class="card metric-card">
                <h3>Lockout Escalations</h3>
                <div class="value" style="color: {'#ef4444' if m.lockout_events > 0 else 'inherit'}">{m.lockout_events}</div>
            </div>
            <div class="card metric-card">
                <h3>Anomaly Steps</h3>
                <div class="value" style="color: {'#f59e0b' if m.anomaly_elevations > 0 else 'inherit'}">{m.anomaly_elevations}</div>
            </div>
            <div class="card metric-card">
                <h3>Tamper Detections</h3>
                <div class="value" style="color: {'#ef4444' if m.integrity_violations > 0 else 'inherit'}">{m.integrity_violations}</div>
            </div>
            <div class="card metric-card">
                <h3>Key Rotations</h3>
                <div class="value">{m.key_rotations}</div>
            </div>
        </div>

        <div class="card" style="margin-top: 16px;">
            <h3 style="margin-top: 0; font-size: 14px;">Audit Chain Event Breakdown</h3>
            <table>
                <thead>
                    <tr><th>Event Type</th><th>Occurrences</th></tr>
                </thead>
                <tbody>
                    {top_events_html}
                </tbody>
            </table>
        </div>

        <footer>
            JARVIS / Sentinel Read-Only Security Telemetry System
        </footer>
    </div>
</body>
</html>
"""
    if output_path is not None:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(html, encoding="utf-8")

    return html


if __name__ == "__main__":
    print(render_cli_report())
    out_file = _base_dir() / "memory" / "security_dashboard.html"
    render_html_report(output_path=out_file)
    print(f"\n[Dashboard] Standalone HTML report generated: {out_file}")