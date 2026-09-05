"""
core/unified_security_alert.py — Unified Security Alert Dispatcher
====================================================================
Unifies multiple security failure triggers into a single, cohesive alert pipeline:
  1. Windows lock-screen password failures (Event Log 4625)
  2. JARVIS PIN authentication triage failures (intruder / repeated lockout)
  3. JARVIS voice-identity verification failures (speaker mismatch on sensitive actions)
  4. Cold-boot / Credential Provider duress alerts

Integrates with LocationProvider (3-tier fallback chain) with strictly labeled
source and precision tier metadata.
Routes all alerts through ProactiveBridge at CRITICAL priority (10), guaranteeing
tamper-evident audit logging before out-of-band delivery.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from core.location_provider import LocationProvider, LocationResult
from core.proactive_bridge import ProactiveBridge, ProactiveEvent, ProactivePriority
from core.sentinel_extras import AlertHistory

logger = logging.getLogger("JARVIS.UnifiedSecurityAlert")


TRIGGER_TITLES = {
    "windows_lockscreen_failure": "Windows Lockscreen Intruder Alert",
    "jarvis_pin_failure": "JARVIS PIN Gate Violation",
    "jarvis_voice_auth_failure": "Voice Identity Authentication Failure",
    "duress_logon_success": "SILENT DURESS LOGON ALERT",
}


def dispatch_security_alert(
    trigger_type: str,
    actor: str = "system",
    details: Optional[Dict[str, Any]] = None,
    snapshot_bytes: Optional[bytes] = None,
    bridge: Optional[ProactiveBridge] = None,
    custom_msg: Optional[str] = None,
    location: Optional[LocationResult] = None,
    face_note: Optional[str] = None,
    on_alert_cb: Optional[Callable[[str, Optional[bytes]], None]] = None,
    log_fn: Optional[Callable[[str], None]] = None,
    audit_logger: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Unified entrypoint for all security intrusion and authentication failure alerts.

    Flow:
      1. Resolves location via LocationProvider (Windows Location API -> IP Geolocation -> Phone GPS).
      2. Assembles structured event payload with explicit 'source' and 'precision_tier'.
      3. Records to AlertHistory.
      4. Dispatches to ProactiveBridge at CRITICAL priority (10), which guarantees
         synchronous audit logging before async fanning out to voice, UI, mobile, telegram.
    """
    hostname = socket.gethostname()
    now_dt = datetime.now()
    time_str = now_dt.strftime("%H:%M:%S")

    # 1. Resolve Location
    if location is None:
        try:
            location = LocationProvider.get_instance().get_location(timeout=1.5, non_blocking=True)
        except Exception as e:
            logger.warning(f"Location resolution error: {e}")
            location = LocationResult(source="unavailable", precision_tier="unavailable")

    loc_summary = location.summary_str()

    # 2. Build Title and Alert Message
    title = TRIGGER_TITLES.get(trigger_type, "Security Sentinel Alert")
    fn_suffix = f" — {face_note}" if face_note else ""

    if custom_msg:
        main_text = custom_msg
    elif trigger_type == "windows_lockscreen_failure":
        main_text = f"Failed Windows logon attempt on {hostname} at {time_str}"
    elif trigger_type == "jarvis_pin_failure":
        action_name = (details or {}).get("action", "restricted_action")
        main_text = f"Unauthorized access attempt / PIN failure on action '{action_name}'"
    elif trigger_type == "jarvis_voice_auth_failure":
        action_name = (details or {}).get("action", "wake/auth")
        score = (details or {}).get("score", "N/A")
        main_text = f"Unenrolled voice detected on sensitive action '{action_name}' (match score: {score})"
    else:
        main_text = f"Security sentinel alert triggered: {trigger_type}"

    full_message = f"🚨 {title}: {main_text}{fn_suffix}\n📍 Location: {loc_summary}"

    if log_fn:
        try:
            log_fn(f"SYS: {full_message}")
        except Exception:
            pass

    # 3. Assemble Structured Event Payload
    merged_details = dict(details or {})
    merged_details.update({
        "trigger_type": trigger_type,
        "hostname": hostname,
        "time": time_str,
        "location": location.to_dict(),
        "location_source": location.source,
        "precision_tier": location.precision_tier,
        "face_note": face_note or "",
    })

    event_data = {
        "trigger_type": trigger_type,
        "actor": actor,
        "hostname": hostname,
        "time": time_str,
        "location": location.to_dict(),
        "location_source": location.source,
        "precision_tier": location.precision_tier,
        "details": merged_details,
        "jpeg_bytes": snapshot_bytes,
    }

    # 4. Record to AlertHistory
    try:
        AlertHistory.record(
            event_type=trigger_type,
            title=title,
            detail=full_message,
            extra=merged_details,
        )
    except Exception as e:
        logger.warning(f"AlertHistory recording failed: {e}")

    # 5. Dispatch via ProactiveBridge (CRITICAL priority)
    if bridge:
        try:
            event = ProactiveEvent(
                category="security",
                title=title,
                message=full_message,
                priority=ProactivePriority.CRITICAL,
                ttl_seconds=86400.0,
                dedup_key=f"sec_alert:{trigger_type}:{time_str}",
                data=event_data,
                channels={"audit", "voice", "ui", "mobile", "telegram"},
            )
            bridge.dispatch(event)
        except Exception as e:
            logger.error(f"ProactiveBridge dispatch error: {e}")
    else:
        # Fallback if no bridge is provided
        try:
            if audit_logger is not None:
                audit_logger.log_event(event_type=trigger_type, actor=actor, details=merged_details)
            else:
                from sentinel.audit import AuditLogger
                _audit = AuditLogger()
                _audit.log_event(event_type=trigger_type, actor=actor, details=merged_details)
        except Exception as e:
            logger.warning("Audit logging fallback failed: %s", e)
            try:
                from core.audit_log import AuditLog
                AuditLog().append(f"alert:{trigger_type}", merged_details)
            except Exception:
                pass

        if on_alert_cb:
            try:
                on_alert_cb(full_message, snapshot_bytes)
            except Exception as e:
                logger.warning(f"on_alert_cb failed: {e}")

    return event_data
