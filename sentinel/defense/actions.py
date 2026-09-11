"""Autonomous defense action primitives for Sentinel."""
import os
import sys
import time
import json
import ctypes
import getpass
import logging
import platform
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from sentinel.config.settings import default_settings
from sentinel.audit.security_utils import apply_owner_only_dacl

logger = logging.getLogger(__name__)


def lock_session() -> bool:
    """
    Executes an operating system desktop session lock.
    Windows: invokes user32.LockWorkStation().
    Non-Windows fallback: invokes standard desktop lock utilities.
    Returns True if successfully locked, False otherwise.
    """
    if platform.system().lower() == "windows":
        try:
            user32 = ctypes.windll.user32
            # LockWorkStation returns non-zero on success in Win32 API
            res = user32.LockWorkStation()
            if res != 0:
                logger.info("[SentinelDefense] 🔒 OS session locked via LockWorkStation")
                return True
            else:
                err = ctypes.GetLastError()
                logger.error(f"[SentinelDefense] ❌ LockWorkStation returned 0 (error code: {err})")
                return False
        except Exception as e:
            logger.error(f"[SentinelDefense] ❌ Failed to invoke LockWorkStation: {e}")
            return False
    else:
        # Cross-platform fallback (Linux/macOS)
        try:
            for cmd in [["xdg-screensaver", "lock"], ["gnome-screensaver-command", "-l"], ["pmset", "displaysleepnow"]]:
                try:
                    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2.0)
                    logger.info(f"[SentinelDefense] 🔒 OS session locked via {cmd[0]}")
                    return True
                except Exception:
                    continue
        except Exception as e:
            logger.error(f"[SentinelDefense] ❌ Non-Windows lock failed: {e}")
        return False


def revoke_active_tokens(auth_engine: Any = None, mobile_hub: Any = None) -> int:
    """
    Invalidates all currently active presence challenge tokens, session tokens,
    and mobile companion connections.
    Returns the exact count (int) of revoked tokens and terminated sessions.
    """
    revocation_count = 0

    # 1. Invalidate enrollment/auth presence tokens
    if auth_engine is not None:
        enrollment_mgr = getattr(auth_engine, "enrollment_manager", None)
        if enrollment_mgr is not None:
            presence_file = getattr(enrollment_mgr, "presence_file", None)
            if presence_file and isinstance(presence_file, Path) and presence_file.exists():
                try:
                    presence_file.unlink()
                    revocation_count += 1
                    logger.info(f"[SentinelDefense] 🚫 Unlinked physical presence token at {presence_file}")
                except Exception as e:
                    logger.warning(f"[SentinelDefense] ⚠️ Failed to unlink presence token: {e}")

        # Invalidate in-memory presence token caches if present
        for attr in ["_active_presence_tokens", "active_tokens", "_presence_cache"]:
            token_store = getattr(auth_engine, attr, None)
            if isinstance(token_store, (dict, set, list)):
                revocation_count += len(token_store)
                if isinstance(token_store, dict):
                    token_store.clear()
                elif isinstance(token_store, set):
                    token_store.clear()
                elif isinstance(token_store, list):
                    token_store.clear()

    # 2. Terminate mobile companion websocket sessions if active
    if mobile_hub is not None:
        try:
            clients = getattr(mobile_hub, "_clients", None)
            if clients and isinstance(clients, (set, list)):
                client_list = list(clients)
                revocation_count += len(client_list)
                for ws in client_list:
                    try:
                        # Close websocket connection with 4403 (unauthorized/revoked)
                        import asyncio
                        if hasattr(ws, "close"):
                            asyncio.create_task(ws.close(code=4403, reason="Security Lockdown: Tokens Revoked"))
                    except Exception:
                        pass
        except Exception as e:
            logger.warning(f"[SentinelDefense] ⚠️ Mobile hub session revocation error: {e}")

    logger.info(f"[SentinelDefense] 🛑 Revoked {revocation_count} active tokens/sessions")
    return revocation_count


def capture_evidence(
    evidence_dir: Optional[Path] = None,
    context_summary: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> Path:
    """
    Captures a local forensics bundle (screenshot, camera frame, and system context).
    STRICT INVARIANT: Operates entirely locally with zero cloud or external network calls.
    Secured with owner-only DACL.
    Returns the Path to the evidence directory.
    """
    if evidence_dir is None:
        now_ts = int(time.time())
        import secrets
        rnd = secrets.token_hex(4)
        evidence_dir = default_settings.evidence_dir / f"evidence_{now_ts}_{rnd}"

    evidence_dir = Path(evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    apply_owner_only_dacl(evidence_dir)

    # 1. Capture screen
    try:
        from actions.screen_processor import _capture_screenshot
        shot_bytes = _capture_screenshot()
        if shot_bytes:
            shot_file = evidence_dir / "screenshot.jpg"
            shot_file.write_bytes(shot_bytes)
            apply_owner_only_dacl(shot_file)
            logger.info(f"[SentinelDefense] 📸 Screenshot saved to {shot_file}")
    except Exception as e:
        logger.warning(f"[SentinelDefense] ⚠️ Evidence screenshot capture failed: {e}")

    # 2. Capture webcam if available
    try:
        from actions.screen_processor import _capture_camera
        cam_bytes = _capture_camera()
        if cam_bytes:
            cam_file = evidence_dir / "camera.jpg"
            cam_file.write_bytes(cam_bytes)
            apply_owner_only_dacl(cam_file)
            logger.info(f"[SentinelDefense] 📷 Camera frame saved to {cam_file}")
    except Exception as e:
        # Camera may be busy or absent - non-fatal
        logger.debug(f"[SentinelDefense] Camera capture skipped or unavailable: {e}")

    # 3. Write metadata and recent context
    context_data = {
        "timestamp": time.time(),
        "iso_timestamp": datetime.now(timezone.utc).isoformat(),
        "context_summary": context_summary or "",
        "pid": os.getpid(),
        "user": getpass.getuser(),
        "platform": platform.platform(),
        "metadata": metadata or {},
    }
    context_file = evidence_dir / "context.json"
    context_file.write_text(json.dumps(context_data, indent=2), encoding="utf-8")
    apply_owner_only_dacl(context_file)

    logger.info(f"[SentinelDefense] 🛡️ Evidence bundle assembled at {evidence_dir}")
    return evidence_dir


def network_isolate(reason: str = "", dry_run: bool = False) -> bool:
    """
    Applies network isolation by enabling defensive firewall containment.
    GATED: requires allow_network_isolation=True in SentinelSettings or
    SENTINEL_ALLOW_NETWORK_ISOLATION=1 in environment.
    Returns True if isolation is applied, False if rejected or disabled.
    """
    allow = default_settings.allow_network_isolation or (
        os.environ.get("SENTINEL_ALLOW_NETWORK_ISOLATION", "").strip().lower() in ("1", "true", "yes")
    )
    if not allow:
        logger.warning(
            f"[SentinelDefense] ⚠️ Network isolation blocked: allow_network_isolation is disabled in settings. Reason: {reason}"
        )
        return False

    if dry_run:
        logger.info(f"[SentinelDefense] 🧪 Network isolation dry-run: would isolate host network for '{reason}'")
        return True

    if platform.system().lower() == "windows":
        try:
            # Block outbound and inbound via Windows Firewall profile policy
            subprocess.run(
                ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5.0,
            )
            logger.critical(f"[SentinelDefense] 🚨 Network isolation APPLIED via Windows Firewall: {reason}")
            return True
        except Exception as e:
            logger.error(f"[SentinelDefense] ❌ Failed to apply network isolation via netsh: {e}")
            return False
    else:
        logger.warning("[SentinelDefense] Network isolation not configured for this operating system")
        return False


def alert_owner(summary: str, evidence_path: Optional[Path] = None, event_type: str = "sentinel_defense_alert") -> bool:
    """
    Dispatches critical incident alerts to configured channels (Telegram, local alert history).
    Must be called BEFORE network_isolate() during an escalation.
    Returns True if dispatch succeeded, False otherwise.
    """
    logger.critical(f"[SentinelDefense] 🚨 OWNER ALERT: {summary}")

    dispatched = False
    # 1. Telegram Alert dispatch
    try:
        from core.telegram_alert import TelegramAlerter
        alerter = TelegramAlerter()
        if alerter.configured:
            msg = f"🚨 <b>SENTINEL DEFENSE ALERT</b>\n\n{summary}"
            if evidence_path:
                msg += f"\n\n📁 Evidence: <code>{evidence_path.name}</code>"
            alerter.send_message(msg)
            dispatched = True
    except Exception as e:
        logger.warning(f"[SentinelDefense] Telegram alert dispatch unavailable: {e}")

    # 2. Record in alert history
    try:
        alert_record = {
            "timestamp": time.time(),
            "iso_time": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "summary": summary,
            "evidence_path": str(evidence_path) if evidence_path else None,
        }
        history_file = default_settings.base_dir / "defense_alerts.jsonl"
        with open(history_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert_record) + "\n")
        apply_owner_only_dacl(history_file)
        dispatched = True
    except Exception as e:
        logger.warning(f"[SentinelDefense] Failed to append to defense_alerts.jsonl: {e}")

    return dispatched
