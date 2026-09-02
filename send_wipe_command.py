"""
send_wipe_command.py — Owner-Facing Remote Wipe Command Generator & Dispatcher
==============================================================================
Generates and cryptographically signs an out-of-band emergency wipe command
for the Sentinel / JARVIS daemon.

Operational Threat Model & Setup Instructions:
----------------------------------------------
⚠️ REQUIRED ONE-TIME SETUP FOR OFF-DEVICE RESILIENCE:
By default, the 32-byte HMAC authentication key is generated and stored locally
under Windows DPAPI (tied to the local Windows user profile). If the protected device
is lost, stolen, or physically unreachable, local DPAPI storage cannot be accessed.

Therefore, the operator MUST perform a one-time key export during initial setup:
    python send_wipe_command.py --export-key

Store the exported 64-character hex key in an off-device password manager (1Password,
Bitwarden) or secure mobile store. In an actual emergency, you can trigger the remote
wipe from any device or phone without access to the host machine.

Usage Modes:
------------
1. Off-Device Remote Operator (Real-World Emergency):
   When the target device is lost, stolen, or inaccessible, the operator generates
   and dispatches the signed payload from an independent operator laptop, phone, or CI runner:
       python send_wipe_command.py --key-hex <64-char-hex-key> --send --to emergency-inbox@example.com

2. On-Device Local Diagnostics:
   When run on the target machine with DPAPI session access:
       python send_wipe_command.py --send --to emergency-inbox@example.com

3. Manual Dispatch (Payload Inspection / Custom Mail Client):
   Omit `--send` to output the exact signed JSON payload to stdout, suitable for
   pasting into the body of an email sent from any mobile mail app (Gmail, Outlook, etc.):
       python send_wipe_command.py --key-hex <64-char-hex-key>
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import smtplib
import sys
import time
from email.message import EmailMessage
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

from core.email_wipe_listener import (
    EmailWipeListener,
    load_email_wipe_credentials,
    WIPE_KEY_DEFAULT,
    WIPE_CREDS_DEFAULT,
)


def export_hmac_key(key_path: Optional[Path] = None) -> str:
    """
    Decrypts and returns the DPAPI-protected 32-byte HMAC secret key as a 64-character hex string.
    Zero persistent side-effects: creates no logs, no temp files, and writes nowhere to disk.
    """
    target_path = key_path or WIPE_KEY_DEFAULT
    raw_key = EmailWipeListener._get_or_create_hmac_key(target_path)
    return raw_key.hex()


def load_hmac_key(
    key_hex: Optional[str] = None,
    key_path: Optional[Path] = None,
) -> bytes:
    """
    Loads the 32-byte HMAC signing key.
    Precedence:
    1. Explicit key_hex CLI argument.
    2. SENTINEL_EMAIL_WIPE_KEY environment variable.
    3. DPAPI-protected key file on local device.
    """
    if key_hex:
        raw = bytes.fromhex(key_hex.strip())
        if len(raw) != 32:
            raise ValueError(f"HMAC key hex must decode to exactly 32 bytes (got {len(raw)} bytes).")
        return raw

    env_hex = os.environ.get("SENTINEL_EMAIL_WIPE_KEY")
    if env_hex:
        raw = bytes.fromhex(env_hex.strip())
        if len(raw) != 32:
            raise ValueError(f"SENTINEL_EMAIL_WIPE_KEY must decode to exactly 32 bytes (got {len(raw)} bytes).")
        return raw

    target_path = key_path or WIPE_KEY_DEFAULT
    return EmailWipeListener._get_or_create_hmac_key(target_path)


def generate_signed_wipe_payload(
    key: bytes,
    action: str = "emergency_wipe",
    reason: str = "remote_operator_emergency_signal",
    timestamp: Optional[float] = None,
    nonce: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Constructs and signs a canonical emergency wipe command payload.
    """
    if timestamp is None:
        timestamp = time.time()
    if nonce is None:
        nonce = secrets.token_hex(16)

    payload = {
        "action": action,
        "timestamp": float(timestamp),
        "nonce": str(nonce),
        "reason": str(reason),
    }

    signature = EmailWipeListener.compute_signature(key, payload)
    return {
        "payload": payload,
        "signature": signature,
    }


def send_email_command(
    command_dict: Dict[str, Any],
    to_addr: str,
    smtp_server: str = "smtp.gmail.com",
    smtp_port: int = 465,
    smtp_user: Optional[str] = None,
    smtp_password: Optional[str] = None,
    creds_path: Optional[Path] = None,
    subject: str = "SENTINEL EMERGENCY WIPE SIGNAL",
) -> Tuple[bool, str]:
    """
    Dispatches the signed command payload via SMTP over SSL.
    """
    user = smtp_user
    password = smtp_password
    if not user or not password:
        user, password = load_email_wipe_credentials(creds_path or WIPE_CREDS_DEFAULT)

    if not user or not password:
        return False, "Missing SMTP credentials (neither CLI args nor DPAPI storage provided)."

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = user
    msg["To"] = to_addr
    msg.set_content(json.dumps(command_dict, indent=2))

    try:
        with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
            server.login(user, password)
            server.send_message(msg)
        return True, f"Emergency wipe command successfully dispatched to {to_addr} via {smtp_server}:{smtp_port}"
    except Exception as e:
        return False, f"SMTP dispatch failed: {e}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sentinel / JARVIS Out-of-Band Signed Emergency Wipe Command Generator & Dispatcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--export-key", action="store_true", help="One-time export of DPAPI-stored master HMAC key for off-device backup.")
    parser.add_argument("--key-hex", help="64-character hex string of the 32-byte master HMAC key (for off-device use).")
    parser.add_argument("--key-path", type=Path, help="Path to DPAPI key file on local device.")
    parser.add_argument("--reason", default="remote_operator_emergency_signal", help="Reason recorded in the audit log.")
    parser.add_argument("--send", action="store_true", help="Automatically dispatch email via SMTP.")
    parser.add_argument("--to", help="Destination monitored inbox email address (required if --send is used).")
    parser.add_argument("--smtp-server", default="smtp.gmail.com", help="SMTP server hostname (default: smtp.gmail.com).")
    parser.add_argument("--smtp-port", type=int, default=465, help="SMTP server port (default: 465).")
    parser.add_argument("--smtp-user", help="SMTP username (overrides DPAPI).")
    parser.add_argument("--smtp-pass", help="SMTP password (overrides DPAPI).")
    parser.add_argument("--creds-path", type=Path, help="Path to DPAPI credentials file.")

    args = parser.parse_args()

    if args.export_key:
        try:
            hex_key = export_hmac_key(key_path=args.key_path)
            print("================================================================================")
            print("🔐 SENTINEL EMAIL KILL-SWITCH: MASTER HMAC KEY EXPORT")
            print("================================================================================")
            print("⚠️  SECURITY WARNING:")
            print("1. This 32-byte secret is required to authenticate remote wipe commands.")
            print("2. Copy this hex key immediately into an off-device password manager")
            print("   (e.g., 1Password, Bitwarden, KeePassXC) or secure mobile store.")
            print("3. DO NOT commit this key to version control or save in plain text.")
            print("4. Clear your terminal scrollback buffer after copying.")
            print("--------------------------------------------------------------------------------")
            print(f"MASTER_KEY_HEX: {hex_key}")
            print("================================================================================")
            return 0
        except Exception as e:
            print(f"❌ Failed to export key: {e}", file=sys.stderr)
            return 1

    try:
        key = load_hmac_key(key_hex=args.key_hex, key_path=args.key_path)
    except Exception as e:
        print(f"❌ Error loading HMAC signing key: {e}", file=sys.stderr)
        return 1

    command_dict = generate_signed_wipe_payload(key=key, reason=args.reason)
    command_json = json.dumps(command_dict, indent=2)

    print("================================================================================")
    print("🚨 SENTINEL CRYPTOGRAPHICALLY SIGNED EMERGENCY WIPE COMMAND")
    print("================================================================================")
    print(command_json)
    print("================================================================================")

    if args.send:
        if not args.to:
            print("❌ --to <email> is required when --send is specified.", file=sys.stderr)
            return 1

        print(f"📡 Dispatching signed command to {args.to}...")
        ok, status = send_email_command(
            command_dict=command_dict,
            to_addr=args.to,
            smtp_server=args.smtp_server,
            smtp_port=args.smtp_port,
            smtp_user=args.smtp_user,
            smtp_password=args.smtp_pass,
            creds_path=args.creds_path,
        )
        if ok:
            print(f"✅ {status}")
            return 0
        else:
            print(f"❌ {status}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
