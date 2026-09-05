"""
generate_pairing_qr.py — JARVIS Mobile Companion QR Pairing Generator
======================================================================
Generates and displays a pairing QR code encoding:
- Local LAN IP
- WebSocket port (8081)
- HTTP port (8080)
- mobile_auth_token (from config/api_keys.json)

Renders both an ASCII QR code in the terminal and saves pairing_qr.png.
"""

from __future__ import annotations

import json
import os
import socket
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
API_KEYS_PATH = BASE_DIR / "config" / "api_keys.json"
QR_OUTPUT_PATH = BASE_DIR / "pairing_qr.png"

def get_lan_ip() -> str:
    """Discovers the active LAN IP of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def load_auth_token() -> str:
    """Loads or creates mobile_auth_token in config/api_keys.json."""
    from mobile_server import _load_or_create_mobile_token
    return _load_or_create_mobile_token()

def generate_pairing_payload(lan_ip: str | None = None) -> dict:
    ip = lan_ip or get_lan_ip()
    token = load_auth_token()
    return {
        "ip": ip,
        "port": 8081,
        "http_port": 8080,
        "token": token,
    }

def render_qr(payload: dict, save_image: bool = True) -> str:
    import qrcode

    raw_json = json.dumps(payload)
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=2,
    )
    qr.add_data(raw_json)
    qr.make(fit=True)

    print("\n" + "=" * 60)
    print("      J.A.R.V.I.S  COMPANION  PAIRING  QR  CODE")
    print("=" * 60)
    print(f"  PC LAN IP   : {payload['ip']}")
    print(f"  WS Port     : {payload['port']}")
    print(f"  HTTP Port   : {payload['http_port']}")
    print(f"  Auth Token  : {payload['token'][:6]}...{payload['token'][-4:]}")
    print("=" * 60 + "\n")

    try:
        if sys.stdout.encoding.lower() != "utf-8":
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        qr.print_ascii(invert=True)
    except Exception:
        # Fallback ascii printing
        matrix = qr.get_matrix()
        for row in matrix:
            print("".join("██" if cell else "  " for cell in row))

    if save_image:
        try:
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(str(QR_OUTPUT_PATH))
            print(f"\n[QR] Saved image to: {QR_OUTPUT_PATH}")
        except Exception as e:
            print(f"[QR] Failed to save image: {e}")

    return raw_json

if __name__ == "__main__":
    payload = generate_pairing_payload()
    render_qr(payload)
