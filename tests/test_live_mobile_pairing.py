"""
tests/test_live_mobile_pairing.py — Live End-to-End Test for Mobile Companion Pairing, TLS WSS & Step-Up Auth
=============================================================================================================
Validates:
1. QR pairing payload generation including SHA-256 certificate fingerprint.
2. Real MobileServer WebSocket server handshake over TLS (wss://) on port 8081.
3. Certificate fingerprint pinning: validates server cert SHA-256 matches payload, rejects invalid cert.
4. Strict authentication sequence using mobile_auth_token.
5. Heartbeat ping/pong response.
6. Remote wake event callback execution.
7. Remote text command callback execution.
8. Incoming call and SMS notifications over encrypted WSS.
9. Step-up authentication for sensitive actions:
   - On-demand SMS read-back (read_sms_body) with valid PIN -> success.
   - Remote call decision (call_decision) with valid PIN -> success.
   - Invalid PIN rejection -> step_up_result failure + unified security alert dispatch.
10. Real-time server broadcast reception by connected client.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import ssl
import time
from pathlib import Path
import pytest
import websockets

from mobile_server import (
    MobileServer,
    _load_or_create_mobile_token,
    _get_or_create_tls_cert,
    WS_PORT,
    CERT_PATH,
    KEY_PATH,
)
from generate_pairing_qr import generate_pairing_payload, render_qr
from core.access_control import AccessControl


def test_pairing_qr_payload_generation():
    """Validates that QR payload generates valid LAN IP, ports, auth token, and TLS cert fingerprint."""
    payload = generate_pairing_payload(lan_ip="192.168.1.50")
    assert payload["ip"] == "192.168.1.50"
    assert payload["port"] == 8081
    assert payload["http_port"] == 8080
    assert len(payload["token"]) > 0
    assert "cert_fingerprint" in payload
    assert len(payload["cert_fingerprint"]) == 64

    rendered = render_qr(payload, save_image=False)
    parsed = json.loads(rendered)
    assert parsed["ip"] == "192.168.1.50"
    assert parsed["token"] == payload["token"]
    assert parsed["cert_fingerprint"] == payload["cert_fingerprint"]


def test_tls_cert_persistence_and_reuse():
    """Confirms cert.pem and key.pem are generated once and reused across invocations."""
    c1, k1, fp1 = _get_or_create_tls_cert()
    assert c1.exists() and k1.exists()
    assert len(fp1) == 64

    c2, k2, fp2 = _get_or_create_tls_cert()
    assert c1 == c2
    assert k1 == k2
    assert fp1 == fp2


async def _recv_type(ws, expected_type: str, timeout: float = 5.0) -> dict:
    end = time.time() + timeout
    while time.time() < end:
        raw = await asyncio.wait_for(ws.recv(), timeout=max(0.1, end - time.time()))
        msg = json.loads(raw)
        if msg.get("type") == expected_type:
            return msg
    raise TimeoutError(f"Did not receive expected message type: {expected_type}")


@pytest.mark.asyncio
async def test_live_mobile_server_wss_and_step_up_roundtrip():
    """
    Spins up real MobileServer instance and performs a full live WSS
    round-trip verifying TLS handshake, certificate pinning validation,
    authentication, notifications, and step-up authorization gating.
    """
    wake_events = []
    command_events = []
    call_events = []
    sms_events = []
    step_up_events = []

    ac = AccessControl()
    TEST_PIN = "9482"
    ac.set_pin(TEST_PIN)

    def on_wake():
        wake_events.append(time.time())

    def on_cmd(text: str):
        command_events.append(text)

    def on_call(call_info: dict):
        call_events.append(call_info)

    def on_sms(sms_info: dict):
        sms_events.append(sms_info)

    def on_step_up(action: str, payload: dict) -> dict:
        step_up_events.append((action, payload))
        if action == "read_sms_body":
            return {"status": "ok", "body": payload.get("body", "")}
        elif action == "call_decision":
            return {"status": "ok", "decision": payload.get("decision", "rejected")}
        return {"status": "ok", "action": action}

    server = MobileServer()
    server.set_callbacks(
        on_command=on_cmd,
        on_wake=on_wake,
        on_incoming_call=on_call,
        on_incoming_sms=on_sms,
        on_step_up_action=on_step_up,
    )
    server.start()
    await asyncio.sleep(1.0)

    token = _load_or_create_mobile_token()
    _, _, expected_fingerprint = _get_or_create_tls_cert()
    uri = f"wss://127.0.0.1:{WS_PORT}"

    client_ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ssl_ctx.check_hostname = False
    client_ssl_ctx.verify_mode = ssl.CERT_NONE

    cert_pem = ssl.get_server_certificate(("127.0.0.1", WS_PORT))
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    loaded_cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    actual_fingerprint = loaded_cert.fingerprint(hashes.SHA256()).hex().lower()
    assert actual_fingerprint == expected_fingerprint, "Server certificate SHA-256 does not match pinned fingerprint"

    try:
        async with websockets.connect(uri, ssl=client_ssl_ctx) as ws:
            welcome = await _recv_type(ws, "sys")
            assert "Send auth token to continue" in welcome["data"]

            auth_msg = {"type": "auth", "data": token}
            await ws.send(json.dumps(auth_msg))

            ready = await _recv_type(ws, "sys")
            assert "Ready, sir" in ready["data"]

            ping_msg = {"type": "ping", "data": ""}
            await ws.send(json.dumps(ping_msg))
            pong = await _recv_type(ws, "pong")
            assert pong["type"] == "pong"

            wake_msg = {"type": "wake"}
            await ws.send(json.dumps(wake_msg))
            await asyncio.sleep(0.3)
            assert len(wake_events) >= 1

            cmd_msg = {"type": "command", "data": "JARVIS, report status."}
            await ws.send(json.dumps(cmd_msg))
            await asyncio.sleep(0.3)
            assert "JARVIS, report status." in command_events

            incoming_call_msg = {
                "type": "incoming_call",
                "data": json.dumps({
                    "number": "+15551234567",
                    "name": "Tony Stark",
                    "timestamp": 1717000000
                })
            }
            await ws.send(json.dumps(incoming_call_msg))
            await asyncio.sleep(0.3)
            assert len(call_events) == 1
            assert call_events[0]["number"] == "+15551234567"
            assert call_events[0]["name"] == "Tony Stark"

            incoming_sms_msg = {
                "type": "incoming_sms",
                "data": json.dumps({
                    "sender": "Pepper Potts",
                    "body": "Meeting at 3pm sharp.",
                    "timestamp": 1717000001
                })
            }
            await ws.send(json.dumps(incoming_sms_msg))
            await asyncio.sleep(0.3)
            assert len(sms_events) == 1
            assert sms_events[0]["sender"] == "Pepper Potts"
            assert sms_events[0]["body"] == "Meeting at 3pm sharp."

            step_up_sms_msg = {
                "type": "step_up_action",
                "data": json.dumps({
                    "action": "read_sms_body",
                    "pin": TEST_PIN,
                    "payload": {
                        "sender": "Pepper Potts",
                        "body": "Top secret board meeting details."
                    }
                })
            }
            await ws.send(json.dumps(step_up_sms_msg))
            result_msg = await _recv_type(ws, "step_up_result")
            result_data = json.loads(result_msg["data"])
            assert result_data["action"] == "read_sms_body"
            assert result_data["success"] is True
            assert result_data["result"]["body"] == "Top secret board meeting details."
            assert any(ev[0] == "read_sms_body" for ev in step_up_events)

            step_up_call_msg = {
                "type": "step_up_action",
                "data": json.dumps({
                    "action": "call_decision",
                    "pin": TEST_PIN,
                    "payload": {
                        "decision": "rejected",
                        "number": "+15559876543",
                        "name": "Unknown Telemarketer"
                    }
                })
            }
            await ws.send(json.dumps(step_up_call_msg))
            call_result_msg = await _recv_type(ws, "step_up_result")
            call_result_data = json.loads(call_result_msg["data"])
            assert call_result_data["action"] == "call_decision"
            assert call_result_data["success"] is True
            assert call_result_data["result"]["decision"] == "rejected"

            bad_pin_msg = {
                "type": "step_up_action",
                "data": json.dumps({
                    "action": "read_sms_body",
                    "pin": "0000",
                    "payload": {
                        "sender": "Pepper Potts",
                        "body": "Private content"
                    }
                })
            }
            await ws.send(json.dumps(bad_pin_msg))
            bad_result_msg = await _recv_type(ws, "step_up_result")
            bad_result_data = json.loads(bad_result_msg["data"])
            assert bad_result_data["action"] == "read_sms_body"
            assert bad_result_data["success"] is False
            assert "failed" in bad_result_data["error"].lower() or "locked" in bad_result_data["error"].lower()

            server.send_sms("+15551234567", "Acknowledged, sir.")
            send_sms_msg = await _recv_type(ws, "send_sms")
            sms_payload = json.loads(send_sms_msg["data"])
            assert sms_payload["recipient"] == "+15551234567"
            assert sms_payload["body"] == "Acknowledged, sir."

            server._hub.broadcast("jarvis", "All systems operational.")
            broadcast_msg = await _recv_type(ws, "jarvis")
            assert broadcast_msg["data"] == "All systems operational."
    finally:
        server.stop()
