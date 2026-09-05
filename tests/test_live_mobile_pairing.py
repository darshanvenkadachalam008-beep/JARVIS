"""
tests/test_live_mobile_pairing.py — Live End-to-End Test for Mobile Companion Pairing & WebSocket Protocol
========================================================================================================
Validates:
1. QR pairing payload generation and format.
2. Real MobileServer WebSocket server handshake on port 8081.
3. Strict authentication sequence using mobile_auth_token.
4. Heartbeat ping/pong response.
5. Remote wake event callback execution.
6. Remote text command callback execution.
7. Real-time server broadcast reception by connected client.
"""

from __future__ import annotations

import asyncio
import json
import time
import pytest
import websockets

from mobile_server import MobileServer, _load_or_create_mobile_token, WS_PORT
from generate_pairing_qr import generate_pairing_payload, render_qr


def test_pairing_qr_payload_generation():
    """Validates that QR payload generates valid LAN IP, ports, and auth token."""
    payload = generate_pairing_payload(lan_ip="192.168.1.50")
    assert payload["ip"] == "192.168.1.50"
    assert payload["port"] == 8081
    assert payload["http_port"] == 8080
    assert len(payload["token"]) > 0

    rendered = render_qr(payload, save_image=False)
    parsed = json.loads(rendered)
    assert parsed["ip"] == "192.168.1.50"
    assert parsed["token"] == payload["token"]


async def _recv_type(ws, expected_type: str, timeout: float = 5.0) -> dict:
    end = time.time() + timeout
    while time.time() < end:
        raw = await asyncio.wait_for(ws.recv(), timeout=max(0.1, end - time.time()))
        msg = json.loads(raw)
        if msg.get("type") == expected_type:
            return msg
    raise TimeoutError(f"Did not receive expected message type: {expected_type}")


@pytest.mark.asyncio
async def test_live_mobile_server_websocket_roundtrip():
    """
    Spins up the real MobileServer instance and performs a full live WebSocket
    round-trip verifying handshake, authentication, ping, wake, and command execution.
    """
    wake_events = []
    command_events = []
    call_events = []
    sms_events = []

    def on_wake():
        wake_events.append(time.time())

    def on_cmd(text: str):
        command_events.append(text)

    def on_call(call_info: dict):
        call_events.append(call_info)

    def on_sms(sms_info: dict):
        sms_events.append(sms_info)

    # 1. Start real MobileServer background threads
    server = MobileServer()
    server.set_callbacks(
        on_command=on_cmd,
        on_wake=on_wake,
        on_incoming_call=on_call,
        on_incoming_sms=on_sms,
    )
    server.start()
    await asyncio.sleep(1.0) # Allow websockets.serve to bind 0.0.0.0:8081

    token = _load_or_create_mobile_token()
    uri = f"ws://127.0.0.1:{WS_PORT}"

    try:
        async with websockets.connect(uri) as ws:
            # Step 1: Expect Welcome Message
            welcome = await _recv_type(ws, "sys")
            assert "Send auth token to continue" in welcome["data"]

            # Step 2: Send Auth Token
            auth_msg = {"type": "auth", "data": token}
            await ws.send(json.dumps(auth_msg))

            # Step 3: Expect Auth Success
            ready = await _recv_type(ws, "sys")
            assert "Ready, sir" in ready["data"]

            # Step 4: Heartbeat Ping / Pong
            ping_msg = {"type": "ping", "data": ""}
            await ws.send(json.dumps(ping_msg))
            pong = await _recv_type(ws, "pong")
            assert pong["type"] == "pong"

            # Step 5: Remote Wake
            wake_msg = {"type": "wake"}
            await ws.send(json.dumps(wake_msg))
            await asyncio.sleep(0.3)
            assert len(wake_events) >= 1

            # Step 6: Remote Text Command
            cmd_msg = {"type": "command", "data": "JARVIS, report status."}
            await ws.send(json.dumps(cmd_msg))
            await asyncio.sleep(0.3)
            assert "JARVIS, report status." in command_events

            # Step 7: Incoming Call Dispatch
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

            # Step 8: Incoming SMS Dispatch
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

            # Step 9: Canned SMS Send Command from Server to Mobile Client
            server.send_sms("+15551234567", "Acknowledged, sir.")
            send_sms_msg = await _recv_type(ws, "send_sms")
            sms_payload = json.loads(send_sms_msg["data"])
            assert sms_payload["recipient"] == "+15551234567"
            assert sms_payload["body"] == "Acknowledged, sir."

            # Step 10: Broadcast from Server to Client
            server._hub.broadcast("jarvis", "All systems operational.")
            broadcast_msg = await _recv_type(ws, "jarvis")
            assert broadcast_msg["data"] == "All systems operational."
    finally:
        server.stop()
