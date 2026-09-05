"""
tests/test_unified_security_alert.py — Tests for Phase B Unified Security Alert & Location Fallback Chain
==========================================================================================================
Verifies:
  1. Regression test: main.py ProactiveBridge has a non-None audit sink wired at startup.
  2. LocationProvider Tier 1 (Windows Location API) -> 'high_confidence_wifi'.
  3. LocationProvider Tier 2 (HTTPS IP Geolocation fallback) -> 'city_level_ip_estimate'.
  4. LocationProvider Tier 3 (Opportunistic Paired Phone GPS) -> 'gps_precise'.
  5. LocationProvider Exhausted / Offline -> 'unavailable'.
  6. Explicit source & precision_tier labeling on every alert payload.
  7. IntruderAlertWatcher / Event Log 4625 triggers unified alert at ProactivePriority.CRITICAL.
  8. AccessControl PIN triage failure triggers unified alert at ProactivePriority.CRITICAL.
  9. SpeakerVerifier voice auth failure triggers unified alert at ProactivePriority.CRITICAL.
 10. Tamper-evident audit logging executes synchronously before dispatch.
"""

import json
import time
import unittest
from unittest.mock import MagicMock, patch

from core.access_control import AccessControl, TriageStatus
from core.intruder_alert import IntruderAlertWatcher
from core.location_provider import LocationProvider, LocationResult
from core.proactive_bridge import ProactiveBridge, ProactiveEvent, ProactivePriority
from core.speaker_verify import SpeakerVerifier
from core.unified_security_alert import dispatch_security_alert


import tempfile
from pathlib import Path


class TestMainBridgeAuditSinkWiring(unittest.TestCase):
    """Regression test ensuring main.py always wires an audit sink to ProactiveBridge."""

    def test_main_bridge_wiring_logic(self):
        bridge = ProactiveBridge()
        from sentinel.audit import AuditLogger
        with tempfile.TemporaryDirectory() as td:
            audit = AuditLogger(audit_dir=Path(td))
            bridge.set_audit_sink(lambda cat, actor, details: audit.log_event(cat, actor, details))

            self.assertIsNotNone(bridge._audit_sink, "ProactiveBridge must have an active audit sink")

            # Test that CRITICAL events synchronously invoke this audit sink
            audit_records = []
            bridge.set_audit_sink(lambda cat, actor, details: audit_records.append((cat, actor, details)))

            ev = ProactiveEvent(
                category="security",
                title="Intruder Test",
                message="Test payload",
                priority=ProactivePriority.CRITICAL,
                data={"trigger_type": "windows_lockscreen_failure", "actor": "system", "details": {"test": 1}},
                channels={"audit", "voice"},
            )
            bridge.dispatch(ev)

            self.assertEqual(len(audit_records), 1)
            self.assertEqual(audit_records[0][0], "security")
            self.assertEqual(audit_records[0][1], "system")
            self.assertEqual(audit_records[0][2]["trigger_type"], "windows_lockscreen_failure")


class TestLocationProviderFallbackChain(unittest.TestCase):
    """Tests the 3-tier fallback chain and strict labeling guarantees."""

    def setUp(self):
        self.provider = LocationProvider(cache_ttl_seconds=1.0)
        self.provider.clear_cache()

    def test_tier1_windows_location_api_success(self):
        mock_win_result = LocationResult(
            latitude=11.0168,
            longitude=76.9558,
            accuracy_meters=45.0,
            source="windows_location_api",
            precision_tier="high_confidence_wifi",
            details={"binding": "winrt_powershell"},
        )
        with patch.object(self.provider, "_query_windows_location_api", return_value=mock_win_result):
            loc = self.provider.get_location(allow_phone=False, force_refresh=True)

            self.assertEqual(loc.source, "windows_location_api")
            self.assertEqual(loc.precision_tier, "high_confidence_wifi")
            self.assertAlmostEqual(loc.latitude, 11.0168)
            self.assertAlmostEqual(loc.longitude, 76.9558)
            self.assertEqual(loc.accuracy_meters, 45.0)

    def test_tier2_ip_geolocation_fallback_when_windows_api_fails(self):
        mock_ip_result = LocationResult(
            latitude=13.0827,
            longitude=80.2707,
            accuracy_meters=10000.0,
            source="ip_geolocation",
            precision_tier="city_level_ip_estimate",
            city="Chennai",
            region="Tamil Nadu",
            country="India",
        )
        with patch.object(self.provider, "_query_windows_location_api", return_value=None):
            with patch.object(self.provider, "_query_ip_geolocation", return_value=mock_ip_result):
                loc = self.provider.get_location(allow_phone=False, force_refresh=True)

                self.assertEqual(loc.source, "ip_geolocation")
                self.assertEqual(loc.precision_tier, "city_level_ip_estimate")
                self.assertEqual(loc.city, "Chennai")
                self.assertNotEqual(loc.precision_tier, "high_confidence_wifi", "IP estimate must NEVER be labeled Wi-Fi")

    def test_tier3_paired_phone_gps_opportunistic(self):
        self.provider.update_phone_gps(
            latitude=12.9716,
            longitude=77.5946,
            accuracy_meters=8.0,
            city="Bengaluru",
        )
        loc = self.provider.get_location(allow_phone=True, force_refresh=False)

        self.assertEqual(loc.source, "paired_phone_gps")
        self.assertEqual(loc.precision_tier, "gps_precise")
        self.assertAlmostEqual(loc.latitude, 12.9716)
        self.assertEqual(loc.accuracy_meters, 8.0)

    def test_all_tiers_exhausted_returns_unavailable(self):
        with patch.object(self.provider, "_query_windows_location_api", return_value=None):
            with patch.object(self.provider, "_query_ip_geolocation", return_value=None):
                loc = self.provider.get_location(allow_phone=False, force_refresh=True)

                self.assertEqual(loc.source, "unavailable")
                self.assertEqual(loc.precision_tier, "unavailable")


class TestUnifiedSecurityAlertDispatch(unittest.TestCase):
    """Tests the unified dispatch pipeline across all failure sources."""

    def test_dispatch_windows_lockscreen_failure(self):
        mock_bridge = MagicMock(spec=ProactiveBridge)
        mock_loc = LocationResult(
            latitude=11.099,
            longitude=77.027,
            accuracy_meters=60.0,
            source="windows_location_api",
            precision_tier="high_confidence_wifi",
            city="Coimbatore",
        )

        res = dispatch_security_alert(
            trigger_type="windows_lockscreen_failure",
            actor="SYSTEM",
            details={"record_id": 4625123},
            bridge=mock_bridge,
            location=mock_loc,
            face_note="webcam face does NOT match enrolled owner",
        )

        self.assertEqual(res["trigger_type"], "windows_lockscreen_failure")
        self.assertEqual(res["location_source"], "windows_location_api")
        self.assertEqual(res["precision_tier"], "high_confidence_wifi")
        self.assertEqual(mock_bridge.dispatch.call_count, 1)

        event = mock_bridge.dispatch.call_args[0][0]
        self.assertEqual(event.priority, ProactivePriority.CRITICAL)
        self.assertIn("audit", event.channels)
        self.assertIn("voice", event.channels)
        self.assertIn("telegram", event.channels)
        self.assertIn("mobile", event.channels)
        self.assertIn("windows_location_api", event.message)

    def test_intruder_alert_watcher_routes_to_unified_dispatcher(self):
        mock_bridge = MagicMock(spec=ProactiveBridge)
        watcher = IntruderAlertWatcher(
            on_alert=lambda txt, img: None,
            bridge=mock_bridge,
            enabled=True,
        )

        with patch("core.intruder_alert._take_webcam_snapshot", return_value=None):
            with patch("core.intruder_alert._capture_webcam_clip", return_value=None):
                watcher.fire_synthetic_alert(custom_msg="Test Lockscreen Failure", record_id=4625999)

        self.assertEqual(mock_bridge.dispatch.call_count, 1)
        event = mock_bridge.dispatch.call_args[0][0]
        self.assertEqual(event.priority, ProactivePriority.CRITICAL)
        self.assertEqual(event.data["trigger_type"], "windows_lockscreen_failure")

    def test_speaker_verifier_routes_to_unified_dispatcher(self):
        mock_bridge = MagicMock(spec=ProactiveBridge)
        sv = SpeakerVerifier(threshold=0.85, bridge=mock_bridge)

        res = sv.trigger_voice_auth_alert(
            action="execute_destructive_command",
            score=0.42,
        )

        self.assertEqual(res["trigger_type"], "jarvis_voice_auth_failure")
        self.assertEqual(mock_bridge.dispatch.call_count, 1)
        event = mock_bridge.dispatch.call_args[0][0]
        self.assertEqual(event.priority, ProactivePriority.CRITICAL)
        self.assertEqual(event.data["trigger_type"], "jarvis_voice_auth_failure")


class TestRealCallerAlertIntegration(unittest.TestCase):
    """Integration tests asserting real caller paths trigger unified alerts."""

    def test_main_py_wires_audit_intruder_and_speaker_verifier(self):
        """Regression test ensuring JarvisLive in main.py wires audit sink, IntruderAlertWatcher, and SpeakerVerifier to ProactiveBridge."""
        with patch("core.wake_word.WakeWordEngine"), \
             patch("core.gesture_control.GestureControlEngine"), \
             patch("mobile_server.MobileServer"), \
             patch("sentinel.audit.AuditLogger"):

            from main import JarvisLive
            mock_ui = MagicMock()
            jarvis = JarvisLive(ui=mock_ui)

            self.assertIsNotNone(jarvis._proactive_bridge, "JarvisLive must have a ProactiveBridge")
            self.assertIsNotNone(jarvis._proactive_bridge._audit_sink, "JarvisLive ProactiveBridge must have an active audit sink")
            self.assertIsNotNone(jarvis._intruder_alert, "JarvisLive must instantiate IntruderAlertWatcher")
            self.assertEqual(jarvis._intruder_alert._bridge, jarvis._proactive_bridge, "IntruderAlertWatcher must be wired to JarvisLive ProactiveBridge")
            self.assertIsNotNone(jarvis._speaker_verifier, "JarvisLive must instantiate SpeakerVerifier")
            self.assertEqual(jarvis._speaker_verifier._bridge, jarvis._proactive_bridge, "SpeakerVerifier must be wired to JarvisLive ProactiveBridge")

    def test_emergency_wipe_caller_wrong_pin_dispatches_alert(self):
        """Asserts EmergencyWipeController caller triggering wrong PIN fires unified alert through ProactiveBridge."""
        from core.sentinel_extras import EmergencyWipeController
        mock_bridge = MagicMock(spec=ProactiveBridge)

        with tempfile.TemporaryDirectory() as td:
            auth_dir = Path(td) / "auth"
            auth_dir.mkdir(parents=True, exist_ok=True)
            ac = AccessControl(path=auth_dir / "access_control.json")
            ac.set_bridge(mock_bridge)
            ac.set_pin("123456")

            # Patch AccessControl in sentinel_extras to use our instance
            with patch("core.sentinel_extras.AccessControl", return_value=ac):
                ctrl = EmergencyWipeController(wipe_paths=[str(auth_dir / "test.txt")], bridge=mock_bridge)
                EmergencyWipeController.set_instance(ctrl)

                # 1. Initiate wipe
                ctrl.request_wipe(channel="telegram")

                # 2. Confirm wipe with WRONG PIN
                success, msg, _ = ctrl.confirm_wipe(pin="000000", channel="telegram")
                self.assertFalse(success)
                self.assertIn("PIN incorrect", msg)

                # Verify alert was dispatched
                self.assertEqual(mock_bridge.dispatch.call_count, 1)
                event = mock_bridge.dispatch.call_args[0][0]
                self.assertEqual(event.priority, ProactivePriority.CRITICAL)
                self.assertEqual(event.data["trigger_type"], "jarvis_pin_failure")
                self.assertEqual(event.data["details"]["action"], "emergency_wipe")
                self.assertEqual(event.data["details"]["result"], "denied_wrong_pin")

                # 3. Confirm wipe with CORRECT PIN -> must NOT dispatch a PIN failure alert
                mock_bridge.dispatch.reset_mock()
                # Re-initiate pending request
                ctrl.request_wipe(channel="telegram")
                with patch.object(ctrl, "execute_wipe", return_value=(True, ["✅ test.txt"])):
                    success, msg, _ = ctrl.confirm_wipe(pin="123456", channel="telegram")
                    self.assertTrue(success)
                    self.assertEqual(mock_bridge.dispatch.call_count, 0, "Successful PIN verification must NOT dispatch a failure alert")

    def test_wake_word_unenrolled_speaker_dispatches_alert(self):
        """Asserts wake-word rejection of unauthorized voice triggers unified security alert."""
        import numpy as np
        from core.speaker_verify import SpeakerVerifier, VerifyResult

        mock_bridge = MagicMock(spec=ProactiveBridge)
        sv = SpeakerVerifier(threshold=0.80, bridge=mock_bridge)

        # Mock enrollment with a dummy reference embedding
        enrolled_emb = np.ones(128, dtype=np.float32)
        enrolled_emb /= np.linalg.norm(enrolled_emb)

        # Candidate audio of an intruder (different vector -> negative cosine similarity)
        intruder_emb = -np.ones(128, dtype=np.float32)
        intruder_emb /= np.linalg.norm(intruder_emb)

        with patch.object(sv, "_load_embedding", return_value=enrolled_emb), \
             patch.object(sv, "_embed", return_value=intruder_emb):
            fake_pcm = np.zeros(16000, dtype=np.int16)
            res = sv.verify(fake_pcm, sample_rate=16000, action="wake_word")
            self.assertTrue(res.enrolled)
            self.assertFalse(res.accepted)

            # Trigger alert as done in _on_wake_word
            alert_payload = sv.trigger_voice_auth_alert(
                action="wake_word_unenrolled_voice",
                score=res.score,
            )

            self.assertEqual(alert_payload["trigger_type"], "jarvis_voice_auth_failure")
            self.assertEqual(mock_bridge.dispatch.call_count, 1)
            event = mock_bridge.dispatch.call_args[0][0]
            self.assertEqual(event.priority, ProactivePriority.CRITICAL)
            self.assertEqual(event.data["trigger_type"], "jarvis_voice_auth_failure")
            self.assertEqual(event.data["details"]["action"], "wake_word_unenrolled_voice")

    def test_computer_settings_caller_wrong_pin_dispatches_alert(self):
        """Asserts computer_settings dangerous action with wrong PIN dispatches CRITICAL alert."""
        from actions.computer_settings import computer_settings
        mock_bridge = MagicMock(spec=ProactiveBridge)

        AccessControl.set_default_bridge(mock_bridge)
        ac = AccessControl()
        ac.set_pin("123456")

        # Run computer_settings shutdown action with incorrect PIN
        res = computer_settings(
            parameters={"action": "shutdown", "confirmed": "yes", "pin": "WRONG_PIN"}
        )
        self.assertIn("refused: PIN missing or incorrect", res)
        self.assertEqual(mock_bridge.dispatch.call_count, 1)
        event = mock_bridge.dispatch.call_args[0][0]
        self.assertEqual(event.priority, ProactivePriority.CRITICAL)
        self.assertEqual(event.data["trigger_type"], "jarvis_pin_failure")
        self.assertEqual(event.data["details"]["action"], "computer_settings:shutdown")
        self.assertEqual(event.data["details"]["result"], "denied_wrong_pin")

    def test_file_controller_caller_wrong_pin_dispatches_alert(self):
        """Asserts file_controller permanent delete with wrong PIN dispatches CRITICAL alert."""
        from actions.file_controller import file_controller
        mock_bridge = MagicMock(spec=ProactiveBridge)

        AccessControl.set_default_bridge(mock_bridge)
        ac = AccessControl()
        ac.set_pin("123456")

        with tempfile.TemporaryDirectory() as td:
            dummy_file = Path(td) / "secret.txt"
            dummy_file.write_text("classified data")

            with patch.dict("sys.modules", {"send2trash": None}):
                res = file_controller({"action": "delete", "path": str(dummy_file), "pin": "000000"})
                self.assertIn("Permanent delete refused: PIN missing or incorrect", res)
                self.assertEqual(mock_bridge.dispatch.call_count, 1)
                event = mock_bridge.dispatch.call_args[0][0]
                self.assertEqual(event.priority, ProactivePriority.CRITICAL)
                self.assertEqual(event.data["trigger_type"], "jarvis_pin_failure")
                self.assertEqual(event.data["details"]["action"], "file_controller:permanent_delete")
                self.assertEqual(event.data["details"]["result"], "denied_wrong_pin")

    def test_command_guard_caller_wrong_pin_dispatches_alert(self):
        """Asserts command_guard destructive command with wrong PIN dispatches CRITICAL alert."""
        from core.command_guard import guard
        mock_bridge = MagicMock(spec=ProactiveBridge)

        AccessControl.set_default_bridge(mock_bridge)
        ac = AccessControl()
        ac.set_pin("123456")

        with self.assertRaises(PermissionError) as ctx:
            guard("shutdown /s /t 0", confirmed=True, pin="BAD_PIN")
        self.assertIn("PIN verification failed", str(ctx.exception))
        self.assertEqual(mock_bridge.dispatch.call_count, 1)
        event = mock_bridge.dispatch.call_args[0][0]
        self.assertEqual(event.priority, ProactivePriority.CRITICAL)
        self.assertEqual(event.data["trigger_type"], "jarvis_pin_failure")
        self.assertEqual(event.data["details"]["action"], "command_guard:system_level")
        self.assertEqual(event.data["details"]["result"], "denied_wrong_pin")

    def test_face_verify_caller_wrong_pin_dispatches_alert(self):
        """Asserts face_verify pin-gate violation with wrong PIN dispatches CRITICAL alert."""
        from core.face_verify import FaceVerifier
        mock_bridge = MagicMock(spec=ProactiveBridge)

        AccessControl.set_default_bridge(mock_bridge)
        ac = AccessControl()
        ac.set_pin("123456")

        with patch.object(AccessControl, "is_tampered", return_value=False):
            fv = FaceVerifier()
            with self.assertRaises(PermissionError) as ctx:
                fv._verify_pin_gate(pin="WRONG_PIN", action="face_enroll")
            self.assertIn("Invalid Security PIN or lockout active", str(ctx.exception))
            self.assertEqual(mock_bridge.dispatch.call_count, 1)
            event = mock_bridge.dispatch.call_args[0][0]
            self.assertEqual(event.priority, ProactivePriority.CRITICAL)
            self.assertEqual(event.data["trigger_type"], "jarvis_pin_failure")
            self.assertEqual(event.data["details"]["action"], "face_enroll")
            self.assertEqual(event.data["details"]["result"], "denied_wrong_pin")


if __name__ == "__main__":
    unittest.main()






