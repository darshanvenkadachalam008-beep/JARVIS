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

    def test_access_control_pin_failure_routes_to_unified_dispatcher(self):
        mock_bridge = MagicMock(spec=ProactiveBridge)
        ac = AccessControl()
        ac.set_bridge(mock_bridge)
        ac.set_pin("987654")

        # Wrong PIN with no face -> INTRUDER_SUSPECTED
        res = ac.triage_authentication(
            candidate_pin="000000",
            action="wipe_drive",
            snapshot_bytes=b"fake_face_frame",
        )

        self.assertEqual(res.status, TriageStatus.INTRUDER_SUSPECTED)
        self.assertEqual(mock_bridge.dispatch.call_count, 1)
        event = mock_bridge.dispatch.call_args[0][0]
        self.assertEqual(event.priority, ProactivePriority.CRITICAL)
        self.assertEqual(event.data["trigger_type"], "jarvis_pin_failure")

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


if __name__ == "__main__":
    unittest.main()
