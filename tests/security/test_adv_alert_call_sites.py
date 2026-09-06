"""
tests/security/test_adv_alert_call_sites.py
============================================
Static and dynamic liveness test for the complete set of 5 Unified Security Alert Triggers:
1. windows_lockscreen_failure
2. jarvis_pin_failure
3. jarvis_voice_auth_failure
4. duress_logon_success
5. mobile_step_up_failure

Asserts that every trigger exists in TRIGGER_TITLES, has an active call site in production code,
and dispatches properly through dispatch_security_alert.
"""

import ast
from pathlib import Path
from core.unified_security_alert import TRIGGER_TITLES, dispatch_security_alert

EXPECTED_TRIGGERS = {
    "windows_lockscreen_failure",
    "jarvis_pin_failure",
    "jarvis_voice_auth_failure",
    "duress_logon_success",
    "mobile_step_up_failure",
}


def test_trigger_enumeration_completeness():
    """Asserts TRIGGER_TITLES contains exactly the 5 registered security triggers."""
    registered = set(TRIGGER_TITLES.keys())
    assert registered == EXPECTED_TRIGGERS, f"Mismatch in registered triggers: {registered ^ EXPECTED_TRIGGERS}"


def test_trigger_call_sites_exist_in_codebase():
    """Statically verifies through AST inspection that all 5 triggers appear in production call sites."""
    root_dir = Path(__file__).resolve().parent.parent.parent
    core_dir = root_dir / "core"

    found_triggers = {t: [] for t in EXPECTED_TRIGGERS}

    for py_file in core_dir.glob("*.py"):
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    if node.value in EXPECTED_TRIGGERS:
                        found_triggers[node.value].append(py_file.name)
        except Exception:
            pass

    # Assert every expected trigger is referenced in core production files
    for trigger, files in found_triggers.items():
        assert len(files) > 0, f"Trigger '{trigger}' has no references in core/"
        # Ensure it is referenced outside unified_security_alert.py itself
        external_refs = [f for f in files if f != "unified_security_alert.py"]
        assert len(external_refs) > 0, f"Trigger '{trigger}' is dead code; only appears in unified_security_alert.py"


def test_duress_logon_success_dispatch():
    """Explicitly verifies dispatch of the highest-stakes duress_logon_success trigger."""
    event = dispatch_security_alert(
        trigger_type="duress_logon_success",
        actor="credential_provider_dll",
        details={"user": "TonyStark", "logon_type": "duress_pin"}
    )
    assert event["trigger_type"] == "duress_logon_success"
    assert event["actor"] == "credential_provider_dll"
    assert "SILENT DURESS LOGON ALERT" in event["details"]["trigger_type"] or event["details"]["trigger_type"] == "duress_logon_success"


def test_all_five_triggers_dispatch_successfully():
    """Verifies that all 5 triggers produce structured alert payloads without throwing."""
    for trigger in EXPECTED_TRIGGERS:
        event = dispatch_security_alert(
            trigger_type=trigger,
            actor="test_adversarial",
            details={"action": "test_verification"}
        )
        assert event["trigger_type"] == trigger
        assert event["actor"] == "test_adversarial"
        assert "time" in event
        assert "location" in event
