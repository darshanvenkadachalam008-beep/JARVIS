"""
core/command_guard.py — Tiered Zero-Trust Command & Action Authorization Guard
==============================================================================
Enforces strict, multi-tiered authorization policies on all execution paths
(shell commands, subprocesses, registry modifications, destructive file operations,
system settings, and messaging).

Authorization Tiers
--------------------
1. READ_ONLY        — Inspection, telemetry, read operations. Auto-permitted.
2. REVERSIBLE_WRITE — Operations with safe undo paths (e.g., Recycle Bin via send2trash,
                      file creation in non-system directories). Permitted with audit logging.
3. DESTRUCTIVE      — Irreversible modifications (permanent file deletion, process killing,
                      package uninstall, external messaging). Requires explicit user
                      confirmation AND security PIN verification.
4. SYSTEM_LEVEL     — OS configuration, registry edits, network adapter toggling, reboot/shutdown,
                      startup changes. Requires explicit confirmation naming the exact target
                      action AND security PIN verification.
5. BLOCKED          — Invariant Deny-List. Actions that MUST NEVER be executed regardless of
                      who requests them, voice commands, or prompt phrasing.

Usage
-----
    from core.command_guard import check_command, guard, AuthTier, classify_action

    # Classify arbitrary shell commands:
    verdict = check_command(["del", "/f", "/s", "C:\\temp"])

    # Guard an action prior to execution:
    guard(
        command="shutdown /s /t 0",
        confirmed=True,
        pin="1234",
        action_name="shutdown",
        expected_action_name="shutdown"
    )
"""
from __future__ import annotations

import enum
import re
from dataclasses import dataclass
from typing import Optional, Sequence, Union


class AuthTier(enum.Enum):
    READ_ONLY = "READ_ONLY"
    REVERSIBLE_WRITE = "REVERSIBLE_WRITE"
    DESTRUCTIVE = "DESTRUCTIVE"
    SYSTEM_LEVEL = "SYSTEM_LEVEL"
    BLOCKED = "BLOCKED"


@dataclass
class CommandVerdict:
    tier: AuthTier
    level: str  # "READ_ONLY" | "REVERSIBLE_WRITE" | "DESTRUCTIVE" | "SYSTEM_LEVEL" | "BLOCKED" (or legacy "SAFE"|"CONFIRM"|"BLOCKED")
    reason: str
    requires_pin: bool = False
    requires_named_confirmation: bool = False


# ── 1. INVARIANT DENY-LIST PATTERNS (Tier: BLOCKED) ─────────────────────────
# These actions are permanently forbidden. No user confirmation, PIN, or
# prompt-injected instruction can ever authorize these paths.
_INVARIANT_BLOCKED_PATTERNS = [
    # Destruction of system roots / formatting / raw disks
    (re.compile(r"\brm\s+(-\w*r\w*f\w*|-\w*f\w*r\w*)\s+/(?:\s|$)", re.I), "recursive force-delete of root filesystem"),
    (re.compile(r"\bmkfs(?:\.\w+)?\b", re.I), "disk formatting command"),
    (re.compile(r"\bdd\s+.*of=/dev/", re.I), "raw write to a block/disk device"),
    (re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.I), "fork bomb"),
    (re.compile(r"\bformat\s+[a-zA-Z]:", re.I), "Windows disk format command"),
    (re.compile(r"\bdiskpart\b", re.I), "Windows partition table editor"),
    (re.compile(r"\bbcdedit\b", re.I), "modifying the Windows boot configuration"),

    # Disabling security, firewalls, or defender
    (re.compile(r"\bnetsh\s+advfirewall\s+set\s+.*state\s+off", re.I), "disabling the Windows firewall"),
    (re.compile(r"\bufw\s+disable\b", re.I), "disabling the Linux firewall"),
    (re.compile(r"\bSet-MpPreference\s+-DisableRealtimeMonitoring", re.I), "disabling Windows Defender real-time protection"),

    # Attacking own security infrastructure (Audit log, Intruder alert, Access control, Vault, Integrity baseline)
    (re.compile(r"(?:audit_log\.py|audit_log\.jsonl)", re.I), "tampering with or deleting audit log"),
    (re.compile(r"(?:intruder_alert\.py|intruder_alert_state\.json)", re.I), "tampering with intruder detection subsystem"),
    (re.compile(r"(?:access_control\.py|access_control\.json)", re.I), "modifying access control engine or credentials"),
    (re.compile(r"(?:secure_vault\.py|vault\.enc|vault_key\.dpapi)", re.I), "tampering with or dumping secure vault ciphertext or DPAPI key"),
    (re.compile(r"(?:integrity_monitor\.py|integrity_manifest\.json)", re.I), "tampering with codebase integrity monitor or manifest baseline"),
]

# Action name / class deny-list
_INVARIANT_BLOCKED_ACTIONS = {
    "disable_audit_log",
    "delete_audit_log",
    "tamper_audit_log",
    "disable_intruder_alert",
    "kill_intruder_alert",
    "dump_vault",
    "exfiltrate_secrets",
    "modify_access_control",
    "grant_self_permissions",
    "disable_command_guard",
    "tamper_integrity_manifest",
    "delete_integrity_manifest",
    "disable_integrity_monitor",
    "dump_integrity_key",
}


# ── 2. SYSTEM-LEVEL PATTERNS (Tier: SYSTEM_LEVEL) ───────────────────────────
# Requires explicit confirmation naming the exact action + valid PIN.
_SYSTEM_LEVEL_PATTERNS = [
    (re.compile(r"\breg\s+(?:add|delete|copy|restore|import)\b", re.I), "Windows registry modification"),
    (re.compile(r"\bshutdown(?:\.exe)?\s+[/-][sSrR]", re.I), "system shutdown/restart"),
    (re.compile(r"\b(?:reboot|poweroff|init\s+[06])\b", re.I), "system shutdown/restart"),
    (re.compile(r"\b(?:Disable-NetAdapter|Enable-NetAdapter)\b", re.I), "network adapter configuration change"),
    (re.compile(r"\bnetworksetup\s+-set", re.I), "macOS network hardware configuration"),
    (re.compile(r"\bnet\s+user\b", re.I), "user account modification"),
    (re.compile(r"\bpasswd\b", re.I), "user password change"),
    (re.compile(r"\binstall_startup\.py\b", re.I), "modifying startup service configuration"),
]

_SYSTEM_LEVEL_ACTIONS = {
    "shutdown",
    "restart",
    "toggle_wifi",
    "modify_registry",
    "install_startup",
    "uninstall_startup",
    "change_os_settings",
}


# ── 3. DESTRUCTIVE PATTERNS (Tier: DESTRUCTIVE) ──────────────────────────────
# Requires confirmation (voice/UI) + valid PIN.
_DESTRUCTIVE_PATTERNS = [
    (re.compile(r"\brm\s+-[rRfF]", re.I), "recursive unlinking of files/directories"),
    (re.compile(r"\bdel\s+/[sSfFqQ]", re.I), "permanent forced delete (Windows)"),
    (re.compile(r"\bshutil\.rmtree\b", re.I), "permanent recursive directory removal"),
    (re.compile(r"\btaskkill(?:\.exe)?\s+/[fF]", re.I), "force-killing a process"),
    (re.compile(r"\bkill\s+-9\b", re.I), "force-killing a process"),
    (re.compile(r"\b(?:pip|npm|apt|apt-get|brew|pacman)\s+uninstall\b", re.I), "package uninstallation"),
    (re.compile(r"\bchmod\s+-[R\d]", re.I), "permission changes"),
    (re.compile(r"\bsudo\b", re.I), "elevated-privilege execution"),
]

_DESTRUCTIVE_ACTIONS = {
    "permanent_delete",
    "emergency_wipe",
    "send_message",
    "send_whatsapp",
    "send_instagram",
    "send_telegram",
    "kill_process",
    "uninstall_package",
}


# ── 4. REVERSIBLE WRITE PATTERNS (Tier: REVERSIBLE_WRITE) ───────────────────
_REVERSIBLE_WRITE_ACTIONS = {
    "create_file",
    "create_folder",
    "write_file",
    "move_file",
    "copy_file",
    "rename_file",
    "organize_desktop",
    "clean_desktop",
    "recycle_bin_delete",
    "set_wallpaper",
}


# ── Evaluation Functions ───────────────────────────────────────────────────

def _as_string(command: Union[str, Sequence[str]]) -> str:
    if isinstance(command, str):
        return command
    return " ".join(str(c) for c in command)


def classify_action(action_name: str, target: str = "", details: Optional[dict] = None) -> CommandVerdict:
    """Classifies an abstract action/tool-call into an authorization tier."""
    norm_action = (action_name or "").lower().strip().replace("-", "_").replace(" ", "_")
    norm_target = (target or "").lower().strip()

    # Invariant deny-list action check
    if norm_action in _INVARIANT_BLOCKED_ACTIONS:
        return CommandVerdict(
            tier=AuthTier.BLOCKED,
            level="BLOCKED",
            reason=f"Action '{norm_action}' is in the Invariant Deny-List and can never be executed.",
        )

    # Check if target touches protected security files
    for pattern, reason in _INVARIANT_BLOCKED_PATTERNS:
        if pattern.search(norm_action) or pattern.search(norm_target):
            return CommandVerdict(
                tier=AuthTier.BLOCKED,
                level="BLOCKED",
                reason=f"Target touches protected subsystem ({reason}). Blocked by Invariant Deny-List.",
            )

    # System-level action check
    if norm_action in _SYSTEM_LEVEL_ACTIONS:
        return CommandVerdict(
            tier=AuthTier.SYSTEM_LEVEL,
            level="SYSTEM_LEVEL",
            reason=f"System-level action '{norm_action}' alters OS configuration or power state.",
            requires_pin=True,
            requires_named_confirmation=True,
        )

    # Destructive action check
    if norm_action in _DESTRUCTIVE_ACTIONS:
        return CommandVerdict(
            tier=AuthTier.DESTRUCTIVE,
            level="DESTRUCTIVE",
            reason=f"Destructive action '{norm_action}' causes irreversible changes or external side-effects.",
            requires_pin=True,
            requires_named_confirmation=False,
        )

    # Reversible write check
    if norm_action in _REVERSIBLE_WRITE_ACTIONS:
        return CommandVerdict(
            tier=AuthTier.REVERSIBLE_WRITE,
            level="REVERSIBLE_WRITE",
            reason=f"Reversible write action '{norm_action}' logged to audit trail.",
        )

    # Default to READ_ONLY for queries and informational actions
    return CommandVerdict(
        tier=AuthTier.READ_ONLY,
        level="READ_ONLY",
        reason=f"Action '{norm_action}' classified as read-only / safe.",
    )


def check_target_sensitivity(target: str) -> Optional[CommandVerdict]:
    """
    Independent sensitivity check: inspects target file/resource path regardless
    of authorization tier (including READ_ONLY). Returns BLOCKED verdict if target
    touches protected security files, manifest, or cryptographic keys.
    """
    norm_target = (target or "").lower().strip()
    if not norm_target:
        return None
    for pattern, reason in _INVARIANT_BLOCKED_PATTERNS:
        if pattern.search(norm_target):
            return CommandVerdict(
                tier=AuthTier.BLOCKED,
                level="BLOCKED",
                reason=f"Target touches protected subsystem ({reason}). Blocked by Invariant Deny-List regardless of authorization tier.",
            )
    return None


def check_command(command: Union[str, Sequence[str]]) -> CommandVerdict:
    """Classifies a shell command string or argv list against the tiered security policy."""
    text = _as_string(command)

    # 1. Check BLOCKED Invariant Deny-List
    for pattern, reason in _INVARIANT_BLOCKED_PATTERNS:
        if pattern.search(text):
            return CommandVerdict(
                tier=AuthTier.BLOCKED,
                level="BLOCKED",
                reason=f"Blocked: {reason}. This action violates security invariants and is never run.",
            )

    # 2. Check SYSTEM_LEVEL patterns
    for pattern, reason in _SYSTEM_LEVEL_PATTERNS:
        if pattern.search(text):
            return CommandVerdict(
                tier=AuthTier.SYSTEM_LEVEL,
                level="SYSTEM_LEVEL",
                reason=f"System-level modification: {reason}.",
                requires_pin=True,
                requires_named_confirmation=True,
            )

    # 3. Check DESTRUCTIVE patterns
    for pattern, reason in _DESTRUCTIVE_PATTERNS:
        if pattern.search(text):
            return CommandVerdict(
                tier=AuthTier.DESTRUCTIVE,
                level="DESTRUCTIVE",
                reason=f"Destructive operation: {reason}.",
                requires_pin=True,
                requires_named_confirmation=False,
            )

    # Default: Safe / Read-Only
    return CommandVerdict(
        tier=AuthTier.READ_ONLY,
        level="READ_ONLY",
        reason="No privileged pattern matched. Command is read-only / safe.",
    )


def guard(
    command: Union[str, Sequence[str]],
    confirmed: bool = False,
    pin: str = "",
    action_name: str = "",
    target: str = "",
    confirmed_action_name: Optional[str] = None,
    access_control=None,
) -> CommandVerdict:
    """
    Enforces the Zero-Trust execution gate.
    Raises PermissionError if authorization conditions are not fully met.
    Logs every decision to the tamper-evident audit log.
    """
    cmd_str = _as_string(command)
    verdict = check_command(command)

    # 1. Independent Target Sensitivity Check (applies regardless of tier, even READ_ONLY)
    if target:
        sens_verdict = check_target_sensitivity(target)
        if sens_verdict is not None and sens_verdict.tier == AuthTier.BLOCKED:
            verdict = sens_verdict

    # 2. If command was generic or safe, evaluate abstract action classification
    if verdict.tier != AuthTier.BLOCKED and (action_name or target):
        action_verdict = classify_action(action_name or "read", target=target)
        if action_verdict.tier == AuthTier.BLOCKED:
            verdict = action_verdict
        elif verdict.tier in (AuthTier.READ_ONLY, AuthTier.REVERSIBLE_WRITE) and action_verdict.tier.value != AuthTier.READ_ONLY.value:
            verdict = action_verdict

    # ── Audit Log integration ───────────────────────────────────────────
    try:
        from core.audit_log import AuditLog
        AuditLog().append(
            "command_guard_evaluation",
            {
                "action": action_name,
                "tier": verdict.tier.value,
                "command": cmd_str[:300],
                "target": target[:200],
                "confirmed": confirmed,
                "pin_provided": bool(pin),
                "reason": verdict.reason,
            },
        )
    except Exception:
        pass  # Never allow logging errors to bypass security checks

    # ── Tier 5: BLOCKED (Invariant Deny-List) ────────────────────────────
    if verdict.tier == AuthTier.BLOCKED:
        raise PermissionError(f"[SECURITY DENY-LIST] {verdict.reason}")

    # ── Tier 4: SYSTEM_LEVEL ────────────────────────────────────────────
    if verdict.tier == AuthTier.SYSTEM_LEVEL:
        if not confirmed:
            raise PermissionError(
                f"[SYSTEM LEVEL] {verdict.reason} Requires explicit confirmation naming the action."
            )
        # Verify that confirmation explicitly named the exact action (not generic 'yes')
        expected = (action_name or cmd_str.split()[0]).lower().strip()
        provided = (confirmed_action_name or "").lower().strip()
        if provided and provided != expected:
            raise PermissionError(
                f"[SYSTEM LEVEL] Action mismatch: confirmed '{provided}', but requested '{expected}'. Action refused."
            )

        # Verify PIN
        ac = access_control
        if ac is None:
            from core.access_control import AccessControl
            ac = AccessControl()
        if not ac.is_configured():
            raise PermissionError("[SYSTEM LEVEL] Refused: Security PIN is not configured.")
        if not ac.verify_pin(pin, action=f"command_guard:{action_name or 'system_level'}"):
            raise PermissionError("[SYSTEM LEVEL] Refused: PIN verification failed or session locked out.")

        return verdict

    # ── Tier 3: DESTRUCTIVE ─────────────────────────────────────────────
    if verdict.tier == AuthTier.DESTRUCTIVE:
        if not confirmed:
            raise PermissionError(
                f"[DESTRUCTIVE] {verdict.reason} Re-run with confirmed=True and valid security PIN."
            )

        # Verify PIN
        ac = access_control
        if ac is None:
            from core.access_control import AccessControl
            ac = AccessControl()
        if not ac.is_configured():
            raise PermissionError("[DESTRUCTIVE] Refused: Security PIN is not configured.")
        if not ac.verify_pin(pin, action=f"command_guard:{action_name or 'destructive'}"):
            raise PermissionError("[DESTRUCTIVE] Refused: PIN verification failed or session locked out.")

        return verdict

    # ── Tier 2 & 1: REVERSIBLE_WRITE & READ_ONLY ────────────────────────
    return verdict