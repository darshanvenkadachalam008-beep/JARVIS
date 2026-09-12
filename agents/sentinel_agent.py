"""
SentinelAgent — Autonomous Cybersecurity Defense Agent for JARVIS.
Subclasses BaseAgent and implements a fail-secure defense state machine:
NORMAL → ELEVATED → DEFENSE → LOCKDOWN.
Tamper-evident audit logging for all transitions via sentinel.audit.chain.AuditLogger.
De-escalation strictly requires explicit AuthEngine authentication.
"""
from __future__ import annotations

import logging
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, Any, Callable

from agents.base_agent import BaseAgent
from sentinel.defense.actions import (
    lock_session,
    revoke_active_tokens,
    capture_evidence,
    network_isolate,
    alert_owner,
)

logger = logging.getLogger(__name__)


class SentinelState(str, Enum):
    NORMAL = "NORMAL"
    ELEVATED = "ELEVATED"
    DEFENSE = "DEFENSE"
    LOCKDOWN = "LOCKDOWN"


class SentinelAgent(BaseAgent):
    """
    Autonomous cybersecurity defense agent.
    Driven by AnomalyDetector event_sink callbacks and security state checks.
    """

    def __init__(
        self,
        auth_engine: Any = None,
        audit_logger: Any = None,
        anomaly_detector: Any = None,
        mobile_hub: Any = None,
    ):
        super().__init__(name="Sentinel")
        self.defense_state: SentinelState = SentinelState.NORMAL
        self.mobile_hub = mobile_hub
        self._auth_engine = auth_engine
        self._audit_logger = audit_logger
        self._anomaly_detector = anomaly_detector

        # Lazily initialize dependencies if not provided via singletons
        if self._auth_engine is None:
            try:
                from sentinel.auth.engine import AuthEngine
                self._auth_engine = AuthEngine.get_instance(event_sink=self.on_event)
            except Exception as e:
                logger.warning(f"[SentinelAgent] Could not initialize AuthEngine: {e}")

        if self._audit_logger is None:
            try:
                from sentinel.audit.chain import AuditLogger
                self._audit_logger = AuditLogger.get_instance()
            except Exception as e:
                logger.warning(f"[SentinelAgent] Could not initialize AuditLogger: {e}")

        if self._anomaly_detector is None and self._auth_engine is not None:
            self._anomaly_detector = getattr(self._auth_engine, "anomaly_detector", None)

        # Wire event sink hook
        if self._anomaly_detector is not None:
            self._anomaly_detector.event_sink = self.on_event

        logger.info(f"[SentinelAgent] Initialized in {self.defense_state.value} state")

    @property
    def auth_engine(self) -> Any:
        return self._auth_engine

    @property
    def audit_logger(self) -> Any:
        return self._audit_logger

    # ── State Machine & Invariant-Enforced Actions ──────────────────────────

    def on_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """
        Receives detection callbacks from AnomalyDetector or AuthEngine.
        Drives state machine transitions based on threat severity and clustering.
        """
        logger.info(f"[SentinelAgent] 🔔 Received event '{event_type}': {details}")

        # 1. Medium severity: Friction elevated
        if event_type == "auth_anomaly_friction_elevated":
            if self.defense_state == SentinelState.NORMAL:
                reasons = details.get("reasons", ["Friction elevated"])
                self.transition_to(
                    SentinelState.ELEVATED,
                    reason=f"Friction elevated (score={details.get('score', 1.0)}): {reasons}",
                )

        # 2. High severity clusters: Face failure or watchdog restart cluster
        elif event_type in ("face_failure_cluster_detected", "watchdog_restart_cluster_detected"):
            cluster_count = details.get("cluster_count", 3)
            window_s = details.get("window_secs", 180.0)
            reason = f"{event_type} ({cluster_count} events in {window_s}s)"

            if self.defense_state in (SentinelState.NORMAL, SentinelState.ELEVATED):
                self.transition_to(SentinelState.DEFENSE, reason=reason)
            elif self.defense_state == SentinelState.DEFENSE:
                self.transition_to(SentinelState.LOCKDOWN, reason=f"Persistent attack: {reason}")

        # 3. Critical severity: Audit chain or mirror tampering
        elif event_type in ("audit_chain_tamper_detected", "audit_mirror_state_tampered"):
            reason = f"Audit chain integrity compromise: {details.get('error', 'tampering detected')}"
            if self.defense_state != SentinelState.LOCKDOWN:
                # Direct transition to DEFENSE or LOCKDOWN
                next_st = SentinelState.LOCKDOWN if self.defense_state == SentinelState.DEFENSE else SentinelState.DEFENSE
                self.transition_to(next_st, reason=reason)

        # 4. Critical severity: Emergency wipe authorization failure or repeated lockout
        elif event_type in ("lockout_account_locked", "hard_lockout_entered"):
            if self.defense_state in (SentinelState.NORMAL, SentinelState.ELEVATED):
                self.transition_to(SentinelState.DEFENSE, reason=f"Account lockout triggered: {event_type}")

    def transition_to(self, new_state: SentinelState, reason: str = "") -> bool:
        """
        Escalates the defense state machine and triggers invariant-ordered actions.
        Downwards transitions must use deescalate(pin) — never automatic.
        """
        if new_state == self.defense_state:
            return True

        # Enforce escalation hierarchy: NORMAL -> ELEVATED -> DEFENSE -> LOCKDOWN
        valid_escalations = {
            SentinelState.NORMAL: [SentinelState.ELEVATED, SentinelState.DEFENSE, SentinelState.LOCKDOWN],
            SentinelState.ELEVATED: [SentinelState.DEFENSE, SentinelState.LOCKDOWN],
            SentinelState.DEFENSE: [SentinelState.LOCKDOWN],
            SentinelState.LOCKDOWN: [],
        }
        if new_state not in valid_escalations.get(self.defense_state, []):
            logger.warning(
                f"[SentinelAgent] ⛔ Direct de-escalation from {self.defense_state.value} to {new_state.value} "
                "is forbidden. Use deescalate() with valid credentials."
            )
            return False

        prev_state = self.defense_state
        logger.critical(f"[SentinelAgent] 🚨 ESCALATING: {prev_state.value} ➔ {new_state.value} | Reason: {reason}")

        # ── Strict Ordering Invariant Pipeline ──
        if new_state == SentinelState.ELEVATED:
            # Observability & friction elevation
            self._log_audit(
                "sentinel_state_transition",
                details={"from_state": prev_state.value, "to_state": new_state.value, "reason": reason},
            )
            self.defense_state = SentinelState.ELEVATED
            self._log(f"[Sentinel] State is now ELEVATED. Reason: {reason}")
            return True

        elif new_state == SentinelState.DEFENSE:
            action_failures = []

            # 1. Capture evidence locally (ZERO network dependencies)
            evidence_path = None
            try:
                evidence_path = capture_evidence(context_summary=f"DEFENSE mode entered: {reason}")
            except Exception as e:
                logger.error(f"[SentinelAgent] Action 'capture_evidence' failed during DEFENSE transition: {e}")
                action_failures.append("capture_evidence")
                self._log_audit(
                    "sentinel_action_failed",
                    details={"action": "capture_evidence", "error": str(e), "target_state": new_state.value},
                )

            # 2. Alert owner via network while connectivity is still alive
            try:
                alert_owner(f"Sentinel DEFENSE engaged: {reason}", evidence_path=evidence_path)
            except Exception as e:
                logger.error(f"[SentinelAgent] Action 'alert_owner' failed during DEFENSE transition: {e}")
                action_failures.append("alert_owner")
                self._log_audit(
                    "sentinel_action_failed",
                    details={"action": "alert_owner", "error": str(e), "target_state": new_state.value},
                )

            # 3. Lock operating system session
            try:
                lock_session()
            except Exception as e:
                logger.error(f"[SentinelAgent] Action 'lock_session' failed during DEFENSE transition: {e}")
                action_failures.append("lock_session")
                self._log_audit(
                    "sentinel_action_failed",
                    details={"action": "lock_session", "error": str(e), "target_state": new_state.value},
                )

            # 4. Log tamper-evident audit event & commit state transition
            ev_str = str(evidence_path) if evidence_path else None
            self._log_audit(
                "sentinel_defense_mode_entered",
                details={
                    "from_state": prev_state.value,
                    "to_state": new_state.value,
                    "reason": reason,
                    "evidence_path": ev_str,
                    "action_failures": action_failures,
                },
            )
            self.defense_state = SentinelState.DEFENSE
            ev_name = evidence_path.name if evidence_path else "none"
            self._log(f"[Sentinel] 🛡️ State is now DEFENSE. Session locked. Evidence: {ev_name}")
            return True

        elif new_state == SentinelState.LOCKDOWN:
            action_failures = []

            # 1. Capture evidence locally
            evidence_path = None
            try:
                evidence_path = capture_evidence(context_summary=f"LOCKDOWN mode entered: {reason}")
            except Exception as e:
                logger.error(f"[SentinelAgent] Action 'capture_evidence' failed during LOCKDOWN transition: {e}")
                action_failures.append("capture_evidence")
                self._log_audit(
                    "sentinel_action_failed",
                    details={"action": "capture_evidence", "error": str(e), "target_state": new_state.value},
                )

            # 2. Alert owner via network before potential isolation
            try:
                alert_owner(f"Sentinel LOCKDOWN engaged: {reason}", evidence_path=evidence_path)
            except Exception as e:
                logger.error(f"[SentinelAgent] Action 'alert_owner' failed during LOCKDOWN transition: {e}")
                action_failures.append("alert_owner")
                self._log_audit(
                    "sentinel_action_failed",
                    details={"action": "alert_owner", "error": str(e), "target_state": new_state.value},
                )

            # 3. Revoke all active tokens and sessions
            revoked_count = 0
            try:
                revoked_count = revoke_active_tokens(self._auth_engine, mobile_hub=self.mobile_hub)
            except Exception as e:
                logger.error(f"[SentinelAgent] Action 'revoke_active_tokens' failed during LOCKDOWN transition: {e}")
                action_failures.append("revoke_active_tokens")
                self._log_audit(
                    "sentinel_action_failed",
                    details={"action": "revoke_active_tokens", "error": str(e), "target_state": new_state.value},
                )

            # 4. Lock session
            try:
                lock_session()
            except Exception as e:
                logger.error(f"[SentinelAgent] Action 'lock_session' failed during LOCKDOWN transition: {e}")
                action_failures.append("lock_session")
                self._log_audit(
                    "sentinel_action_failed",
                    details={"action": "lock_session", "error": str(e), "target_state": new_state.value},
                )

            # 5. Apply network isolation (if enabled in settings)
            isolation_applied = False
            try:
                isolation_applied = network_isolate(reason=f"LOCKDOWN: {reason}")
            except Exception as e:
                logger.error(f"[SentinelAgent] Action 'network_isolate' failed during LOCKDOWN transition: {e}")
                action_failures.append("network_isolate")
                self._log_audit(
                    "sentinel_action_failed",
                    details={"action": "network_isolate", "error": str(e), "target_state": new_state.value},
                )

            # 6. Log tamper-evident audit event & commit state transition
            ev_str = str(evidence_path) if evidence_path else None
            self._log_audit(
                "sentinel_lockdown_entered",
                details={
                    "from_state": prev_state.value,
                    "to_state": new_state.value,
                    "reason": reason,
                    "revoked_tokens": revoked_count,
                    "network_isolated": isolation_applied,
                    "evidence_path": ev_str,
                    "action_failures": action_failures,
                },
            )
            self.defense_state = SentinelState.LOCKDOWN
            self._log(f"[Sentinel] ⛔ State is now LOCKDOWN. Tokens revoked: {revoked_count}. Isolated: {isolation_applied}")
            return True

        return False

    def deescalate(self, pin: str, recovery: bool = False) -> bool:
        """
        De-escalates the state machine strictly gated by AuthEngine verification:
        LOCKDOWN ➔ DEFENSE ➔ ELEVATED ➔ NORMAL.
        Never timer-based or automatic.
        """
        if self.defense_state == SentinelState.NORMAL:
            return True

        if self._auth_engine is None:
            logger.error("[SentinelAgent] Cannot de-escalate: AuthEngine unavailable.")
            return False

        # Authenticate via Primary PIN (or Recovery PIN if recovery=True)
        try:
            if recovery:
                authed = self._auth_engine.authenticate_recovery(pin)
            else:
                authed = self._auth_engine.authenticate_primary(pin)
        except Exception as e:
            logger.warning(f"[SentinelAgent] De-escalation authentication error: {e}")
            authed = False

        if not authed:
            self._log_audit(
                "sentinel_defense_deescalate_failed",
                actor="user",
                details={"current_state": self.defense_state.value, "recovery": recovery},
            )
            logger.warning(f"[SentinelAgent] ❌ De-escalation failed: unauthorized credentials.")
            return False

        # Step down by one level
        target_map = {
            SentinelState.LOCKDOWN: SentinelState.DEFENSE,
            SentinelState.DEFENSE: SentinelState.ELEVATED,
            SentinelState.ELEVATED: SentinelState.NORMAL,
        }
        prev_state = self.defense_state
        target_state = target_map.get(self.defense_state, SentinelState.NORMAL)
        self.defense_state = target_state

        self._log_audit(
            "sentinel_defense_deescalated",
            actor="user",
            details={"from_state": prev_state.value, "to_state": target_state.value, "recovery": recovery},
        )
        logger.info(f"[SentinelAgent] 🔓 De-escalated: {prev_state.value} ➔ {target_state.value}")
        self._log(f"[Sentinel] De-escalated to {target_state.value}")
        return True

    # ── Audit Logger Helper ──────────────────────────────────────────────────

    def _log_audit(self, event_type: str, details: Dict[str, Any], actor: str = "sentinel") -> None:
        if self._audit_logger is not None:
            try:
                self._audit_logger.log_event(event_type, actor=actor, details=details)
            except Exception as e:
                logger.error(f"[SentinelAgent] ⚠️ Audit logging failed: {e}")

    # ── BaseAgent Overrides ──────────────────────────────────────────────────

    def execute_task(self, task: str, **kwargs) -> str:
        """
        Executes defense commands or returns status telemetry.
        """
        self.status = "running"
        self.current_task = task
        self.update_progress(10.0, f"Processing defense command: {task[:40]}")

        lower = task.strip().lower()
        if "status" in lower or "health" in lower:
            chain_ok = True
            chain_err = None
            if self._audit_logger and hasattr(self._audit_logger, "verify_chain"):
                try:
                    chain_ok = self._audit_logger.verify_chain()
                except Exception as e:
                    chain_ok = False
                    chain_err = str(e)

            report = (
                f"[Sentinel Defense Status]\n"
                f"State: {self.defense_state.value}\n"
                f"Audit Chain Integrity: {'VERIFIED' if chain_ok else f'TAMPERED: {chain_err}'}\n"
                f"Auth Engine Initialized: {self._auth_engine.is_initialized() if self._auth_engine else 'N/A'}"
            )
            return self.report_result(report)

        elif "lock" in lower:
            success = lock_session()
            return self.report_result(f"OS session lock invoked: {'SUCCESS' if success else 'FAILED'}")

        elif "evidence" in lower:
            path = capture_evidence(context_summary="Manual evidence trigger")
            return self.report_result(f"Forensics evidence bundle captured: {path.name}")

        return self.report_result(f"Sentinel defense agent standing by in state {self.defense_state.value}.")
