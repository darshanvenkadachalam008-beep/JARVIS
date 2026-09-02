"""
core/email_wipe_listener.py — Secondary Out-of-Band Remote Emergency Wipe Trigger via Signed Email
===================================================================================================
Polls a dedicated, isolated email inbox over IMAP (SSL/TLS) for cryptographically signed
emergency wipe commands.

Security Properties:
1. Command Authentication: Requires HMAC-SHA256 signature using a pre-shared secret key
   stored encrypted at rest with Windows DPAPI and owner-only DACL. Email headers (From, Subject)
   are never trusted in isolation.
2. Replay & Freshness Protection: Bounded timestamp freshness window (default: 5 min / 300s)
   plus dual-anchored nonce tracking (local JSON + cryptographically verified audit chain)
   to defeat local nonce deletion replay attacks.
3. Protected Credential Storage: Mailbox credentials (IMAP user and password) are encrypted
   at rest using Windows DPAPI (CryptProtectData) with owner-only DACL protection.
4. Fail-Closed / Safe No-Op on Errors: Network timeouts, socket failures, and authentication errors
   safely no-op (no false triggers, no daemon crashes).
5. Unified Wipe Mechanism: Routes authorized execution directly through EmergencyWipeController.
"""
from __future__ import annotations

import email
import hashlib
import hmac
import imaplib
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Optional, Dict, Any, Set, Tuple, List

from core.sentinel_extras import EmergencyWipeController
from sentinel.security_utils import apply_owner_only_dacl
from core.watchdog_auth import _protect_key_bytes, _unprotect_key_bytes

logger = logging.getLogger(__name__)

NONCE_STORE_DEFAULT = Path(__file__).resolve().parent.parent / "memory" / ".email_wipe_nonces.json"
WIPE_KEY_DEFAULT = Path(__file__).resolve().parent.parent / "memory" / ".email_wipe_auth.key"
WIPE_CREDS_DEFAULT = Path(__file__).resolve().parent.parent / "memory" / ".email_wipe_creds.dpapi"
DEFAULT_FRESHNESS_WINDOW_SECS = 300.0  # 5 minutes


def save_email_wipe_credentials(
    user: str,
    password: str,
    creds_path: Optional[Path] = None,
) -> Path:
    """
    Encrypts and saves IMAP mailbox credentials at rest using Windows DPAPI
    and owner-only DACL.
    """
    if creds_path is None:
        creds_path = WIPE_CREDS_DEFAULT

    creds_path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"imap_user": user, "imap_password": password}).encode("utf-8")
    protected = _protect_key_bytes(payload)

    temp_file = creds_path.with_suffix(f".tmp.{os.getpid()}")
    temp_file.write_bytes(protected)
    temp_file.replace(creds_path)
    apply_owner_only_dacl(creds_path)
    return creds_path


def load_email_wipe_credentials(
    creds_path: Optional[Path] = None,
) -> Tuple[str, str]:
    """
    Loads and decrypts IMAP mailbox credentials from DPAPI-protected storage,
    falling back to environment variables if unconfigured.
    """
    if creds_path is None:
        creds_path = WIPE_CREDS_DEFAULT

    if creds_path.exists():
        try:
            raw_bytes = creds_path.read_bytes()
            if raw_bytes:
                decrypted = _unprotect_key_bytes(raw_bytes)
                data = json.loads(decrypted.decode("utf-8"))
                return data.get("imap_user", ""), data.get("imap_password", "")
        except Exception as e:
            logger.warning("Could not decrypt email wipe credentials (%s); falling back to env.", e)

    return (
        os.environ.get("SENTINEL_EMAIL_WIPE_USER", ""),
        os.environ.get("SENTINEL_EMAIL_WIPE_PASSWORD", ""),
    )


class EmailWipeListener:
    """
    Monitors an IMAP inbox and triggers EmergencyWipeController upon receiving
    a verified, cryptographically signed wipe command.
    """

    def __init__(
        self,
        imap_server: str = "imap.gmail.com",
        imap_port: int = 993,
        imap_user: Optional[str] = None,
        imap_password: Optional[str] = None,
        creds_path: Optional[Path] = None,
        hmac_key: Optional[bytes] = None,
        key_path: Optional[Path] = None,
        wipe_controller: Optional[EmergencyWipeController] = None,
        nonce_store_path: Optional[Path] = None,
        audit_dir: Optional[Path] = None,
        freshness_window_secs: float = DEFAULT_FRESHNESS_WINDOW_SECS,
    ):
        self.imap_server = imap_server
        self.imap_port = imap_port
        self.freshness_window = freshness_window_secs
        self.key_path = key_path or WIPE_KEY_DEFAULT
        self.creds_path = creds_path or WIPE_CREDS_DEFAULT
        self.nonce_store_path = nonce_store_path or NONCE_STORE_DEFAULT
        self.audit_dir = audit_dir
        self._controller = wipe_controller or EmergencyWipeController.get_instance()
        self._lock = threading.Lock()

        # Precedence rule:
        # 1. Explicit imap_user + imap_password take top precedence.
        # 2. Else load from specified creds_path if provided.
        # 3. Else load from default WIPE_CREDS_DEFAULT (with env var fallback).
        if imap_user is not None and imap_password is not None:
            self.imap_user = imap_user
            self.imap_password = imap_password
        elif creds_path is not None:
            self.imap_user, self.imap_password = load_email_wipe_credentials(creds_path)
        else:
            self.imap_user, self.imap_password = load_email_wipe_credentials(self.creds_path)

        try:
            self._seen_nonces: Set[str] = self._load_nonces()
        except Exception as e:
            logger.warning("Could not pre-load nonces on init (%s); starting fresh.", e)
            self._seen_nonces = set()

        if hmac_key:
            self._key = hmac_key
        else:
            self._key = self._get_or_create_hmac_key(self.key_path)

    @staticmethod
    def _get_or_create_hmac_key(key_path: Path) -> bytes:
        """Retrieves or generates a 32-byte HMAC key protected by DPAPI and owner-only DACL."""
        key_path.parent.mkdir(parents=True, exist_ok=True)
        if key_path.exists():
            try:
                raw_bytes = key_path.read_bytes()
                if raw_bytes:
                    unprotected = _unprotect_key_bytes(raw_bytes)
                    if len(unprotected) == 32:
                        return unprotected
            except Exception as e:
                logger.warning("Could not read email wipe key (%s); generating new key.", e)

        new_key = os.urandom(32)
        protected_bytes = _protect_key_bytes(new_key)
        temp_file = key_path.with_suffix(f".tmp.{os.getpid()}")
        temp_file.write_bytes(protected_bytes)
        temp_file.replace(key_path)
        apply_owner_only_dacl(key_path)
        return new_key

    def _load_nonces(self) -> Set[str]:
        """
        Loads seen nonces from local JSON store AND cross-checks the hardened audit log/chain
        to prevent replay attacks if .email_wipe_nonces.json was deleted by an attacker.
        Cryptographically verifies the audit chain (verify_chain) before trusting its contents.
        """
        nonces: Set[str] = set()

        # 1. Read from local store if present
        if self.nonce_store_path.exists():
            try:
                data = json.loads(self.nonce_store_path.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    nonces.update(data)
            except Exception as e:
                logger.warning("Could not parse local nonce store (%s).", e)

        # 2. Cryptographically verified production Sentinel Audit chain cross-check
        try:
            from sentinel.audit.chain import AuditLogger, ChainIntegrityError
            prod_dir = self.audit_dir
            if prod_dir is None:
                from sentinel.config.settings import default_settings
                prod_dir = default_settings.audit_dir

            audit_file = prod_dir / "audit.jsonl"
            if audit_file.exists() and audit_file.stat().st_size > 0:
                keys = AuditLogger.load_hmac_keys_from_dir(prod_dir)
                if not keys:
                    # Existing audit file with missing/erased keys is a tamper condition (applies to explicit and default audit_dir)
                    logger.critical("AUDIT CHAIN INTEGRITY BREACH: Missing HMAC keys for existing audit log in %s.", prod_dir)
                    raise ChainIntegrityError(f"Missing audit HMAC keys for existing audit log in {prod_dir}")

                is_valid, count, err = AuditLogger.verify_chain(audit_file, keys)
                if not is_valid:
                    logger.critical("AUDIT CHAIN INTEGRITY BREACH: Corrupted audit log during email nonce load: %s", err)
                    raise ChainIntegrityError(f"Audit log chain integrity failure: {err}")

                for line in audit_file.read_text(encoding="utf-8").strip().splitlines():
                    if not line.strip():
                        continue
                    entry = json.loads(line)
                    ev = entry.get("event_type") or entry.get("event")
                    if ev == "email_wipe_command_executed":
                        details = entry.get("details", {})
                        n = details.get("nonce")
                        if n:
                            nonces.add(str(n))
        except (ChainIntegrityError, PermissionError, json.JSONDecodeError, TypeError, OSError) as e:
            logger.critical("Failed to safely reconstruct nonces from audit chain: %s", e)
            if isinstance(e, ChainIntegrityError) or "ChainIntegrityError" in type(e).__name__:
                raise
            raise ChainIntegrityError(f"Audit log read/decode failure during nonce reconstruction: {e}") from e
        except Exception as e:
            logger.error("Unexpected error during audit nonce loading: %s", e)
            raise ChainIntegrityError(f"Unexpected error loading audit nonces: {e}") from e

        # 3. Cross-check local legacy audit log if present
        try:
            log_path = (self.audit_dir / "audit_log.jsonl") if self.audit_dir else (Path(__file__).resolve().parent.parent / "memory" / "audit_log.jsonl")
            if log_path.exists() and log_path.stat().st_size > 0:
                for line in log_path.read_text(encoding="utf-8").strip().splitlines():
                    try:
                        entry = json.loads(line)
                        if entry.get("event_type") == "email_wipe_command_executed":
                            details = entry.get("details", {})
                            n = details.get("nonce")
                            if n:
                                nonces.add(str(n))
                    except Exception:
                        continue
        except Exception:
            pass

        return nonces

    def _save_nonces(self) -> None:
        """Saves seen nonces atomically with owner-only DACL."""
        try:
            self.nonce_store_path.parent.mkdir(parents=True, exist_ok=True)
            temp_file = self.nonce_store_path.with_suffix(f".tmp.{os.getpid()}")
            temp_file.write_text(json.dumps(list(self._seen_nonces)), encoding="utf-8")
            temp_file.replace(self.nonce_store_path)
            apply_owner_only_dacl(self.nonce_store_path)
        except Exception as e:
            logger.warning("Could not save email wipe nonces: %s", e)

    @staticmethod
    def compute_signature(key: bytes, payload_dict: Dict[str, Any]) -> str:
        """Computes deterministic HMAC-SHA256 over canonical JSON string of payload."""
        canonical = json.dumps(payload_dict, sort_keys=True).encode("utf-8")
        return hmac.new(key, canonical, hashlib.sha256).hexdigest()

    def process_email_payload(self, raw_input: str | dict) -> Tuple[bool, str]:
        """
        Validates structure, HMAC signature, timestamp freshness, and nonce uniqueness.
        If all pass, triggers EmergencyWipeController.execute_wipe(channel='signed_email').
        """
        if isinstance(raw_input, str):
            try:
                data = json.loads(raw_input)
            except Exception:
                logger.critical("Invalid JSON format in email wipe command.")
                return False, "Invalid JSON payload"
        elif isinstance(raw_input, dict):
            data = raw_input
        else:
            return False, "Unsupported payload type"

        if not isinstance(data, dict) or "payload" not in data or "signature" not in data:
            logger.critical("Missing required payload or signature fields in email wipe command.")
            return False, "Missing payload or signature"

        payload = data["payload"]
        signature = data["signature"]

        if not isinstance(payload, dict):
            return False, "Malformed payload object"

        # 1. Verify action
        if payload.get("action") != "emergency_wipe":
            return False, "Invalid action type"

        # 2. Verify HMAC Signature
        expected_sig = self.compute_signature(self._key, payload)
        if not hmac.compare_digest(str(signature), expected_sig):
            logger.critical("FORGERY ATTEMPT: Email wipe command HMAC signature mismatch. Rejected.")
            try:
                from core.audit_log import AuditLog
                log_path = (self.audit_dir / "audit_log.jsonl") if self.audit_dir else None
                al = AuditLog(path=log_path) if log_path else AuditLog()
                al.append("email_wipe_signature_mismatch", {"payload": payload})
            except Exception:
                pass
            return False, "Invalid cryptographic signature"

        # 3. Verify Freshness Window
        ts = payload.get("timestamp", 0.0)
        now = time.time()
        if abs(now - ts) > self.freshness_window:
            logger.warning("Email wipe command expired or from future (ts=%.1f, now=%.1f).", ts, now)
            return False, "Command timestamp expired or invalid"

        # 4. Replay Protection: Nonce check with verified audit chain
        nonce = payload.get("nonce")
        if not nonce or not isinstance(nonce, str):
            return False, "Missing or invalid nonce"

        with self._lock:
            try:
                # Refresh nonces including cryptographically verified audit chain cross-check
                self._seen_nonces.update(self._load_nonces())
            except Exception as chain_err:
                logger.critical("REFUSING EMAIL COMMAND: Audit chain verification failed: %s", chain_err)
                return False, f"Audit chain integrity failure: {chain_err}"

            if nonce in self._seen_nonces:
                logger.critical("REPLAY ATTACK ATTEMPT: Email wipe command nonce '%s' already used. Rejected.", nonce)
                try:
                    from core.audit_log import AuditLog
                    log_path = (self.audit_dir / "audit_log.jsonl") if self.audit_dir else None
                    al = AuditLog(path=log_path) if log_path else AuditLog()
                    al.append("email_wipe_replay_rejected", {"nonce": nonce})
                except Exception:
                    pass
                return False, "Replay attack detected: nonce already consumed"

            self._seen_nonces.add(nonce)
            self._save_nonces()

        # 5. Execute Wipe via Shared EmergencyWipeController
        logger.critical("🚨 AUTHENTICATED EMAIL WIPE COMMAND VERIFIED. Executing remote wipe.")
        try:
            from core.audit_log import AuditLog
            log_path = (self.audit_dir / "audit_log.jsonl") if self.audit_dir else None
            al = AuditLog(path=log_path) if log_path else AuditLog()
            al.append("email_wipe_command_executed", {"nonce": nonce, "reason": payload.get("reason", "")})
        except Exception:
            pass

        try:
            from sentinel.audit.chain import AuditLogger
            prod_logger = AuditLogger(audit_dir=self.audit_dir) if self.audit_dir else AuditLogger()
            prod_logger.log_event("email_wipe_command_executed", actor="email_listener", details={"nonce": nonce})
        except Exception:
            pass

        success, results = self._controller.execute_wipe(channel="signed_email")
        status_msg = "Wipe executed successfully" if success else "Wipe execution encountered errors"
        return success, f"{status_msg}: {', '.join(results)}"

    def poll_inbox(self, client: Optional[Any] = None) -> List[Tuple[bool, str]]:
        """
        Polls the IMAP inbox for new messages and processes any signed wipe commands.
        Fails safely to a no-op on network or credential errors.
        """
        results: List[Tuple[bool, str]] = []
        mail_client = client

        try:
            if mail_client is None:
                if not self.imap_user or not self.imap_password:
                    return results
                mail_client = imaplib.IMAP4_SSL(self.imap_server, self.imap_port)
                mail_client.login(self.imap_user, self.imap_password)

            mail_client.select("INBOX")
            status, response = mail_client.search(None, "UNSEEN")
            if status != "OK" or not response or not response[0]:
                return results

            msg_ids = response[0].split()
            for m_id in msg_ids:
                res_status, msg_data = mail_client.fetch(m_id, "(RFC822)")
                if res_status != "OK" or not msg_data:
                    continue

                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        raw_email = response_part[1]
                        msg = email.message_from_bytes(raw_email)
                        body = ""
                        if msg.is_multipart():
                            for part in msg.walk():
                                if part.get_content_type() == "text/plain":
                                    payload = part.get_payload(decode=True)
                                    if payload:
                                        body = payload.decode("utf-8", errors="ignore")
                                        break
                        else:
                            payload = msg.get_payload(decode=True)
                            if payload:
                                body = payload.decode("utf-8", errors="ignore")

                        if body:
                            outcome = self.process_email_payload(body)
                            results.append(outcome)

            if client is None and mail_client:
                try:
                    mail_client.close()
                    mail_client.logout()
                except Exception:
                    pass

        except Exception as conn_err:
            logger.warning("Email wipe listener connectivity failure: %s (safe no-op).", conn_err)
            return []

        return results
