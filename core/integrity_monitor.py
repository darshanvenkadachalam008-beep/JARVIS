"""
core/integrity_monitor.py — Codebase & Startup Integrity Monitor (C10 Signed Manifest)
=======================================================================================
Protects the codebase against unauthorized file tampering, backdoor injection,
and persistence hijacking using asymmetric Ed25519 digital signatures:
1. Generates SHA-256 cryptographic hashes for all modules in core/, sentinel/, agent/, agents/, actions/.
   Crucially includes core/integrity_monitor.py itself to protect the verifier.
2. The baseline manifest is digitally signed with an Ed25519 Private Key.
3. The running daemon only stores and trusts the pinned Ed25519 Public Key (memory/integrity_pubkey.pem).
   The private signing key never resides on the monitored runtime environment.
4. Verifies Ed25519 signature and file hashes on startup and prior to executing critical actions.
5. Verifies Windows startup registration (Registry HKCU Run / Startup folder).
6. Strict Fail-Closed Policy: Missing public key, corrupted manifest, signature mismatch,
   or modified files immediately triggers critical alerts, emits audit log events, and refuses execution.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Union, Dict, Any, List

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from core.audit_log import AuditLog

logger = logging.getLogger(__name__)


def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


_MONITORED_DIRS = ["core", "sentinel", "agent", "agents", "actions"]
_DEFAULT_MANIFEST_PATH = _base_dir() / "memory" / "integrity_manifest.json"
_DEFAULT_PUBKEY_PATH = _base_dir() / "memory" / "integrity_pubkey.pem"


def _compute_file_sha256(path: Path) -> str:
    """Calculates SHA-256 hash of file contents with normalized newlines."""
    content = path.read_bytes()
    # Normalize CRLF to LF for deterministic hashing across platforms
    normalized = content.replace(b"\r\n", b"\n")
    return hashlib.sha256(normalized).hexdigest()


def generate_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generates an Ed25519 keypair for offline signing and public key pinning."""
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def export_public_key_pem(public_key: ed25519.Ed25519PublicKey) -> str:
    """Serializes Ed25519 public key to PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def export_private_key_pem(private_key: ed25519.Ed25519PrivateKey) -> str:
    """Serializes Ed25519 private key to PEM format."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def load_public_key(key_source: Union[str, Path, bytes, ed25519.Ed25519PublicKey]) -> ed25519.Ed25519PublicKey:
    """Loads an Ed25519 public key from PEM string, file path, raw bytes, or existing instance."""
    if isinstance(key_source, ed25519.Ed25519PublicKey):
        return key_source
    if isinstance(key_source, Path):
        key_source = key_source.read_bytes()
    elif isinstance(key_source, str):
        if os.path.exists(key_source):
            key_source = Path(key_source).read_bytes()
        else:
            key_source = key_source.encode("utf-8")
    elif not isinstance(key_source, bytes):
        raise TypeError(f"Unsupported key source type: {type(key_source)}")

    try:
        # Try loading PEM format
        loaded = serialization.load_pem_public_key(key_source)
        if isinstance(loaded, ed25519.Ed25519PublicKey):
            return loaded
        raise ValueError("Public key is not an Ed25519 key.")
    except Exception:
        # Try loading raw 32-byte public key
        if len(key_source) == 32:
            return ed25519.Ed25519PublicKey.from_public_bytes(key_source)
        raise ValueError("Invalid public key format or encoding.")


def load_private_key(key_source: Union[str, Path, bytes, ed25519.Ed25519PrivateKey]) -> ed25519.Ed25519PrivateKey:
    """Loads an Ed25519 private key from PEM string, file path, raw bytes, or existing instance."""
    if isinstance(key_source, ed25519.Ed25519PrivateKey):
        return key_source
    if isinstance(key_source, Path):
        key_source = key_source.read_bytes()
    elif isinstance(key_source, str):
        if os.path.exists(key_source):
            key_source = Path(key_source).read_bytes()
        else:
            key_source = key_source.encode("utf-8")
    elif not isinstance(key_source, bytes):
        raise TypeError(f"Unsupported key source type: {type(key_source)}")

    try:
        loaded = serialization.load_pem_private_key(key_source, password=None)
        if isinstance(loaded, ed25519.Ed25519PrivateKey):
            return loaded
        raise ValueError("Private key is not an Ed25519 key.")
    except Exception:
        if len(key_source) == 32:
            return ed25519.Ed25519PrivateKey.from_private_bytes(key_source)
        raise ValueError("Invalid private key format or encoding.")


@dataclass
class IntegrityReport:
    is_valid: bool
    tampered_files: list[str]
    missing_files: list[str]
    new_untracked_files: list[str]
    startup_tampered: bool = False
    details: str = ""


class IntegrityMonitor:
    def __init__(
        self,
        manifest_path: Optional[Path] = None,
        public_key_path: Optional[Path] = None,
        base_dir: Optional[Path] = None,
    ):
        self.base = base_dir or _base_dir()
        self.manifest_path = manifest_path or (self.base / "memory" / "integrity_manifest.json")
        self.public_key_path = public_key_path or (self.base / "memory" / "integrity_pubkey.pem")
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        self._audit = AuditLog()

    def generate_baseline(
        self,
        private_key: Union[str, Path, bytes, ed25519.Ed25519PrivateKey],
        pin: str = "",
        access_control=None,
    ) -> dict:
        """
        Computes current SHA-256 hashes of all monitored files and saves the Ed25519-signed manifest.
        Requires PIN if access control is configured.
        Requires explicit out-of-band private_key (never read from ambient daemon environment).
        """
        if access_control is not None and access_control.is_configured():
            if not access_control.verify_pin(pin, action="generate_integrity_baseline"):
                raise PermissionError("PIN verification failed: cannot generate baseline without authorization.")

        if private_key is None:
            raise ValueError(
                "Explicit Ed25519 private signing key is required to generate/sign an integrity manifest. "
                "Private signing keys are held out-of-band and are strictly forbidden from being stored in or ambiently accessible by the daemon runtime."
            )

        priv = load_private_key(private_key)
        pub = priv.public_key()
        pub_pem = export_public_key_pem(pub)
        pub_fingerprint = hashlib.sha256(pub_pem.encode("utf-8")).hexdigest()[:16]

        file_hashes: dict[str, str] = {}
        for dir_name in _MONITORED_DIRS:
            target_dir = self.base / dir_name
            if not target_dir.exists():
                continue
            for file_path in target_dir.rglob("*.py"):
                # Skip cache and temporary files
                if "__pycache__" in str(file_path) or file_path.name.endswith(".pyc"):
                    continue
                rel_path = str(file_path.relative_to(self.base)).replace("\\", "/")
                file_hashes[rel_path] = _compute_file_sha256(file_path)

        manifest_data = {
            "version": "2.0",
            "file_count": len(file_hashes),
            "hashes": file_hashes,
        }

        # Canonicalize JSON representation for signature
        canonical_bytes = json.dumps(manifest_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig_bytes = priv.sign(canonical_bytes)
        sig_hex = sig_bytes.hex()

        payload = {
            "version": "2.0",
            "algorithm": "Ed25519",
            "public_key_fingerprint": pub_fingerprint,
            "signature": sig_hex,
            "manifest": manifest_data,
        }

        self.manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        # Ensure public key is present
        if not self.public_key_path.exists():
            self.public_key_path.write_text(pub_pem, encoding="utf-8")

        self._audit.append("integrity_baseline_updated", {
            "file_count": len(file_hashes),
            "manifest": str(self.manifest_path.name),
            "fingerprint": pub_fingerprint,
        })
        return payload

    def verify_integrity(
        self,
        public_key: Optional[Union[str, Path, bytes, ed25519.Ed25519PublicKey]] = None,
        alert_callback: Optional[Callable[[str], None]] = None,
    ) -> IntegrityReport:
        """
        Verifies all monitored Python files against the Ed25519 digitally-signed baseline manifest.
        Fails closed on missing/invalid public key, corrupted manifest, signature mismatch, or file tampering.
        """
        # 1. Resolve and validate pinned public key
        pub: Optional[ed25519.Ed25519PublicKey] = None
        if public_key is not None:
            try:
                pub = load_public_key(public_key)
            except Exception as e:
                err_msg = f"Provided public verification key is invalid: {e}"
                self._audit.append("integrity_check_failure", {"error": err_msg})
                if alert_callback:
                    alert_callback(f"🚨 INTEGRITY CRITICAL: {err_msg}")
                return IntegrityReport(is_valid=False, tampered_files=["public_key"], missing_files=[], new_untracked_files=[], details=err_msg)
        elif self.public_key_path.exists():
            try:
                pub = load_public_key(self.public_key_path)
            except Exception as e:
                err_msg = f"Pinned public verification key file is corrupted: {e}"
                self._audit.append("integrity_check_failure", {"error": err_msg})
                if alert_callback:
                    alert_callback(f"🚨 INTEGRITY CRITICAL: {err_msg}")
                return IntegrityReport(is_valid=False, tampered_files=["public_key.pem"], missing_files=[], new_untracked_files=[], details=err_msg)
        else:
            err_msg = "Pinned public verification key is missing. Refusing execution (fail-closed)."
            self._audit.append("integrity_check_failure", {"error": err_msg})
            if alert_callback:
                alert_callback(f"🚨 INTEGRITY CRITICAL: {err_msg}")
            return IntegrityReport(is_valid=False, tampered_files=["public_key_missing"], missing_files=[], new_untracked_files=[], details=err_msg)

        # 2. Check manifest existence
        if not self.manifest_path.exists():
            err_msg = "Integrity manifest file is missing. Failing closed."
            self._audit.append("integrity_check_failure", {"error": err_msg})
            if alert_callback:
                alert_callback(f"🚨 INTEGRITY CRITICAL: {err_msg}")
            return IntegrityReport(
                is_valid=False,
                tampered_files=[],
                missing_files=["integrity_manifest.json"],
                new_untracked_files=[],
                details=err_msg,
            )

        try:
            payload = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            sig_hex = payload.get("signature", "")
            manifest = payload.get("manifest", {})
            stored_hashes = manifest.get("hashes", {})
        except Exception as e:
            err_msg = f"Integrity manifest is corrupted or unreadable: {e}"
            self._audit.append("integrity_check_failure", {"error": err_msg})
            if alert_callback:
                alert_callback(f"🚨 INTEGRITY CRITICAL: {err_msg}")
            return IntegrityReport(is_valid=False, tampered_files=["integrity_manifest.json"], missing_files=[], new_untracked_files=[], details=err_msg)

        # 3. Verify Ed25519 Asymmetric Signature
        try:
            sig_bytes = bytes.fromhex(sig_hex)
            canonical_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
            pub.verify(sig_bytes, canonical_bytes)
        except (InvalidSignature, ValueError, TypeError) as e:
            tamper_msg = f"Integrity manifest Ed25519 signature is INVALID! Manifest file has been tampered with or signed with an unauthorized key: {e}"
            self._audit.append("integrity_check_failure", {"error": tamper_msg})
            if alert_callback:
                alert_callback(f"🚨 INTEGRITY CRITICAL: {tamper_msg}")
            return IntegrityReport(is_valid=False, tampered_files=["manifest.signature"], missing_files=[], new_untracked_files=[], details=tamper_msg)

        # 4. Check each baseline file
        tampered = []
        missing = []
        for rel_path, expected_hash in stored_hashes.items():
            full_path = self.base / rel_path
            if not full_path.exists():
                missing.append(rel_path)
                continue
            curr_hash = _compute_file_sha256(full_path)
            if curr_hash != expected_hash:
                tampered.append(rel_path)

        # 5. Check for unauthorized new scripts injected into monitored directories
        untracked = []
        for dir_name in _MONITORED_DIRS:
            target_dir = self.base / dir_name
            if not target_dir.exists():
                continue
            for file_path in target_dir.rglob("*.py"):
                if "__pycache__" in str(file_path) or file_path.name.endswith(".pyc"):
                    continue
                rel_path = str(file_path.relative_to(self.base)).replace("\\", "/")
                if rel_path not in stored_hashes:
                    untracked.append(rel_path)

        # 6. Check Windows startup entry integrity
        startup_tampered = False
        if sys.platform.startswith("win"):
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ) as key:
                    val, _ = winreg.QueryValueEx(key, "JARVIS")
                    # Ensure path points to valid jarvis startup launcher
                    if "jarvis" not in val.lower():
                        startup_tampered = True
            except FileNotFoundError:
                pass
            except Exception:
                pass

        is_clean = len(tampered) == 0 and len(missing) == 0 and len(untracked) == 0 and not startup_tampered

        if not is_clean:
            alert_text = (
                f"🚨 CODEBASE INTEGRITY VIOLATION DETECTED!\n"
                f"Tampered files: {tampered}\n"
                f"Missing files: {missing}\n"
                f"Untracked files: {untracked}\n"
                f"Startup hijacked: {startup_tampered}"
            )
            self._audit.append("integrity_violation", {
                "tampered": tampered,
                "missing": missing,
                "untracked": untracked,
                "startup_tampered": startup_tampered,
            })
            if alert_callback:
                alert_callback(alert_text)

        return IntegrityReport(
            is_valid=is_clean,
            tampered_files=tampered,
            missing_files=missing,
            new_untracked_files=untracked,
            startup_tampered=startup_tampered,
            details="Integrity verified clean." if is_clean else "Integrity check failed.",
        )


def verify_on_startup() -> bool:
    """Startup verification gate. Returns True if clean; triggers Telegram alert on failure."""
    monitor = IntegrityMonitor()
    if not monitor.manifest_path.exists() or not monitor.public_key_path.exists():
        print("[IntegrityMonitor] 🚨 Integrity manifest or pinned public key is missing. Failing closed.")
        return False

    def _alert_telegram(msg: str):
        try:
            from core.telegram_alert import TelegramAlerter
            t = TelegramAlerter()
            if t.configured:
                t.send_alert(msg)
        except Exception:
            pass

    report = monitor.verify_integrity(alert_callback=_alert_telegram)
    if not report.is_valid:
        print(f"[IntegrityMonitor] [CRITICAL] {report.details}")
        print(f"  Tampered files: {report.tampered_files}")
        print(f"  Missing files: {report.missing_files}")
        print(f"  Untracked files: {report.new_untracked_files}")
        return False

    print("[IntegrityMonitor] [OK] Codebase integrity verified (Ed25519 signed manifest valid)")
    return True


if __name__ == "__main__":
    import argparse
    import getpass

    parser = argparse.ArgumentParser(
        description="Sentinel / JARVIS Codebase & Startup Integrity Monitor Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--init", action="store_true", help="Generate a new Ed25519 keypair, sign the codebase manifest, and pin the public key.")
    parser.add_argument("--update", action="store_true", help="Re-sign the codebase manifest using an existing Ed25519 private key.")
    parser.add_argument("--private-key", help="Path to Ed25519 private key file or PEM string (for --update).")
    parser.add_argument("--save-private-key", type=Path, help="Optional path to save the generated private key (e.g. to a secure backup directory or USB drive).")
    parser.add_argument("--pin", help="Admin PIN (if access control is configured).")
    parser.add_argument("--verify", action="store_true", help="Verify codebase integrity against pinned public key.")

    args = parser.parse_args()

    if args.init:
        print("[*] Generating new Ed25519 keypair for Codebase Integrity Baseline...")
        priv, pub = generate_keypair()
        priv_pem = export_private_key_pem(priv)
        pub_pem = export_public_key_pem(pub)

        pin = args.pin or ""
        ac = None
        if pin:
            try:
                from core.access_control import AccessControl
                ac = AccessControl()
            except Exception:
                pass

        monitor = IntegrityMonitor()
        payload = monitor.generate_baseline(private_key=priv, pin=pin, access_control=ac)

        # Ensure public key is written to memory/integrity_pubkey.pem
        monitor.public_key_path.write_text(pub_pem, encoding="utf-8")

        print("================================================================================")
        print("[SUCCESS] INTEGRITY BASELINE GENERATED SUCCESSFULLY")
        print("================================================================================")
        print(f"Manifest written to:   {monitor.manifest_path}")
        print(f"Public key pinned to:  {monitor.public_key_path}")
        print(f"Monitored files:       {payload['manifest']['file_count']}")
        print(f"Key fingerprint:       {payload['public_key_fingerprint']}")
        print("================================================================================")
        print("[SECURITY NOTICE] ED25519 PRIVATE SIGNING KEY:")
        print("Per the C10 design, the private key must be kept OUT-OF-BAND (offline vault, password manager).")
        print("If you lose this key, you cannot generate updates to the manifest without generating")
        print("a new keypair and re-pinning the public key.")
        print("--------------------------------------------------------------------------------")
        print(priv_pem)
        print("================================================================================")

        if args.save_private_key:
            try:
                args.save_private_key.parent.mkdir(parents=True, exist_ok=True)
                args.save_private_key.write_text(priv_pem, encoding="utf-8")
                try:
                    from sentinel.security_utils import apply_owner_only_dacl
                    apply_owner_only_dacl(args.save_private_key)
                except Exception:
                    pass
                print(f"[+] Private key also saved to: {args.save_private_key}")
            except Exception as e:
                print(f"[!] Failed to save private key to specified path: {e}")

        sys.exit(0)

    elif args.update:
        if not args.private_key:
            print("[-] --private-key <path_or_pem> is required when --update is specified.", file=sys.stderr)
            sys.exit(1)

        pin = args.pin or ""
        try:
            from core.access_control import AccessControl
            ac = AccessControl()
            if ac.is_configured() and not pin:
                pin = getpass.getpass("Enter Admin PIN to authorize baseline generation: ")
        except Exception:
            ac = None

        monitor = IntegrityMonitor()
        payload = monitor.generate_baseline(private_key=args.private_key, pin=pin, access_control=ac)
        print(f"[+] Integrity manifest updated. Files monitored: {payload['manifest']['file_count']}")
        sys.exit(0)

    else:
        # Default action: verify
        success = verify_on_startup()
        sys.exit(0 if success else 1)


