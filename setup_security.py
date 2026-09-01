"""
setup_security.py — One-time setup for the new security layer
==================================================================
Run this once (`python setup_security.py`) after pulling this update.
It will:

  1. Create an encrypted vault (config/vault.enc) protected by a master
     password you choose, and migrate every key currently sitting in
     plaintext in config/api_keys.json and config/firebase-service-account.json
     into it.
  2. Optionally cache the vault key in your OS keyring so Mark can start
     unattended on this machine without re-prompting every boot.
  3. Set a separate PIN required before any destructive action can run
     (currently: the Telegram /wipe command; wire it into any other
     destructive action via core.access_control.AccessControl().verify_pin()).
  4. Do a first write + verify pass on the tamper-evident audit log.

Nothing here deletes your original plaintext files unless you explicitly
say yes when asked — you can run this, confirm the vault works, and clean
up the plaintext files later.
"""
from __future__ import annotations

import getpass
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.secure_vault import SecureVault
from core.access_control import AccessControl
from core.audit_log import AuditLog


def _prompt_pin(label: str, min_len: int = 4) -> str:
    while True:
        p1 = getpass.getpass(f"  {label} (min {min_len} chars): ")
        if len(p1) < min_len:
            print(f"  Too short — must be at least {min_len} characters.")
            continue
        p2 = getpass.getpass("  Confirm: ")
        if p1 != p2:
            print("  Didn't match, try again.")
            continue
        return p1


def _setup_access_control(ac: AccessControl) -> None:
    print("\n[2/3] Identity & Authorization PINs (Primary + Recovery).")
    print("  This gates sensitive commands, face profile resets, and system actions.")

    if not ac.is_configured():
        # Case (a): Fresh install (not configured at all)
        print("  Configuring new dual-PIN credentials (Primary PIN + Recovery PIN).")
        while True:
            prim_pin = _prompt_pin("Choose a Primary PIN/passphrase")
            rec_pin = _prompt_pin("Choose a distinct Recovery PIN/passphrase")
            if prim_pin == rec_pin:
                print("  Primary PIN and Recovery PIN must not be identical. Please try again.")
                continue
            break

        # Generate and consume physical presence challenge
        token = ac.generate_presence_challenge()

        try:
            ac.enroll_dual_pin(prim_pin, rec_pin, presence_token=token)
            print("  [SUCCESS] Dual-PIN profile armed with full hard-lockout protection.")
        except Exception as e:
            print(f"  [ERROR] Failed to enroll credentials: {e}")

    elif ac.has_recovery_pin():
        # Case (b): Configured with Recovery PIN already set
        ans = input("  A PIN profile (Primary + Recovery) is already set. Replace it? [y/N]: ").strip().lower()
        if ans != "y":
            print("  Keeping existing PIN profile.")
            return

        current_pin = getpass.getpass("  Enter current Primary PIN to authorize changes: ")
        if not ac.verify_pin(current_pin, action="setup_security_replace"):
            print("  [FAILED] Authentication refused — incorrect current Primary PIN. Replacement aborted.")
            return

        print("  Authentication confirmed. Choose new credentials:")
        while True:
            new_prim = _prompt_pin("Choose new Primary PIN/passphrase")
            new_rec = _prompt_pin("Choose new Recovery PIN/passphrase")
            if new_prim == new_rec:
                print("  Primary PIN and Recovery PIN must not be identical. Please try again.")
                continue
            break

        try:
            ac.enroll_dual_pin(new_prim, new_rec, current_primary_pin=current_pin)
            print("  [SUCCESS] Primary and Recovery PINs updated successfully.")
        except Exception as e:
            print(f"  [ERROR] Failed to update PINs: {e}")

    else:
        # Case (c): Configured in legacy-compat mode (no Recovery PIN)
        print("  Primary PIN is configured in legacy-compatibility mode (no Recovery PIN).")
        ans = input("  Add a Recovery PIN now to enable full hard-lockout protection? [Y/n]: ").strip().lower()
        if ans != "n":
            rec_pin = _prompt_pin("Choose a Recovery PIN/passphrase")
            try:
                ac.set_recovery_pin(rec_pin)
                print("  [SUCCESS] Recovery PIN set successfully. Full hard-lockout protection is now active.")
            except Exception as e:
                print(f"  [ERROR] Failed to set recovery PIN: {e}")
        else:
            ans2 = input("  Replace the existing Primary PIN entirely instead? [y/N]: ").strip().lower()
            if ans2 == "y":
                current_pin = getpass.getpass("  Enter current Primary PIN to authorize changes: ")
                if not ac.verify_pin(current_pin, action="setup_security_replace"):
                    print("  [FAILED] Authentication refused — incorrect current Primary PIN. Replacement aborted.")
                    return
                while True:
                    new_prim = _prompt_pin("Choose new Primary PIN/passphrase")
                    new_rec = _prompt_pin("Choose new Recovery PIN/passphrase")
                    if new_prim == new_rec:
                        print("  Primary PIN and Recovery PIN must not be identical. Please try again.")
                        continue
                    break
                try:
                    ac.enroll_dual_pin(new_prim, new_rec, current_primary_pin=current_pin)
                    print("  [SUCCESS] Primary and Recovery PINs updated successfully.")
                except Exception as e:
                    print(f"  [ERROR] Failed to update PINs: {e}")
            else:
                print("  Keeping existing configuration.")


def main():
    print("=" * 60)
    print("  Mark XXXIX-OR — Security Setup")
    print("=" * 60)

    # ── 1. Vault ─────────────────────────────────────────────────────────
    vault = SecureVault()
    if vault.exists():
        print("\n[1/3] Vault already exists at config/vault.enc — skipping creation.")
    else:
        print("\n[1/3] Creating encrypted secrets vault.")
        while True:
            pw1 = getpass.getpass("  Choose a master password (min 8 chars): ")
            if len(pw1) < 8:
                print("  Too short — use at least 8 characters, ideally a passphrase.")
                continue
            pw2 = getpass.getpass("  Confirm: ")
            if pw1 != pw2:
                print("  Didn't match, try again.")
                continue
            break
        vault.set_master_password(pw1)
        migrated = vault.migrate_legacy_secrets(delete_originals=False)
        print(f"  Migrated {len(migrated)} secret(s) into the vault: {', '.join(migrated) or '(none found)'}")

        if migrated:
            ans = input(
                "  Delete the original plaintext config/api_keys.json and "
                "firebase-service-account.json now that they're safely in the vault? [y/N]: "
            ).strip().lower()
            if ans == "y":
                vault2 = SecureVault()
                vault2.unlock(pw1)
                vault2.migrate_legacy_secrets(delete_originals=True)
                print("  Originals securely overwritten and deleted.")
            else:
                print("  Left plaintext originals in place. Delete them yourself once you've verified the vault works.")

        try:
            import keyring  # noqa
            ans = input("  Cache the vault key in this OS's keyring so Mark can start unattended? [y/N]: ").strip().lower()
            if ans != "y":
                print("  Skipped — you'll be prompted for the master password on every start.")
                import keyring as kr
                try:
                    kr.delete_password("mark-xxxix-or-vault", "vault-key")
                except Exception:
                    pass
        except ImportError:
            print("  (keyring not installed — pip install keyring to enable unattended start.)")

    # ── 2. Destructive-action PIN ───────────────────────────────────────
    ac = AccessControl()
    _setup_access_control(ac)

    # ── 3. Audit log sanity check ────────────────────────────────────────
    print("\n[3/3] Verifying tamper-evident audit log.")
    log = AuditLog()
    log.append("setup_security_run", {"result": "completed"})
    ok, problem = log.verify()
    print(f"  Audit log integrity: {'OK' if ok else 'PROBLEM — ' + str(problem)}")

    print("\nDone. See README's 'Security Layer' section for how these plug into the rest of the app.")


if __name__ == "__main__":
    main()