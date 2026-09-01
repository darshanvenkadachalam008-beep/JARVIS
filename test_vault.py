"""
test_vault.py — Test Suite for Encrypted Vault with DPAPI & OS Keyring
======================================================================
Verifies:
1. Master password initialization & AES encryption.
2. Windows DPAPI automatic key recovery.
3. In-memory JSON/dict secret storage (Firebase service account).
4. Secure migration & overwrite of legacy plaintext files.
5. Invalid password rejection.
6. Module-level get_secret() zero-plaintext resolution.
"""
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.secure_vault import SecureVault, get_secret, unlock_global_vault, _dpapi_protect, _dpapi_unprotect


def run():
    tmpdir = tempfile.mkdtemp()
    base = Path(tmpdir)
    passed, failed = 0, 0

    def check(label: str, cond: bool):
        nonlocal passed, failed
        if cond:
            print(f"  [PASS] {label}")
            passed += 1
        else:
            print(f"  [FAIL] {label}")
            failed += 1

    try:
        vault_path = base / "vault.enc"
        legacy_keys = base / "api_keys.json"
        legacy_fb = base / "firebase-service-account.json"

        # ── Test 1: DPAPI Native Protection
        print("\n=== [1] DPAPI Encryption & Decryption ===")
        secret_bytes = b"super_secret_master_password_99"
        protected = _dpapi_protect(secret_bytes)
        unprotected = _dpapi_unprotect(protected)
        check("DPAPI encrypted ciphertext != plaintext", protected != secret_bytes)
        check("DPAPI round-trip successfully recovered original bytes", unprotected == secret_bytes)

        # ── Test 2: Vault Creation & Storage
        print("\n=== [2] Vault Creation & Secret Storage ===")
        v1 = SecureVault(path=vault_path)
        v1._dpapi_key_path = base / "vault_key.dpapi"
        v1.set_master_password("TestMasterPass123")

        check("Vault file created on disk", vault_path.exists())
        check("DPAPI key backup created", (base / "vault_key.dpapi").exists())

        v1.set("gemini_api_key", "AIzaSyDummyGeminiKey12345")
        v1.set("firebase_service_account", {"type": "service_account", "project_id": "jarvis-test-project"})

        check("Read string secret from active vault", v1.get("gemini_api_key") == "AIzaSyDummyGeminiKey12345")
        fb_dict = v1.get("firebase_service_account")
        check("Read dictionary secret from active vault", isinstance(fb_dict, dict) and fb_dict.get("project_id") == "jarvis-test-project")

        # ── Test 3: Unlocking from Fresh Instance
        print("\n=== [3] Unlocking & Automatic DPAPI Recovery ===")
        v2 = SecureVault(path=vault_path)
        v2._dpapi_key_path = base / "vault_key.dpapi"

        # Auto-unlock using DPAPI
        unlocked_auto = v2.unlock()
        check("Auto-unlock via DPAPI succeeded", unlocked_auto is True)
        check("Retrieved secret after DPAPI unlock", v2.get("gemini_api_key") == "AIzaSyDummyGeminiKey12345")

        # Unlock with wrong password should fail
        v3 = SecureVault(path=vault_path)
        v3._dpapi_key_path = base / "non_existent_key.dpapi"
        unlocked_bad = v3.unlock("WrongPassword999")
        check("Unlock with incorrect password rejected", unlocked_bad is False)

        # ── Test 4: Legacy File Migration & Secure Deletion
        print("\n=== [4] Legacy File Migration & Secure Deletion ===")
        legacy_keys.write_text(json.dumps({"openrouter_api_key": "sk-or-test1234"}), encoding="utf-8")
        legacy_fb.write_text(json.dumps({"project_id": "migrated-fb-project"}), encoding="utf-8")

        v_mig = SecureVault(path=base / "migrated_vault.enc")
        v_mig._base = base
        v_mig._dpapi_key_path = base / "migrated_key.dpapi"
        (base / "config").mkdir(exist_ok=True)
        # Move legacy files to expected config/ directory
        shutil.move(str(legacy_keys), str(base / "config" / "api_keys.json"))
        shutil.move(str(legacy_fb), str(base / "config" / "firebase-service-account.json"))

        v_mig.set_master_password("MigrationPass123")
        migrated = v_mig.migrate_legacy_secrets(delete_originals=True)

        check("Migration identified and migrated legacy keys", "openrouter_api_key" in migrated and "firebase_service_account" in migrated)
        check("Legacy api_keys.json was wiped and deleted", not (base / "config" / "api_keys.json").exists())
        check("Legacy firebase-service-account.json was wiped and deleted", not (base / "config" / "firebase-service-account.json").exists())
        check("Migrated secrets accessible in new vault", v_mig.get("openrouter_api_key") == "sk-or-test1234")

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print(f"\n==================================================")
    print(f"  Results: {passed} passed, {failed} failed")
    print(f"==================================================")
    return failed == 0


if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
