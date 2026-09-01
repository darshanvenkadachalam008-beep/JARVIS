# Security Upgrade — Install Instructions

This package contains ONLY new/changed files (no secrets included). To install:

1. Copy these files into your existing Mark-XXXIX-OR project, overwriting where they already exist:
   - core/secure_vault.py       (NEW)
   - core/audit_log.py          (NEW)
   - core/access_control.py     (NEW)
   - core/command_guard.py      (NEW)
   - core/sentinel_extras.py    (REPLACES existing — adds audit-log hook + PIN-gated /wipe)
   - setup_security.py          (NEW — run this once)
   - requirements.txt           (REPLACES existing — was corrupted as UTF-16, now fixed to UTF-8 per its own
                                  header comment, and adds `cryptography` + `keyring`)
   - .gitignore                 (REPLACES existing — adds vault.enc / access_control.json / audit_log.jsonl)
   - readme.md                  (REPLACES existing — adds "Security Layer" section)

2. Install the two new dependencies:
   pip install cryptography keyring --break-system-packages   # (drop --break-system-packages if not needed on your system)

3. Run the one-time setup:
   python setup_security.py

   This will:
   - Create config/vault.enc (encrypted) from your existing config/api_keys.json
     and config/firebase-service-account.json, and offer to delete the plaintext
     originals once you've confirmed it works.
   - Let you cache the vault key in your OS keyring so Mark can still start
     unattended.
   - Set a PIN required before the Telegram /wipe command will actually execute.
   - Do a first write + integrity check of the new tamper-evident audit log.

4. From then on, the Telegram wipe flow is: send `/wipe`, then `/wipe CONFIRM <PIN>`
   instead of just `/wipe CONFIRM`.

Nothing else in your existing code changes or breaks — get_secret() in
secure_vault.py falls back to your old plaintext api_keys.json automatically
until you've run the migration, so this is safe to drop in incrementally.