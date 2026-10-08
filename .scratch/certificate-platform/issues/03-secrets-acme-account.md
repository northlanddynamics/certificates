# 03: Secrets and the Let's Encrypt ACME account

**What to build:** An Organization Administrator can register their Organization's ACME account with Let's Encrypt, choosing staging or production. The account key and any other secrets are stored with envelope encryption: a data key per Organization, wrapped by a pluggable KMS (a local key for development; AWS KMS and Azure Key Vault adapters behind the same interface). Secrets are write-only.

**Blocked by:** 01 (Walking skeleton)

**Status:** ready-for-agent

- [ ] An Organization Administrator can create an ACME account against Let's Encrypt staging or production (Pebble in tests).
- [ ] Staging is the default for a new Organization.
- [ ] No API, including for Organization Administrators or an impersonating Platform Operator, returns a secret's value; secrets can be replaced or tested only.
- [ ] Each Organization's secrets are encrypted under its own data key.
- [ ] The KMS is pluggable, with a local implementation used in development and tests.
- [ ] Account creation and secret replacement are audited without the secret's value.
