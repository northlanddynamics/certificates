# 04: External Account Binding for custom ACME CAs

**What to build:** An Organization Administrator can give a custom ACME CA an External Account Binding key id and HMAC key, so that CAs which require one accept the registration. The HMAC key is a Secret that nobody can read back.

**Blocked by:** 02

**Status:** done

- [x] First check that the test harness can run Pebble with External Account Binding required; if it cannot, make that possible, or record the gap in this ticket and cover it in a unit test of the registration request.
- [x] The create form takes an optional key id and HMAC key; registration with a CA that requires them succeeds, and fails with the CA's reason when they are wrong or missing.
- [x] The HMAC key is stored as a Secret, is never returned by any API, and does not appear in Audit Events, logs or errors; the key id is shown to administrators.
- [x] Server tests cover required, wrong and absent External Account Binding, and that the key is not exposed.

## Comments

- The harness can run it: `docker-compose.yml` gains `pebble-eab`, a second Pebble on `https://localhost:14001/dir` with `externalAccountBindingRequired` and one key (`docker/pebble-eab/pebble-config.json`; the tests' `PEBBLE_EAB_KEY`). CI starts it with the others. So no unit test of the registration request was needed: the scenarios in `server/test/acme-accounts.test.ts` ("External Account Binding") register against it with the real ACME client.
- `POST /acme-cas` takes `externalAccountBinding: { keyId, hmacKey }`, both or neither (400); the HMAC key is base64url or base64. The CA's refusal (missing, wrong HMAC key, unknown key id) is 422 with its reason, and nothing is saved. The HMAC key is stored as a Secret (`acme_ca.external_account_secret_id`, migration 0050) in the same change as the CA; the key id is on the CA, shown as `externalAccountBinding.keyId` to those who see its configuration, and in the `acme_ca.created` Audit Event (`externalAccountBinding: null` when there is none).
- The stored HMAC key is not read by anything yet: EAB is used only when the account is registered, which for a custom CA happens once, when it is added, and the binding is fixed after (spec: "the directory URL and External Account Binding are fixed"). It is kept, as the spec asks, and ticket 05 removes it with the CA. ADR 0002's "replaced or tested" does not apply to it while the binding cannot be changed.
- "External Account Binding" is not yet in `CONTEXT.md`; left for ticket 06 with the other docs.
