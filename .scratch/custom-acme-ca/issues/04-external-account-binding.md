# 04: External Account Binding for custom ACME CAs

**What to build:** An Organization Administrator can give a custom ACME CA an External Account Binding key id and HMAC key, so that CAs which require one accept the registration. The HMAC key is a Secret that nobody can read back.

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] First check that the test harness can run Pebble with External Account Binding required; if it cannot, make that possible, or record the gap in this ticket and cover it in a unit test of the registration request.
- [ ] The create form takes an optional key id and HMAC key; registration with a CA that requires them succeeds, and fails with the CA's reason when they are wrong or missing.
- [ ] The HMAC key is stored as a Secret, is never returned by any API, and does not appear in Audit Events, logs or errors; the key id is shown to administrators.
- [ ] Server tests cover required, wrong and absent External Account Binding, and that the key is not exposed.
