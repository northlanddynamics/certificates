# 02: Prefactor: revocation recorded on the CA's later confirmation

**What to build:** Today Revocation asks the CA and records the result in the same change. ADCS confirms through an Agent later, so make the issuer seam able to accept a revocation request and confirm or refuse it afterwards. The platform records the Revocation (and its Audit Event) only on confirmation, and reports a refusal or an unreachable CA as the request's failure. ACME CAs and Private CAs keep confirming at once, so nothing visible changes. See `.scratch/adcs/spec.md` (Implementation Decisions: Revocation).

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] An issuer kind may accept a revocation request and confirm or refuse it later.
- [ ] A Certificate is shown as revoked, and its Revocation Audit Event written, only once its CA has confirmed.
- [ ] While confirmation is awaited, the Certificate shows that revocation was requested, and the same Certificate cannot be revoked again.
- [ ] A refused or unreachable revocation is reported with its cause and leaves the Certificate unrevoked.
- [ ] Device Certificate revocation (manual, from the revocation feed, and `superseded`) goes through the same path.
- [ ] A test-only issuer kind exercises the deferred path. All existing revocation tests pass unchanged.
