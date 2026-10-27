# 02: Prefactor: revocation recorded on the CA's later confirmation

**What to build:** Today Revocation asks the CA and records the result in the same change. ADCS confirms through an Agent later, so make the issuer seam able to accept a revocation request and confirm or refuse it afterwards. The platform records the Revocation (and its Audit Event) only on confirmation, and reports a refusal or an unreachable CA as the request's failure. ACME CAs and Private CAs keep confirming at once, so nothing visible changes. See `.scratch/adcs/spec.md` (Implementation Decisions: Revocation).

**Blocked by:** None (can start immediately).

**Status:** done

- [x] An issuer kind may accept a revocation request and confirm or refuse it later.
- [x] A Certificate is shown as revoked, and its Revocation Audit Event written, only once its CA has confirmed.
- [x] While confirmation is awaited, the Certificate shows that revocation was requested, and the same Certificate cannot be revoked again.
- [x] A refused or unreachable revocation is reported with its cause and leaves the Certificate unrevoked.
- [x] Device Certificate revocation (manual, from the revocation feed, and `superseded`) goes through the same path.
- [x] A test-only issuer kind exercises the deferred path. All existing revocation tests pass unchanged.

## Comments

- Implemented as a Revocation Request (`revocation_request`, `server/src/issuance/revocations.ts`): `Issuers.revoke` now takes a batch and answers each "revoked" (after the kind called its `record`) or pending with a handle and deadline. `Revocations.report` records on confirmation; refusals, unreachable CAs and the deadline (`timeOut`, once a minute) fail it with the cause. API answers 202 with `revocationRequest`; new Audit Events `*.revocation_requested` and `*.revocation_failed`.
- The revocation feed still answers an outcome on the change that asks: a requested revocation counts as `revoked` to the feed. Ticket 11 should answer the feed only once the CA confirms.
