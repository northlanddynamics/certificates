# 01: Prefactor: an Issuance can wait for its CA and resume

**What to build:** Today an issuer kind issues within one call and hands back the Certificate. ADCS answers through an Agent, sometimes days later, so make the issuer seam able to answer "pending" with a handle the kind keeps. The Issuance stays running and records the handle. It resumes when the kind reports the result: it stores the Certificate, or records the failure cause. If no result arrives by a deadline the kind sets, it fails with "timed out". ACME CAs and Private CAs keep answering at once, so nothing visible changes. See `.scratch/adcs/spec.md` (Implementation Decisions: Issuer kind, Pending and timeouts).

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] An issuer kind may answer an issue request with "pending" and a handle, in place of a Certificate.
- [ ] A pending Issuance stays running, keeps its handle, and still stops another Issuance of its Managed Certificate from starting.
- [ ] A pending Issuance resumes on the kind's result, ending in a stored Certificate or a recorded failure cause, with the same Audit Events and notices as an Issuance that finished at once.
- [ ] A pending Issuance whose deadline passes fails with a "timed out" cause.
- [ ] Pending Issuances survive a platform restart.
- [ ] A test-only issuer kind exercises the pending path through Seam A. All existing ACME and Private CA tests pass unchanged.
