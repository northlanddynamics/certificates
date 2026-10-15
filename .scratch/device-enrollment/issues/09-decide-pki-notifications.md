# 09: Decide PKI notifications

**What to build:** A decision, deferred from the design grilling until both features are built: which notices Private CAs and device enrollment send, and to whom. Candidates: Issuing CA expiry warnings, CRL publication failures, Intune validation failures (such as expiring Entra credentials), RA certificate expiry, enrollment refusal spikes. Once decided, it becomes its own spec or tickets.

**Blocked by:** private-ca 01–09, device-enrollment 01–08

**Status:** ready-for-human

- [ ] The decision is recorded and either specified as tickets or explicitly declined.
