# 10: ACME Renewal Information (ARI)

**What to build:** Automatic Renewal follows the CA's ACME Renewal Information. The scheduler polls ARI for each current Certificate and renews at whichever comes first: a time chosen within the ARI suggested window, or the Renewal Policy's days-before-expiry. Renewal orders identify the Certificate they replace so the CA treats them as ARI-coordinated.

**Blocked by:** 09 (Renewal Policy and scheduler)

**Status:** done

- [x] The scheduler fetches ARI for current Certificates, respecting the CA's Retry-After.
- [x] Renewal happens at the earlier of the ARI-chosen time and the days-before-expiry deadline.
- [x] When the CA moves the window earlier (e.g. ahead of revocation), Renewal is rescheduled earlier (Seam A test with Pebble).
- [x] Renewal orders reference the Certificate being replaced.
- [x] When the CA offers no ARI, only days-before-expiry applies.

## Comments

Implemented on `main`; typecheck, the web build and the full Seam A suite pass against Postgres, Pebble and BIND.

- **Asking the CA.** `CertificateAuthority.renewalInfo(environment, certificate)` reads the directory's `renewalInfo`, asks for the Certificate by its ARI identifier (authority key identifier and serial, RFC 9773) and returns the suggested window and the CA's `Retry-After`; it is null when the CA has no ARI or does not know the Certificate. acme-client 5.4 has no ARI, so this is a plain `fetch`.
- **What is stored.** `renewal_info` (migration 0013) holds, per Certificate, the last window (none if the CA offered none), when the CA last answered, and when it is next asked (`nextCheckAt`). The scheduler pass (`renewal-information.ts`) first asks about the current Certificate of each automatic, live, approved Managed Certificate whose `nextCheckAt` has come: the CA's Retry-After (kept between one minute and a day; six hours when it gave none or offers no ARI), fifteen minutes after a failure to ask, which leaves what it last said standing. At most 100 per pass, ten at a time.
- **Due at the earlier of the two.** `renewalDue` (renewal.ts) is the policy's days (with the tenth-of-life rule) or a time within the CA's window, whichever is first. The time within the window is a point the Certificate's fingerprint decides, so it is the same every pass and spread across Certificates, not drawn at random each time. The window is not held to the tenth-of-life rule: a CA that asks early has a reason. Backoff after a failure applies as before.
- **Moving earlier.** Because the window is read again once the CA's Retry-After has passed, a window moved earlier (Seam A test: Pebble's `set-renewal-info`) makes the Renewal due then; until then the scheduler goes by what it was told.
- **Replaces.** An Issuance of a Managed Certificate that has a Certificate places its order with `replaces` set to that Certificate, but only for a CA whose directory offers ARI. A CA that refuses an order with `replaces` (already replaced, or unknown) is asked again without it, so ARI can never make a Renewal fail. The test checks on the wire that Pebble marked the first Certificate replaced.
- **API and web.** `renewal.dueAt` is now the earlier of the two; `renewal.dueBecause` is `policy` or `ari`, and `renewal.ari` has the window, when the CA last answered and when it is next asked. The Renewal section says "when the CA suggests" when the window is what is due first.
- **Tests.** The harness's CA answers ARI only when a test turns it on (`h.ari.enabled`), because Pebble's own window, two thirds into a Certificate's life, would otherwise decide the Renewals of the earlier tests; it also records what each order replaced and can fail to answer. Pebble's short profile makes Certificates of six days, so the ARI tests use one day before expiry.
- Not here: a manual Managed Certificate is not asked about (ARI drives automatic Renewal only), and ARI for an Agent-held key waits for ticket 19.
- **Review follow-ups.** The `replaces` fallback now places the order without it only when the CA's refusal is about the replacement (already replaced, not known, not this account's), not for a network failure or rate limit (tested against Pebble's `alreadyReplaced`); a Certificate ARI cannot name (no authority key identifier) is renewed as an ordinary order. Known gaps: the ARI poll runs at the start of each scheduler pass, so a slow CA delays that pass; a Retry-After on a failed answer is not read (fifteen minutes) and one over a day is held to a day; a single 404 drops the stored window; the directory is fetched for each Certificate asked about.
