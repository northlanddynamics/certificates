# 09: Renewal Policy and scheduler

**What to build:** Each Managed Certificate has a Renewal Policy: automatic or manual, and how many days before expiry Renewal happens. The scheduler renews automatic Managed Certificates when due, reusing the stored CSR for Owner Key Custody, and retries failures with backoff. Owners can upload a new CSR at any time and can "renew now".

**Blocked by:** 05 (First Certificate (tracer))

**Status:** done

- [x] An Owner or Organization Administrator can set the Renewal Policy (automatic or manual; days before expiry).
- [x] Automatic Managed Certificates are renewed when the configured number of days before expiry is reached, using the stored CSR.
- [x] Manual Managed Certificates are only renewed when an Owner or Organization Administrator starts it.
- [x] "Renew now" is available to Owners and Organization Administrators.
- [x] Owners can upload a new CSR (same algorithm and names) that is used from the next Renewal.
- [x] Failed Renewals are retried with backoff and the failure state is visible in the inventory.
- [x] The scheduler's clock is injectable so Seam A tests control time.
- [x] Renewals and CSR uploads are audited.

## Comments

Implemented on `main`; typecheck, the web build and the full Seam A suite pass against Postgres, Pebble and BIND.

- **Renewal Policy.** `PUT .../managed-certificates/{id}/renewal-policy` takes `{ mode: automatic | manual, daysBeforeExpiry: 1..365 }`; a Managed Certificate starts automatic at 30 days. Organization Administrators and the Managed Certificate's Owners (a Member Owner included) may, through new permissions `setRenewalPolicy`, `renew` and `replaceCsr`, which an Owner holds by owning it, as with `changeOwners` (`findAsOwnerOr` in the reader). Every Managed Certificate in the API now has `renewal: { policy, dueAt, failing }`.
- **The scheduler** (`renewal-scheduler.ts`) is stateless: a pass (`tick`, run every minute by `index.ts`) finds automatic, live, approved Managed Certificates whose current Certificate is within its days of ending and starts an Issuance for each, with the stored CSR. A pass that repeats, or runs on two instances, starts a Renewal once because a Managed Certificate has at most one Issuance running. Its clock is the app's `clock`; the harness has `runRenewalScheduler()`. A decision to confirm: the work queue the spec mentions is, so far, this polling pass over Postgres; there is no job table.
- **A tenth of its life.** A Certificate is never due in the first tenth of its life, so a policy of more days than it lives (30 days on a 6-day Certificate, as Pebble's short profile makes) cannot renew it again the moment it is issued. This is mine, not in the ticket.
- **Retries and backoff.** A failed Renewal is tried again after 10 minutes, then 20, 40 and so on, up to 6 hours. How many have failed is read from the Issuances since the last that succeeded, so there is no counter. `renewal.failing` has the count, the last failure and `nextAttemptAt` (none for a manual Managed Certificate, which is never retried), and the inventory has a `renewalFailing` filter and the web a "Renewal failing" one. A failed first Issuance is not a failing Renewal (no Certificate yet to renew).
- **Renew now** is `POST .../renewals` (202 with the Issuance), for a Managed Certificate that has a Certificate, is approved and is not archived; 409 otherwise, and 409 while one runs. Whoever started it is the Issuance's requester. A manual Managed Certificate's failed renew now counts as failing but is not retried.
- **New CSR.** `POST .../csr` takes a PEM CSR for the same key algorithm and exactly the same names (400 for something that is not a CSR, 422 for a mismatch) and every Renewal from the next on uses it.
- **Audited:** `managed_certificate.renewal_policy_changed` (from and to), `managed_certificate.csr_uploaded` (the CSR's and the previous CSR's fingerprints, never the CSR). A Renewal's `issuance.started` carries `renewal: "scheduled" | "requested"`; a scheduled one has no actor (`requested_by` on `issuance` is now nullable for it), and so do its outcome events.
- Web: a Renewal section on each Managed Certificate (the policy in words, the failure and next attempt, Renew now, and settings for the policy and a new CSR).
- Not here: ARI (ticket 10), Agent custody and "Agent offline" (19), and notices of failures (20).
- **Review follow-ups.** The `renewalFailing` filter now means what `renewal.failing` does (a failure since the last success, so a Managed Certificate stays listed while its retry runs); the scheduler checks mode, archive and Approval again under a row lock before it starts a Renewal; a CSR upload is limited to 64,000 characters; "Try again" shows only for a Managed Certificate with no Certificate yet (Renew now covers the rest); CONTEXT.md states the tenth-of-life rule. Known gaps: no test of an archived Managed Certificate (nothing archives one until ticket 12); policy and CSR changes are not refused on an archived one; Renew now has no cooldown, so an Owner can ask for one Renewal after another against the CA's rate limits.
