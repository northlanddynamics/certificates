# 09: Renewal Policy and scheduler

**What to build:** Each Managed Certificate has a Renewal Policy: automatic or manual, and how many days before expiry Renewal happens. The scheduler renews automatic Managed Certificates when due, reusing the stored CSR for Owner Key Custody, and retries failures with backoff. Owners can upload a new CSR at any time and can "renew now".

**Blocked by:** 05 (First Certificate (tracer))

**Status:** ready-for-agent

- [ ] An Owner or Organization Administrator can set the Renewal Policy (automatic or manual; days before expiry).
- [ ] Automatic Managed Certificates are renewed when the configured number of days before expiry is reached, using the stored CSR.
- [ ] Manual Managed Certificates are only renewed when an Owner or Organization Administrator starts it.
- [ ] "Renew now" is available to Owners and Organization Administrators.
- [ ] Owners can upload a new CSR (same algorithm and names) that is used from the next Renewal.
- [ ] Failed Renewals are retried with backoff and the failure state is visible in the inventory.
- [ ] The scheduler's clock is injectable so Seam A tests control time.
- [ ] Renewals and CSR uploads are audited.
