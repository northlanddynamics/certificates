# 10: ACME Renewal Information (ARI)

**What to build:** Automatic Renewal follows the CA's ACME Renewal Information. The scheduler polls ARI for each current Certificate and renews at whichever comes first: a time chosen within the ARI suggested window, or the Renewal Policy's days-before-expiry. Renewal orders identify the Certificate they replace so the CA treats them as ARI-coordinated.

**Blocked by:** 09 (Renewal Policy and scheduler)

**Status:** ready-for-agent

- [ ] The scheduler fetches ARI for current Certificates, respecting the CA's Retry-After.
- [ ] Renewal happens at the earlier of the ARI-chosen time and the days-before-expiry deadline.
- [ ] When the CA moves the window earlier (e.g. ahead of revocation), Renewal is rescheduled earlier (Seam A test with Pebble).
- [ ] Renewal orders reference the Certificate being replaced.
- [ ] When the CA offers no ARI, only days-before-expiry applies.
