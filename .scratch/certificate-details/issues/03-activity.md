# 03: Activity tab and Issuance attempts

**What to build:** The Activity tab shows the Managed Certificate's history together with each Issuance attempt and its failure, so that a failure cleared by a retry can still be explained, and the newest failure feeds the alert strip. See `spec.md`.

**Blocked by:** 01

**Status:** ready-for-agent

- [x] A server test, written first, covers `GET …/managed-certificates/:id/issuances`: each attempt's time, kind (first issue, Renewal, Name Change), status and failure code and message; ordered newest first; and "not found" for a caller who may not see the Managed Certificate.
- [x] The Activity tab shows the existing history entries and the attempts, interleaved by time, each worded as in the existing history, with failures in the destructive style.
- [x] The alert strip's current failure comes from the newest failed attempt (or `renewal.failing`), and clears when a later attempt succeeds.
- [x] A Managed Certificate that never had an attempt shows an empty state saying so.
- [x] Checked in the browser pane with a failed attempt followed by a successful retry.
- [x] Issue 27 gains one scenario: a Member's Proposal, then an Approver deciding it from the details page.

## Comments

- Each Issuance now records its kind (`first_issue`, `renewal`, `name_change`), decided by `begin` from the Managed Certificate's latest Certificate and names; migration 0030 backfills existing rows (a retried Name Change before it reads as a Renewal).
- Visibility follows the existing convention rather than the ticket's literal "not found": a Member who may not see the Managed Certificate gets 403, as from its GET, `/history` and `/certificates`; another Organization or a missing one gets 404, and the page shows both as "not found".
- The browser check used the dev database for the successful retry (no Pebble in that environment): two failed first Issuances, then a succeeded one with its Certificate. The alert strip cleared and Activity kept both failures.
