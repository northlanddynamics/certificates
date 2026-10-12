# 03: Activity tab and Issuance attempts

**What to build:** The Activity tab shows the Managed Certificate's history together with each Issuance attempt and its failure, so that a failure cleared by a retry can still be explained, and the newest failure feeds the alert strip. See `spec.md`.

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] A server test, written first, covers `GET …/managed-certificates/:id/issuances`: each attempt's time, kind (first issue, Renewal, Name Change), status and failure code and message; ordered newest first; and "not found" for a caller who may not see the Managed Certificate.
- [ ] The Activity tab shows the existing history entries and the attempts, interleaved by time, each worded as in the existing history, with failures in the destructive style.
- [ ] The alert strip's current failure comes from the newest failed attempt (or `renewal.failing`), and clears when a later attempt succeeds.
- [ ] A Managed Certificate that never had an attempt shows an empty state saying so.
- [ ] Checked in the browser pane with a failed attempt followed by a successful retry.
- [ ] Issue 27 gains one scenario: a Member's Proposal, then an Approver deciding it from the details page.

## Comments
