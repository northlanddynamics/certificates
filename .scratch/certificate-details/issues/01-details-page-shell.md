# 01: Details page shell and Overview

**What to build:** A Managed Certificate has its own page at `/organizations/$orgId/certificates/$id` with the header, alert strip and tabs in the path (Overview as the index, then Issued certificates, Activity, Services, Notifications), and Overview carries everything the inline expansion did, so the inline `Details` is removed. See `spec.md` for the layout, states and visibility rules.

**Blocked by:** none

**Status:** ready-for-agent

- [x] Start by checking which renewal and Certificate fields the API already exposes; none is added in this ticket except what Overview strictly needs.
- [x] The route is a layout with child routes `/issued`, `/activity`, `/services`, `/notifications` and an index; an unknown slug redirects to Overview.
- [x] The header shows names, status badge, environment and key algorithm, with Renew now and Download of the current Certificate; Archive sits in a "⋯" menu behind `confirm-dialog`.
- [x] The alert strip shows the latest failure or `renewal.failing` with Try again, and a pending Proposal or Name Change with Approve and Reject (reason required) for an Approver who did not propose it, and "Awaiting Approval" for the proposer.
- [x] Overview shows names with the Name Change control, the current Certificate's fingerprint and validity ("N of M days left"), Key Custody, environment, Owners (each Team with its members, add and remove for those who may), and Renewal (policy, `dueAt`, `dueBecause`, ARI window).
- [x] Services and Notifications render one shared empty-state component with "Not available yet" and a sentence of what will appear; Issued certificates and Activity render a plain placeholder until tickets 02 and 03.
- [x] Loading shows skeletons; a missing, invisible or other-Organization Managed Certificate shows the same "not found"; an Issuance in progress polls every 2 seconds.
- [x] An archived page shows a read-only banner and offers only Download (Revoke joins it in ticket 02), with no Renew, Name Change, Owner or Archive controls; a Proposal and a rejected one show what the spec says on Overview.
- [x] The inventory's Names cell and the Approval queue rows link to the page, the expand column and `Details` are removed, an Administrator's create from the New Managed Certificate dialog opens the new page, and a Member's Proposal stays on the inventory with a confirmation and a link.
- [x] Checked in the browser pane as an Owner, an Approver, an Administrator and a Member who cannot see it, across each state in the spec.

## Comments

Implemented. Notes:
- No server work was needed: `GET …/managed-certificates/:id` already returns `keyCustody`, the current Certificate's `notBefore`, `serial`, `ca` and `acmeAccountId` (so the spec's "list item gains its serial" is already true), and `renewal.{dueAt,dueBecause,ari,failing}`. The web `Certificate` and `ManagedCertificate` types were widened to match.
- Until ticket 02, Revoke stays on Overview (the existing control) for a page that is not archived, and the header Download offers the current Certificate only; older Certificates cannot be downloaded until the Issued certificates tab has per-row Download.
- Try again calls Renew now for a Managed Certificate that has a Certificate (Owners may), and retries the first Issuance otherwise (Administrators only).
- Overview's Owners lists each Team's members from the first 100 Teams (`api.teams`); a Team beyond that shows "No members".

