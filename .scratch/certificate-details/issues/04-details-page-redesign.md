# 04: Details page redesign

**What to build:** Rework the Managed Certificate details page so its state and expiry read at a glance and every change has one home, following the wireframes at https://claude.ai/artifact/Kg9AzSm4pBcqhRQPEyirf9. Web only; it uses what the API already returns.

**Blocked by:** 01, 02, 03

**Status:** ready-for-human

- [x] Header: the common name (or first name) as the title with a "+N names" popover, the status with the expiry ("Issued · expires in 38 days"), and one line of issuer, key algorithm, key holder and profile.
- [x] One "⋯" menu holds every change but Renew and Download: Change names (or Propose a name change), Replace key, Change Issuing CA, Detach from profile, and Archive last and apart. The dialogs are controlled, so the Overview's sections open the same ones.
- [x] The alert strip becomes a "Needs attention" panel, most urgent first, each item with its action; a pending Name Change shows the names it adds and removes, with Approve and Reject for an Approver and Withdraw for whoever proposed it.
- [x] A Lifecycle band above the tabs: a bar from the current Certificate's start to its end with today, the Renewal due date, the CA's suggested window and an overdue Renewal; and tiles for time left, next Renewal and the latest Issuance. A Proposal shows its steps to a first Certificate instead, with the rejection reason if rejected.
- [x] Overview: names and the current Certificate on the left (serial and fingerprint with copy, Revoke, the way to every Certificate); Renewal, Owners, Key, Issuer and Notifications on the right, each with its change beside it.
- [x] Tabs: Overview, Certificates, Activity, Notifications. The empty Services tab is gone; its old URL falls to Overview.
- [x] Activity: grouped by day, an icon per kind, filters (Issuance, Approvals and names, Revocations, failures only), and a failed attempt's full record on request.
- [x] Checked in the browser against the dev database: a healthy one, one with a failing Renewal and a pending Name Change (as Approver and as proposer), a Proposal, Activity filters, the menu's dialogs, Renewal Policy edit, and a phone-width viewport.
