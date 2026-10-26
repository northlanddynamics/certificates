# 04: Portal home

**What to build:** A portal user's home shows what needs their attention first (Managed Certificates expiring soon, Proposals waiting or rejected), then all the Managed Certificates they own, directly or through a Team, and their Proposals, with search. They can start a request, reach the CSR Generator and the Viewer, and, when their permissions go beyond the portal, open the Console. Approvers see how many Proposals wait for them, with a link to decide them in the Console.

**Blocked by:** 03 (Sessions land in their front end)

**Status:** ready-for-agent

- [ ] Built on the existing Managed Certificate and Approval endpoints; no new server behaviour.
- [ ] "Needs your attention" lists Managed Certificates within their renewal urgency (the existing web rule) and Proposals awaiting Approval or rejected with a reason.
- [ ] The list shows each Managed Certificate's names, the Certificate Profile it came from in plain words, its issuer, its expiry and its status. A search narrows it by name.
- [ ] "Request a certificate" is offered only when `/api/me` allows proposing.
- [ ] The waiting-Proposals count and its Console link show only to those whose permissions let them decide Approvals.
- [ ] "Open the console" shows only when the caller's permissions include more than the portal offers, decided from `/api/me` permissions, never role names.
- [ ] Links to the CSR Generator and the Viewer, and to the Organization's help.
- [ ] Works at phone width.
