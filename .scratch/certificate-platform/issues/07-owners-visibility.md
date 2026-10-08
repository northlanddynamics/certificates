# 07: Owners and visibility

**What to build:** Managed Certificates can have Owners (users and/or Teams) or none. Members see only Managed Certificates they own directly or through a Team; Organization Administrators and Approvers see the whole Organization. The inventory has filters and each Managed Certificate has a history view.

**Blocked by:** 02 (Members, roles and Teams), 05 (First Certificate (tracer))

**Status:** ready-for-agent

- [ ] Owners (users or Teams) can be added and removed; zero Owners is allowed.
- [ ] Members see only Managed Certificates they own directly or through a Team, in both the UI and the API.
- [ ] Organization Administrators and Approvers see all Managed Certificates in the Organization.
- [ ] The inventory can be filtered by expiring soon, pending Approval, no Owners, Key Custody and archived (later filters such as renewal failing and Agent offline plug into the same mechanism).
- [ ] A Managed Certificate's history shows its Certificates, name changes and Approvals.
- [ ] Owner changes are audited.
