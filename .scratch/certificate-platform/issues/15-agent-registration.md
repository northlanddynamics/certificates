# 15: Agent Registration and identity

**What to build:** An Organization Administrator creates a single-use Agent Registration token; a Go Agent installed on a Windows or Linux host registers with it, receives an mTLS identity certificate from a platform-internal Agent identity CA (not a Private CA), and thereafter connects only outbound to heartbeat, report its version and poll for work items. The Agents list shows each Agent's host name, OS, version, last contact and online/offline status, flags outdated versions, and lets an Organization Administrator revoke an Agent. This ticket also stands up the Seam B test harness: the Agent run against a stub Platform API built from the OpenAPI contract.

**Blocked by:** 01 (Walking skeleton)

**Status:** ready-for-agent

- [ ] An Organization Administrator can create a single-use Registration token scoped to their Organization; reuse is refused.
- [ ] A registered Agent authenticates with mTLS using a platform-issued identity certificate that rotates automatically before expiry.
- [ ] The Agent only makes outbound HTTPS connections and polls (or long-polls) for work items.
- [ ] The Agents list shows host name, OS, version, last contact and online/offline status, and flags outdated versions.
- [ ] A revoked Agent can no longer authenticate.
- [ ] Each Agent belongs to exactly one Organization.
- [ ] Seam B harness exists and covers registration, identity rotation and offline/retry behaviour.
- [ ] Registration and revocation are audited.
