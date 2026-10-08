# 24: Platform Operator console

**What to build:** Platform Operators can list Organizations with usage counts (Managed Certificates, Agents, users), suspend and reactivate an Organization, and impersonate users through Better Auth. A platform-wide setting, off by default, turns on impersonation auditing: when on, impersonation sessions are recorded and actions taken during them also name the impersonating Platform Operator.

**Blocked by:** 05 (First Certificate (tracer)), 15 (Agent Registration and identity), 21 (Audit search and SIEM forwarding)

**Status:** ready-for-agent

- [ ] Platform Operators see a list of Organizations with usage counts, without seeing inside them.
- [ ] Suspending an Organization blocks its users' sign-in, its API keys, its issuance and Renewal, and its Agents; reactivating restores them.
- [ ] Platform Operators can impersonate a user with no consent step (ADR 0001).
- [ ] With impersonation auditing off (default), no impersonation records are written and actions are attributed to the impersonated user.
- [ ] With it on, session start and end are recorded and actions during impersonation name the Platform Operator.
- [ ] Platform Operator actions are logged on the platform side.
