# 16: Relayed DNS Providers

**What to build:** An Organization Administrator can assign one or more Agents to relay a DNS Provider, so DNS inside the Organization's network (such as on-prem Infoblox or BIND) works with the hosted platform. Any online relay Agent is used.

**Blocked by:** 05 (First Certificate (tracer)), 15 (Agent Registration and identity)

**Status:** ready-for-agent

- [ ] A DNS Provider can be set to run directly or through one or more relay Agents.
- [ ] Present, clean-up and test-connection operations are delivered as work items and executed by the Agent with the same provider code.
- [ ] If one relay Agent is offline, another online one is used; if none are online, the operation fails with a clear cause.
- [ ] End-to-end issuance with Direct DCV via a relayed RFC 2136 DNS Provider succeeds (Seam A with an Agent stand-in, Seam B for the Agent side).
- [ ] DNS Provider credentials reach the Agent only as needed for the operation and are never displayed.
