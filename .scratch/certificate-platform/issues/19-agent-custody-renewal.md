# 19: Renewal with Agent-held keys

**What to build:** Renewal of a Managed Certificate with Agent Key Custody generates a new key on the Agent every time, then issues and deploys as in the first Deployment. If the Agent is offline when Renewal is due, the Renewal waits, the Managed Certificate shows "Agent offline", and it resumes when the Agent reconnects.

**Blocked by:** 09 (Renewal Policy and scheduler), 18 (First Deployment (tracer))

**Status:** ready-for-agent

- [ ] Each Renewal asks the Agent for a new key and CSR; the new Certificate's public key differs from the previous one.
- [ ] The renewed Certificate is deployed by the Deployment Script and recorded as a Deployment Run.
- [ ] If the Agent is offline, the Renewal stays pending, the inventory shows "Agent offline", and it completes once the Agent reconnects (Seam A with controlled time).
- [ ] The "renewal failing" and "Agent offline" inventory filters work.
