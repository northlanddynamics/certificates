# 08: Renewal and Agent custody from a Private CA

**What to build:** Managed Certificates on a Private CA renew on their Renewal Policy (there is no ARI), and Key Custody: Agent works for them, so a Deployment can install a Private CA Certificate exactly as it installs a public one.

**Blocked by:** 03

**Status:** ready-for-agent

- [ ] The Renewal scheduler renews automatic Managed Certificates on a Private CA by days before expiry and the tenth-of-life rule alone; it asks the Private CA no ARI.
- [ ] Manual Renewal and a Renewal after a Name Change work as for ACME.
- [ ] A Deployment with an Agent holding the key obtains and deploys a Private CA Certificate with its full chain, in a scenario like the first-Deployment test.
