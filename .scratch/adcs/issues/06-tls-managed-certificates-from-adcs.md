# 06: TLS Managed Certificates from an ADCS CA

**What to build:** A Managed Certificate's issuer can be an ADCS CA plus one of its TLS templates. An Organization Administrator creates one outright; a Member proposes one and an Approver, who sees the ADCS CA and template, approves it. Before anything is submitted, the platform checks:
- the ADCS CA's optional Permitted Name Rules, which an Organization Administrator sets on the ADCS CA page, with a warning shown when there are none
- the template's minimum key size and key algorithms.

The Issuance runs as `adcs.submit` on an online assigned Agent, failing over to another Agent if one cannot reach the CA. While no Agent is online it waits, and fails after 7 days. The template decides validity, and validity cannot be chosen. Renewal follows the Renewal Policy alone. Name Changes, Deployments with Agent Key Custody, and exports with the chain all work. See `.scratch/adcs/spec.md`.

**Blocked by:** 01 (an Issuance can wait for its CA and resume), 05 (Keeping templates current).

**Status:** ready-for-agent

- [ ] `adcs` is an issuer kind, accepted by the database checks, carrying the ADCS CA and template.
- [ ] Create, propose, approve and Name Change against an ADCS CA and an available, unhidden TLS template. Other templates are refused.
- [ ] Permitted Name Rules on an ADCS CA can be set and changed (Audit Events), and are enforced at proposal, Name Change and Issuance. The console warns when there are none.
- [ ] CSRs that fail the template's key requirements are refused with a clear reason, before submission.
- [ ] Validity fields are refused for an ADCS issuer.
- [ ] `adcs.submit` is in the agent contract and implemented on both sides: issued, `rejected` and `unreachable` results; failover between assigned Agents; the Issuance shows "waiting for an Agent"; it fails after 7 days with no Agent.
- [ ] An issued Certificate records the ADCS request ID, which appears in the Issuance's Audit Events with `adcsCa.requestSubmitted`.
- [ ] A template that is unavailable at submission fails the Issuance with that cause.
- [ ] Renewal by Renewal Policy, a Deployment, and exports with the ADCS chain work, tested through Seam A.
- [ ] The issuer picker in the web console offers ADCS CAs with their TLS templates. Certificate details show the ADCS CA and template.
- [ ] Go: the contract test covers submit, and Seam B covers `adcs.submit`.
