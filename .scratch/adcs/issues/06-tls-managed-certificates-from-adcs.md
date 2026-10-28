# 06: TLS Managed Certificates from an ADCS CA

**What to build:** A Managed Certificate's issuer can be an ADCS CA plus one of its TLS templates. An Organization Administrator creates one outright; a Member proposes one and an Approver, who sees the ADCS CA and template, approves it. Before anything is submitted, the platform checks:
- the ADCS CA's optional Permitted Name Rules, which an Organization Administrator sets on the ADCS CA page, with a warning shown when there are none
- the template's minimum key size and key algorithms.

The Issuance runs as `adcs.submit` on an online assigned Agent, failing over to another Agent if one cannot reach the CA. While no Agent is online it waits, and fails after 7 days. The template decides validity, and validity cannot be chosen. Renewal follows the Renewal Policy alone. Name Changes, Deployments with Agent Key Custody, and exports with the chain all work. See `.scratch/adcs/spec.md`.

**Blocked by:** 01 (an Issuance can wait for its CA and resume), 05 (Keeping templates current).

**Status:** done

- [x] `adcs` is an issuer kind, accepted by the database checks, carrying the ADCS CA and template.
- [x] Create, propose, approve and Name Change against an ADCS CA and an available, unhidden TLS template. Other templates are refused.
- [x] Permitted Name Rules on an ADCS CA can be set and changed (Audit Events), and are enforced at proposal, Name Change and Issuance. The console warns when there are none.
- [x] CSRs that fail the template's key requirements are refused with a clear reason, before submission.
- [x] Validity fields are refused for an ADCS issuer.
- [x] `adcs.submit` is in the agent contract and implemented on both sides: issued, `rejected` and `unreachable` results; failover between assigned Agents; the Issuance shows "waiting for an Agent"; it fails after 7 days with no Agent.
- [x] An issued Certificate records the ADCS request ID, which appears in the Issuance's Audit Events with `adcsCa.requestSubmitted`.
- [x] A template that is unavailable at submission fails the Issuance with that cause.
- [x] Renewal by Renewal Policy, a Deployment, and exports with the ADCS chain work, tested through Seam A.
- [x] The issuer picker in the web console offers ADCS CAs with their TLS templates. Certificate details show the ADCS CA and template.
- [x] Go: the contract test covers submit, and Seam B covers `adcs.submit`.

## Comments

- Server: `server/src/adcs/adcs-issuance.ts` is the ADCS kind of issuer. An Issuance's CSR becomes an `adcs_request` (migration 0062), given as `adcs.submit` to the online assigned Agent most recently heard from; the Issuance is pending (ticket 01) with the request's id as its handle, and a backstop deadline of 7 days and an hour. `tick()` (once a minute from `index.ts`, `h.runAdcsRequests()` in tests) gives waiting requests to Agents that came online, re-checks the template before it does, fails requests 7 days old as `no_agent_available`, and reports again an outcome recorded but not reported.
- Failover: an `unreachable` result goes to another online assigned Agent; when every assigned Agent has been tried it fails as `ca_unreachable`, and while some are offline it waits (retrying the ones that could not reach it once no other is online). An Agent that has not *taken* the item within `submitTimeoutMs` (10 minutes) is given up on; one that took it is never, since a second submission could issue twice at ADCS. Ticket 07 should keep that rule when it adds `adcs.check`.
- `adcs.submit` results: `submission: { status: "issued", requestId, certificate }`; ADCS refusing is `rejected` with its reason (`ca_rejected`). Ticket 07 adds `pending` and `denied` to `SubmissionResult`.
- New failure codes `no_agent_available` and `template_unavailable`. Names outside the CA's Permitted Name Rules at Issuance fail as `name_not_permitted`; a key the template does not take as `ca_rejected` (it is refused at create, propose, Name Change and Deployment first).
- API: `issuer: { kind: "adcs", adcsCaId, templateId }` on create, propose and Deployments; the Managed Certificate shows `{ kind: "adcs", adcsCa, template }`; a Certificate has `adcs: { adcsCaId, templateId, requestId }`; an Issuance has `adcs: { status, agent, requestId }` (`waiting` is "waiting for an Agent"). Approving re-checks the template and Permitted Name Rules. The ADCS CA takes `permittedNames` (null for none) on create and PATCH, audited in `adcs_ca.created`/`updated`.
- Template key rule (`templateKeyRefusal` in `adcs-kinds.ts`, shared with the web): an RSA key must be one of its algorithms and at least its minimum key size; an ECDSA key's curve must be one it allows.
- Revocation of an ADCS Certificate is refused for now (`REVOCATION_REASONS_OF.adcs` is empty) until ticket 08; Certificate Profiles refuse an ADCS issuer until ticket 09.
