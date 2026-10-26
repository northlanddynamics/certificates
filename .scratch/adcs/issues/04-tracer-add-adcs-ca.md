# 04: Tracer: add an ADCS CA and see its templates

**What to build:** An Organization Administrator adds an **ADCS CA**:
- They give its name and config string (`host\CA Name`) and assign one or more of the Organization's Windows Agents.
- An online assigned Agent carries out `adcs.discover`: it fetches the CA certificate and chain and lists the Certificate Templates with their facts.
- Nothing is saved if no Agent can reach the CA.

The ADCS CA page shows the chain, the CDP URLs from the CA certificate, and the discovered templates. The ADCS CA can be renamed, have its Agents changed, and be removed while nothing refers to it.

On the Go Agent side: the ADCS client interface, its fake, the contract test for discovery and the chain, and the "cannot reach ADCS" answer on non-Windows builds.

This ticket also writes the ADR "ADCS is an external CA reached only through Agents" and adds **ADCS CA** and **Certificate Template** to `CONTEXT.md`. See `.scratch/adcs/spec.md`.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] The `adcsCa` permission (`read` for everyone; `create`, `update` and `delete` for Organization Administrators), reported by `/api/me`.
- [ ] Adding an ADCS CA succeeds only when an assigned Agent fetches its chain. An unreachable or rejected CA saves nothing and shows the Agent's reason.
- [ ] Assigning an Agent that does not report Windows, or that belongs to another Organization, is refused.
- [ ] The `adcs.discover` Work Item and its result are in the agent contract, and `agent-contract.test.ts` covers them.
- [ ] Discovered templates are stored with their facts: name, OID, display name, EKUs, validity, minimum key size, key algorithms, manager approval, subject from request, enrollable, published.
- [ ] The web console has an ADCS CAs page with add and edit dialogs, the chain (downloadable), the CDP URLs and a read-only template table.
- [ ] Removing an ADCS CA is refused while anything refers to it.
- [ ] `adcsCa.created`, `adcsCa.updated`, `adcsCa.deleted` and `adcsCa.discovered` Audit Events are written with their changes.
- [ ] Seam A tests use the Agent stand-in backed by a new in-memory ADCS double.
- [ ] Go: the ADCS client interface, the fake, the contract test (discover and chain), and a Seam B test of `adcs.discover` against `platformstub`, including the non-Windows refusal and that nothing secret is logged.
- [ ] The ADR and the `CONTEXT.md` terms are written.
