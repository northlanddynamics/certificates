# 04: Tracer: add an ADCS CA and see its templates

**What to build:** An Organization Administrator adds an **ADCS CA**:
- They give its name and config string (`host\CA Name`) and assign one or more of the Organization's Windows Agents.
- An online assigned Agent carries out `adcs.discover`: it fetches the CA certificate and chain and lists the Certificate Templates with their facts.
- Nothing is saved if no Agent can reach the CA.

The ADCS CA page shows the chain, the CDP URLs from the CA certificate, and the discovered templates. The ADCS CA can be renamed, have its Agents changed, and be removed while nothing refers to it.

On the Go Agent side: the ADCS client interface, its fake, the contract test for discovery and the chain, and the "cannot reach ADCS" answer on non-Windows builds.

This ticket also writes the ADR "ADCS is an external CA reached only through Agents" and adds **ADCS CA** and **Certificate Template** to `CONTEXT.md`. See `.scratch/adcs/spec.md`.

**Blocked by:** None (can start immediately).

**Status:** done

- [x] The `adcsCa` permission (`read` for everyone; `create`, `update` and `delete` for Organization Administrators), reported by `/api/me`.
- [x] Adding an ADCS CA succeeds only when an assigned Agent fetches its chain. An unreachable or rejected CA saves nothing and shows the Agent's reason.
- [x] Assigning an Agent that does not report Windows, or that belongs to another Organization, is refused.
- [x] The `adcs.discover` Work Item and its result are in the agent contract, and `agent-contract.test.ts` covers them.
- [x] Discovered templates are stored with their facts: name, OID, display name, EKUs, validity, minimum key size, key algorithms, manager approval, subject from request, enrollable, published.
- [x] The web console has an ADCS CAs page with add and edit dialogs, the chain (downloadable), the CDP URLs and a read-only template table.
- [x] Removing an ADCS CA is refused while anything refers to it.
- [x] `adcsCa.created`, `adcsCa.updated`, `adcsCa.deleted` and `adcsCa.discovered` Audit Events are written with their changes.
- [x] Seam A tests use the Agent stand-in backed by a new in-memory ADCS double.
- [x] Go: the ADCS client interface, the fake, the contract test (discover and chain), and a Seam B test of `adcs.discover` against `platformstub`, including the non-Windows refusal and that nothing secret is logged.
- [x] The ADR and the `CONTEXT.md` terms are written.

## Comments

- Server: `server/src/adcs/adcs-ca.ts` (routes under `/api/organizations/{orgId}/adcs-cas`, tables `adcs_ca`, `adcs_ca_agent`, `adcs_template`, migration 0060), `adcs-work.ts` (the `adcs.discover` work type and the `discovery` result schema in the agent contract) and `adcs-kinds.ts` (template facts, "available", the EKUs). Discovery is relayed through `server/src/agents/agent-relay.ts`, now shared with relayed DNS Providers: an `unreachable` result passes the work to the next online assigned Agent. A CA no Agent reaches is 502, one ADCS or the Agent refuses is 422, each with the Agent's reason, and nothing is saved.
- Audit actions follow the repo's `<resource>.<verb>` snake case: `adcs_ca.created`, `adcs_ca.updated`, `adcs_ca.deleted`, `adcs_ca.discovered` (documented in `docs/audit-events.md`). Later tickets should name theirs `adcs_ca.template_hidden`, `adcs_ca.request_submitted` and so on.
- Removal is guarded by the database: nothing references an ADCS CA yet, and any table that names one later (tickets 06, 09, 10) should reference `adcs_ca` with a foreign key, which turns into a 409. Those tickets may add a message naming what refers to it, as `acme-accounts.ts` does.
- Discovery replaces the templates wholesale for now; keeping templates that disappear as unavailable, hiding and Refresh are ticket 05.
- Go: `agent/internal/adcs` (the `Client` interface with `Chain` and `Discover`, the `Fake`, `Native`, which refuses off Windows and, until ticket 12, on Windows too) and `adcs/adcstest` (the contract). Submit, check and revoke join the interface with their tickets. The Agent takes a client in `Config.ADCS` for tests.
- ADR 0013 records "ADCS is an external CA reached only through Agents".
