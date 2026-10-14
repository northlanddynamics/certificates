# 19: Renewal with Agent-held keys

**What to build:** Renewal of a Managed Certificate with Agent Key Custody generates a new key on the Agent every time, then issues and deploys as in the first Deployment. If the Agent is offline when Renewal is due, the Renewal waits, the Managed Certificate shows "Agent offline", and it resumes when the Agent reconnects.

**Blocked by:** 09 (Renewal Policy and scheduler), 18 (First Deployment (tracer))

**Status:** done

- [x] Each Renewal asks the Agent for a new key and CSR; the new Certificate's public key differs from the previous one.
- [x] The renewed Certificate is deployed by the Deployment Script and recorded as a Deployment Run.
- [x] If the Agent is offline, the Renewal stays pending, the inventory shows "Agent offline", and it completes once the Agent reconnects (Seam A with controlled time).
- [x] The "renewal failing" and "Agent offline" inventory filters work.

## Comments

Implemented on `agent-custody-renewal`. Typecheck, the web build, the full Seam A suite (534 pass, against Postgres, Pebble and BIND) and the Go Agent's tests pass. The Agent itself is unchanged: its key store already files several keys per Managed Certificate by public-key hash and finds a Certificate's key from the Certificate, so no Seam B tests were needed.

- **A Renewal waits for the key.** An Issuance of an Agent-custody Managed Certificate that already has a Certificate (a Renewal, whoever asked) begins with `awaitingKey` set (new `issuance.awaiting_key` column, migration 0025). It asks the Deployment's Agent for a new key through a durable `deployment.generate_key` work item that names the Issuance. The Issuance runs DCV and finalizes only once the Agent's CSR has been checked and stored. The scheduler is unchanged: one running Issuance per Managed Certificate already prevents repeat requests. The same applies to "Renew now", which returns the waiting Issuance (202).
- **Agent offline.** The work item never expires, so the Renewal waits however long the Agent is away, and a restart's sweep (`failInterrupted`) leaves it alone. Every Managed Certificate now has `agent: { id, hostName, status } | null`, and its Issuance has `awaitingKey`. The inventory has an `agentOffline` filter (the Agent is not revoked and has been silent longer than `offlineAfterSeconds`). The web has the "Agent offline" facet and status, plus an alert while a Renewal is held up. The "Agent revoked" status is also shown.
- **Failures.** If the Agent cannot make a new key, or sends a CSR for the wrong names or algorithm, the Renewal fails with the new code `agent_key_failed`. It then counts as failing and is retried with backoff like any failed Renewal; `deployment.key_failed` is audited with the `issuanceId`.
- **Archive and revocation.** Archiving ends a Renewal still waiting for its key (new code `archived`). Revoking the Agent ends one (`agent_key_failed`). A Renewal of a Managed Certificate whose Agent is revoked is refused (`agent_revoked`, 409 for "Renew now").
- **Audited:** `issuance.started` (with `renewal`), `deployment.key_generated` with the `issuanceId`, then the usual Issuance and Deployment Run events.
- **Known gap:** if building the work item fails with an unexpected error (not a `PreparationError`), the item is marked failed without telling the Issuance, which would wait for good. No API path leads there.

