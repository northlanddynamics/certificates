# 18: First Deployment (tracer)

**What to build:** An Organization Administrator sets up a Deployment in one guided flow: pick the Agent, configure the Managed Certificate (names, key algorithm), pick a Deployment Script version, set the Renewal Policy, and deploy. The Agent generates the key and CSR locally, the platform issues the Certificate, the Agent fetches it, verifies the script hash and runs the script with the agreed environment variables, and reports a Deployment Run. The private key never leaves the Agent's host for the platform (ADR 0002).

**Blocked by:** 05 (First Certificate (tracer)), 15 (Agent Registration and identity), 17 (Deployment Script library)

**Status:** done

- [x] The guided flow creates a Managed Certificate with Agent Key Custody bound to exactly one Agent and one Deployment; no Approval is needed.
- [x] The Agent generates the key with the configured algorithm in a store readable only by its service account and submits a CSR; no private key appears in any request (Seam B test).
- [x] After issuance, the Agent runs the script only if its hash matches, with environment variables giving the key, leaf, chain and full-chain file paths and the Managed Certificate's identifiers.
- [x] A Deployment Run is recorded with time, Certificate fingerprint, exit code and output truncated to a limit.
- [x] An Organization Administrator can re-run the Deployment for the current Certificate without renewing.
- [x] One Agent can serve many Deployments.
- [x] Deployment setup and each Deployment Run are audited.
