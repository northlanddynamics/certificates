# Certificate platform

Domain language: [CONTEXT.md](CONTEXT.md). Spec and tickets: `.scratch/certificate-platform/`.

## Develop

```bash
make dev    # Docker services, dependencies, a generated .env, then the API (:3000) and the web UI (:5173); Ctrl-C stops both
make help   # the other targets: setup, server, web, migrate, creds, test, check, down, clean, and agent-build, agent-test, agent-register, agent-run, agent-reset for a local Agent
```

`make dev` writes `.env` once (generated `AUTH_SECRET`, `LOCAL_KMS_KEY` and Operator password; `make creds` shows the Operator's) and keeps it: `LOCAL_KMS_KEY` wraps each Organization's data key, so a new one would make stored secrets in an existing database unreadable. `make clean` resets both the database and `.env`. To run an Agent against it, make a registration token on the Agents page, then `make agent-register TOKEN=agt_...` once and `make agent-run` in another terminal (state under `.dev/`). The same steps by hand:

```bash
docker compose up -d --wait        # Postgres on localhost:5433 (databases: certs, certs_test); Pebble on localhost:14000; BIND on localhost:5354
bun install
export DATABASE_URL=postgres://postgres:postgres@localhost:5433/certs
export AUTH_SECRET=$(openssl rand -hex 32)
export LOCAL_KMS_KEY=$(openssl rand -base64 32)   # wraps each Organization's data key; losing it loses the stored secrets
export WEB_URL=http://localhost:5173 TRUSTED_ORIGINS=http://localhost:5173   # the Vite dev server
export OPERATOR_EMAIL=operator@example.com OPERATOR_PASSWORD='a-long-password'   # creates the Platform Operator
bun run dev:server                 # API on :3000, applies migrations on start
bun run dev:web                    # UI on :5173 (the web/ workspace), proxies /api to :3000
```

Invitation emails are printed to the server console in development.

## API docs

With the server running, open http://localhost:3000/api/docs (also http://localhost:5173/api/docs through the Vite proxy). It is one Scalar page; use the source picker to switch between "Platform" (our routes) and "Auth" (Better Auth's). The raw OpenAPI documents are at `/api/openapi.json` and `/api/auth/open-api/generate-schema`. On a deployed platform, use `<BASE_URL>/api/docs`.

Identity routes under `/api/auth/*` belong to Better Auth. The page loads the Scalar script from a CDN, so it needs internet access.

## The Agent

`agent/` is the Go Agent, a separate module (`cd agent && go test ./...`). It only connects outbound over HTTPS, registers once with a single-use token that an Organization Administrator makes on the Agents page, and then polls the platform, authenticating with a bearer credential that it rotates before it ends (ADR 0006). It runs on Linux, Windows and macOS (amd64 and arm64).

```bash
agent register --platform https://certs.example.com --token agt_...   # or AGENT_REGISTRATION_TOKEN; once
agent run                                                             # as a service; state in /var/lib/certificate-agent, /Library/Application Support/CertificateAgent or %ProgramData%\CertificateAgent
```

The Agent's protocol is the routes under `/api/agent`. Their OpenAPI contract is generated from the route schemas into `agent/contract/openapi.json` (`bun run contract:export`); a platform test fails while that copy is stale. Seam B runs the Agent against `agent/internal/platformstub`, a stub platform built from that contract, with a clock the tests move; it holds both sides to the contract. An Agent authenticates with `Authorization: Bearer <credential>`, so the platform needs only ordinary TLS: set `TLS_CERT_FILE` and `TLS_KEY_FILE` (PEM) for it to serve HTTPS itself, or put it behind any TLS terminator. An Agent refuses a plain-HTTP platform URL unless the host is loopback, so development needs no certificate. `AGENT_LATEST_VERSION` sets the Agent version below which the Agents list flags an Agent as outdated.

An Organization Administrator can have Agents relay a DNS Provider (`PUT /api/organizations/{orgId}/dns-providers/{id}/relay`), so DNS the hosted platform cannot reach, such as on-prem BIND or Infoblox, still serves DCV. Publishing, removing and testing then become work items (`dns.present`, `dns.cleanup`, `dns.test`) for one online relay Agent, which carries them out with its own RFC 2136 and Infoblox providers (`agent/internal/dnsrelay`, which behave as `server/src/rfc2136.ts` and `server/src/infoblox.ts` do) and reports the result; an offline Agent is passed over, and one that does not answer within 45 seconds is given up on for the next. The provider's credentials are put into a work item only when the Agent is given it, are never stored in it, and are never shown. `AGENT_LONG_POLL_SECONDS` (default 20) is how long an idle poll waits for work, so that relayed operations reach an Agent at once; set it to 0 to answer polls immediately.

Organization Administrators keep a library of Deployment Scripts (Bash or PowerShell, `/api/organizations/{orgId}/deployment-scripts`) that Agents will run to put a Certificate to use (ADR 0004). A script is a name and an interpreter; each upload adds an immutable version identified by the SHA-256 of its exact content (up to 256 KiB), earlier versions stay viewable (the database refuses to change or delete a version), and every upload is audited with the hash. No other role holds `deploymentScript.upload` or `.read`.

An Organization Administrator sets up a Deployment in one call (`POST /api/organizations/{orgId}/deployments`, or Deployments under Automation in the web app): the Agent, the Managed Certificate's names, key algorithm and Renewal Policy, and a Deployment Script version, which is pinned. It makes a Managed Certificate with Key Custody: Agent, bound to that one Agent and that Deployment, with no Approval. The platform never holds the key (ADR 0002):

1. The Agent is asked (`deployment.generate_key`) to make the key, in `<state dir>/keys/<Managed Certificate>/`, readable only by its service account, and sends back only a CSR. The platform checks it as it does an Owner's CSR and begins the Issuance.
2. When the Certificate is stored the Agent is given it and the script (`deployment.run`). It runs the script only if the SHA-256 of the content is the hash that was audited (ADR 0004), and only if the Certificate is the one named and its key is on the host. The script gets `CERT_KEY_FILE`, `CERT_LEAF_FILE`, `CERT_CHAIN_FILE` and `CERT_FULLCHAIN_FILE` (paths; the chain is the intermediates, the full chain the leaf and the chain), and `CERT_MANAGED_CERTIFICATE_ID`, `CERT_DEPLOYMENT_ID`, `CERT_FINGERPRINT`, `CERT_NAMES` (comma-separated) and `CERT_NOT_AFTER`. Bash scripts run with `bash`, PowerShell ones with `pwsh` (Linux) or `powershell.exe` (Windows); a script that runs longer than ten minutes is stopped.
3. The Agent reports a Deployment Run: when, the Certificate's fingerprint, the exit code (none when the script was not started) and its output, kept up to 32 KiB. `POST .../deployments/{id}/runs` has the Agent run the script again for the current Certificate without renewing; `GET` on it lists the runs; when the Agent could not make the key, it asks for the key again.

One Agent can serve many Deployments. Setting one up, the key, each run and each request to run again are Audit Events. Work for a Deployment waits for its Agent however long it is away (the work items are durable), and one the Agent was given but never reported on, because it stopped, is given again after 15 minutes. Until a Deployment can have the Agent make a new key, a Managed Certificate it holds the key for cannot upload a CSR or change its names.

## Notifications

A Managed Certificate's Subscribers are told of upcoming expiry (14, 7 and 1 days before its current Certificate ends), Renewals that succeed or fail, failed Deployment Runs (the exit code, not the script's output), its Agent going offline and Approval decisions (on a proposal or a name change). Subscribers are users, Teams (their members at the time) and notification channels; there are none by default, and being one shows a user nothing more in the portal. Owners and Organization Administrators change them (`/api/organizations/{orgId}/managed-certificates/{id}/subscribers`, or the Notifications tab of the Managed Certificate). Organization Administrators configure the channels (`/api/organizations/{orgId}/notification-channels`, or Notification channels under Administration): an email address, or a webhook (https, to a host that is not localhost or an internal address) that is posted each notice as JSON (`"schema": "certificate-platform.notice/1"`, with the event, the Managed Certificate and the event's detail). A webhook's URL is a Secret, never shown again but for its host. Subscriber and channel changes are audited, and whoever leaves the Organization, a deleted Team and a removed channel stop being Subscribers.

Notices are queued with the change they tell of and sent by a pass the server runs once a minute (`notifications.tick()`), which also notices silent Agents and Certificates nearing their end. One that cannot be sent is tried again after 1, 5 and 30 minutes, 2 and 6 hours, then given up. Mail goes through the server's `Mailer`; in development that is the console.

## Database schema

Drizzle ORM is the data layer; Better Auth uses it through its Drizzle adapter.

- Better Auth's tables come from its CLI: after changing plugins in `server/src/auth.ts`, run `bun run auth:generate` (writes `server/src/db/auth-schema.ts`; do not edit it by hand).
- The platform's own tables are in `server/src/db/schema.ts`.
- `bun run db:generate` turns the schema into a SQL migration in `server/drizzle/` (add `--custom` for hand-written SQL such as triggers). Migrations are applied on server start, or with `bun run migrate`.

## Check

```bash
bun run typecheck
bun run test          # Seam A: the Hono app in-process against the real Postgres (TEST_DATABASE_URL overrides the default), Pebble and BIND
(cd agent && go vet ./... && go test ./...)   # Seam B: the Agent against a stub platform built from the contract
```

Pebble, Let's Encrypt's ACME test server, stands in for the CA (`docker compose up -d pebble`; `PEBBLE_DIRECTORY` overrides `https://localhost:14000/dir`). The tests trust its root, `server/test/pebble/minica.pem`. Pebble checks DNS-01 challenges against BIND (`-dnsserver bind:53` in `docker-compose.yml`), so issuing in the tests runs the real path: the platform publishes the challenge record through an RFC 2136 DNS Provider, and the CA reads it back from the same server.

BIND, built from `docker/bind` (`docker compose up -d --build bind`), is the RFC 2136 DNS server that the DNS Provider tests update with TSIG-signed requests (`BIND_HOST` and `BIND_PORT` override `127.0.0.1:5354`). Its image keeps its config and zones in volumes, so after changing `docker/bind` recreate it with `docker compose up -d --build --force-recreate -V bind`.

### Connecting the local BIND as a DNS Provider

To try the DNS Providers page against this BIND, add a provider (Administration → DNS Providers → Add a DNS Provider) with these values:

| Field | Value |
|---|---|
| Type | RFC 2136 |
| Name | anything, such as `Local BIND` |
| Zone | `rfc2136.test` |
| Server | `127.0.0.1` (use `host.docker.internal` if the platform itself runs in a container) |
| Port | `5354` |
| TSIG key name | `certs-test` |
| TSIG algorithm | `hmac-sha256` |
| TSIG key secret | `dGVzdC10c2lnLWtleS1mb3ItdGhlLXJmYzIxMzYtdGVzdHM=` |

Leave "Where it runs" empty, so the platform talks to BIND itself. "Test" on the new row publishes a throwaway TXT record at `_acme-challenge.rfc2136.test` and removes it again, and says "The connection works." The secret is the fixed test key in `docker/bind/named.conf`; nothing real is behind it. The zone `readonly.test` takes no updates, so a provider for it reports a refusal.

For your own BIND, the key name, algorithm and secret are the `key "…" { algorithm …; secret "…"; };` block of its configuration, and the key must be allowed to update TXT records in the zone (`allow-update` or `update-policy`).

## Secrets

ACME account keys and DNS Provider credentials (an RFC 2136 provider's TSIG key) are write-only secrets: encrypted under a data key per Organization, which a KMS wraps (`server/src/kms.ts`, `server/src/secrets.ts`). No route returns a secret; they can be replaced or tested. Development and tests use the local KMS, keyed by `LOCAL_KMS_KEY` (32 bytes, base64); AWS KMS and Azure Key Vault are to be added behind the same `Kms` interface.

Better Auth's organization endpoints (`/api/auth/organization/*`) are served as they are, from an allowlist in `server/src/organization-changes.ts`: invitations, members and roles, and Teams. Reads go straight to Better Auth; each change runs on a transaction of ours (`server/src/unit-of-work.ts`), with Better Auth's organization hooks writing the Audit Event and enforcing the platform's rules in the same transaction (`server/src/organization-changes.ts`). Endpoints that skip those hooks (`leave`) or that the platform does not offer (updating or deleting an Organization) answer 404. The platform's own routes (inventory, audit, the Teams overview) check permissions with `server/src/authorization.ts`; both read the roles in `server/src/permissions.ts`.

## UI components

shadcn/ui components are added only through its CLI, from the `web/` workspace:

```bash
cd web && bunx --bun shadcn@latest add <component name>
```

The root `package.json` pins `express` to 5.2.1 (`overrides`) because the published `express@5.3.0` tarball was missing when this was set up, which broke the CLI's install. Remove the override once 5.3.0 installs again.
