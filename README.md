# Certificate platform

Domain language: [CONTEXT.md](CONTEXT.md). Spec and tickets: `.scratch/certificate-platform/`.

## Develop

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

## The Agent

`agent/` is the Go Agent, a separate module (`cd agent && go test ./...`). It only connects outbound over HTTPS, registers once with a single-use token that an Organization Administrator makes on the Agents page, and then polls the platform, authenticating with an identity certificate that it rotates before it ends.

```bash
agent register --platform https://certs.example.com --token agt_...   # or AGENT_REGISTRATION_TOKEN; once
agent run                                                             # as a service; state in /var/lib/certificate-agent or %ProgramData%\CertificateAgent
```

The Agent's protocol is the routes under `/api/agent`. Their OpenAPI contract is generated from the route schemas into `agent/contract/openapi.json` (`bun run contract:export`); a platform test fails while that copy is stale. Seam B runs the Agent against `agent/internal/platformstub`, a stub platform built from that contract, over real mutual TLS, with a clock the tests move; it holds both sides to the contract. The platform must run behind a TLS terminator that verifies Agents' client certificates and passes them in a header: see ADR 0005. `AGENT_GATEWAY_SECRET` makes the platform trust that header only from a terminator that sends the secret in `x-agent-gateway-secret`. `AGENT_LATEST_VERSION` sets the Agent version below which the Agents list flags an Agent as outdated.

An Organization Administrator can have Agents relay a DNS Provider (`PUT /api/organizations/{orgId}/dns-providers/{id}/relay`), so DNS the hosted platform cannot reach, such as on-prem BIND or Infoblox, still serves DCV. Publishing, removing and testing then become work items (`dns.present`, `dns.cleanup`, `dns.test`) for one online relay Agent, which carries them out with its own RFC 2136 and Infoblox providers (`agent/internal/dnsrelay`, which behave as `server/src/rfc2136.ts` and `server/src/infoblox.ts` do) and reports the result; an offline Agent is passed over, and one that does not answer within 45 seconds is given up on for the next. The provider's credentials are put into a work item only when the Agent is given it, are never stored in it, and are never shown. `AGENT_LONG_POLL_SECONDS` (default 20) is how long an idle poll waits for work, so that relayed operations reach an Agent at once; set it to 0 to answer polls immediately.

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

## Secrets

ACME account keys and DNS Provider credentials (an RFC 2136 provider's TSIG key) are write-only secrets: encrypted under a data key per Organization, which a KMS wraps (`server/src/kms.ts`, `server/src/secrets.ts`). No route returns a secret; they can be replaced or tested. Development and tests use the local KMS, keyed by `LOCAL_KMS_KEY` (32 bytes, base64); AWS KMS and Azure Key Vault are to be added behind the same `Kms` interface.

API reference: `GET /api/docs`, one Scalar page with two sources. "Platform" is the contract generated from our route schemas (`/api/openapi.json`); "Auth" is Better Auth's own routes, generated by its OpenAPI plugin (`/api/auth/open-api/generate-schema`). Identity routes under `/api/auth/*` belong to Better Auth. The page loads the Scalar script from a CDN.

Better Auth's organization endpoints (`/api/auth/organization/*`) are served as they are, from an allowlist in `server/src/organization-changes.ts`: invitations, members and roles, and Teams. Reads go straight to Better Auth; each change runs on a transaction of ours (`server/src/unit-of-work.ts`), with Better Auth's organization hooks writing the Audit Event and enforcing the platform's rules in the same transaction (`server/src/organization-changes.ts`). Endpoints that skip those hooks (`leave`) or that the platform does not offer (updating or deleting an Organization) answer 404. The platform's own routes (inventory, audit, the Teams overview) check permissions with `server/src/authorization.ts`; both read the roles in `server/src/permissions.ts`.

## UI components

shadcn/ui components are added only through its CLI, from the `web/` workspace:

```bash
cd web && bunx --bun shadcn@latest add <component name>
```

The root `package.json` pins `express` to 5.2.1 (`overrides`) because the published `express@5.3.0` tarball was missing when this was set up, which broke the CLI's install. Remove the override once 5.3.0 installs again.
