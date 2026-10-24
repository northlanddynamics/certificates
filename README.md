# Certificate platform

Domain language: [CONTEXT.md](CONTEXT.md). Spec and tickets: `.scratch/certificate-platform/`.

## Develop

```bash
make dev    # Docker services, dependencies, a generated .env, then the API (:3000) and the web UI (:5173); Ctrl-C stops both
make help   # the other targets: setup, server, web, migrate, creds, test, check, down, clean, and agent-build, agent-test, agent-register, agent-run, agent-reset for a local Agent
```

`make dev` writes `.env` once (generated `AUTH_SECRET`, `LOCAL_KMS_KEY` and Operator password; `make creds` shows the Operator's) and keeps it: `LOCAL_KMS_KEY` wraps each Organization's data key, so a new one would make stored secrets in an existing database unreadable. `make clean` resets both the database and `.env`. To run an Agent against it, make a registration token on the Agents page, then `make agent-register TOKEN=agt_...` once and `make agent-run` in another terminal (state under `.dev/`). The same steps by hand:

```bash
docker compose up -d --wait        # Postgres on localhost:5433 (databases: certs, certs_test); Pebble on localhost:14000 (and :14001 requiring EAB); BIND on localhost:5354
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

An Organization Administrator can have Agents relay a DNS Provider (`PUT /api/organizations/{orgId}/dns-providers/{id}/relay`), so DNS the hosted platform cannot reach, such as on-prem BIND or Infoblox, still serves DCV. Publishing, removing and testing then become work items (`dns.present`, `dns.cleanup`, `dns.test`) for one online relay Agent, which carries them out with its own RFC 2136 and Infoblox providers (`agent/internal/dnsrelay`, which behave as `server/src/issuance/dcv/rfc2136.ts` and `server/src/issuance/dcv/infoblox.ts` do) and reports the result; an offline Agent is passed over, and one that does not answer within 45 seconds is given up on for the next. The provider's credentials are put into a work item only when the Agent is given it, are never stored in it, and are never shown. `AGENT_LONG_POLL_SECONDS` (default 20) is how long an idle poll waits for work, so that relayed operations reach an Agent at once; set it to 0 to answer polls immediately.

Organization Administrators keep a library of Deployment Scripts (Bash or PowerShell, `/api/organizations/{orgId}/deployment-scripts`) that Agents will run to put a Certificate to use (ADR 0004). A script is a name and an interpreter; each upload adds an immutable version identified by the SHA-256 of its exact content (up to 256 KiB), earlier versions stay viewable (the database refuses to change or delete a version), and every upload is audited with the hash. No other role holds `deploymentScript.upload` or `.read`. How to write one, what it is given and how it declares Deployment Parameters is in [docs/deployment-scripts.md](docs/deployment-scripts.md).

An Organization Administrator sets up a Deployment in one call (`POST /api/organizations/{orgId}/deployments`, or Deployments under Automation in the web app): the Agent, the Managed Certificate's names, key algorithm and Renewal Policy, and a Deployment Script version, which is pinned. It makes a Managed Certificate with Key Custody: Agent, bound to that one Agent and that Deployment, with no Approval. The platform never holds the key (ADR 0002):

1. The Agent is asked (`deployment.generate_key`) to make the key, in `<state dir>/keys/<Managed Certificate>/`, readable only by its service account, and sends back only a CSR. The platform checks it as it does an Owner's CSR and begins the Issuance.
2. When the Certificate is stored the Agent is given it and the script (`deployment.run`). It runs the script only if the SHA-256 of the content is the hash that was audited (ADR 0004), and only if the Certificate is the one named and its key is on the host. The script gets `CERT_KEY_FILE`, `CERT_LEAF_FILE`, `CERT_CHAIN_FILE` and `CERT_FULLCHAIN_FILE` (paths; the chain is the intermediates, the full chain the leaf and the chain), and `CERT_MANAGED_CERTIFICATE_ID`, `CERT_DEPLOYMENT_ID`, `CERT_FINGERPRINT`, `CERT_NAMES` (comma-separated) and `CERT_NOT_AFTER`, and a `DEPLOY_PARAM_` variable for each Deployment Parameter the script version declares and the Deployment gives a value (plain text, never a secret: ADR 0010). Bash scripts run with `bash`, PowerShell ones with `pwsh` (Linux) or `powershell.exe` (Windows); a script that runs longer than ten minutes is stopped.
3. The Agent reports a Deployment Run: when, the Certificate's fingerprint, the exit code (none when the script was not started) and its output, kept up to 32 KiB. `POST .../deployments/{id}/runs` has the Agent run the script again for the current Certificate without renewing; `GET` on it lists the runs; when the Agent could not make the key, it asks for the key again.

One Agent can serve many Deployments. Setting one up, the key, each run and each request to run again are Audit Events. Work for a Deployment waits for its Agent however long it is away (the work items are durable), and one the Agent was given but never reported on, because it stopped, is given again after 15 minutes. Until a Deployment can have the Agent make a new key, a Managed Certificate it holds the key for cannot upload a CSR or change its names.

## Notifications

A Managed Certificate's Subscribers are told of upcoming expiry (14, 7 and 1 days before its current Certificate ends), Renewals that succeed, fail or are blocked by a disabled Certificate Profile (once, until unblocked), failed Deployment Runs (the exit code, not the script's output), its Agent going offline and Approval decisions (on a proposal or a name change). Subscribers are users, Teams (their members at the time) and notification channels; there are none by default, and being one shows a user nothing more in the portal. Owners and Organization Administrators change them (`/api/organizations/{orgId}/managed-certificates/{id}/subscribers`, or the Notifications tab of the Managed Certificate). Organization Administrators configure the channels (`/api/organizations/{orgId}/notification-channels`, or Notification channels under Administration): an email address, or a webhook (https, to a host that is not localhost or an internal address) that is posted each notice as JSON (`"schema": "certificate-platform.notice/1"`, with the event, the Managed Certificate and the event's detail). A webhook's URL is a Secret, never shown again but for its host. Subscriber and channel changes are audited, and whoever leaves the Organization, a deleted Team and a removed channel stop being Subscribers.

Notices are queued with the change they tell of and sent by a pass the server runs once a minute (`notifications.tick()`), which also notices silent Agents and Certificates nearing their end. One that cannot be sent is tried again after 1, 5 and 30 minutes, 2 and 6 hours, then given up. Mail goes through the server's `Mailer`; in development that is the console.

## ACME CAs

A Managed Certificate is issued from an ACME CA or from one of a Private CA's Issuing CAs. Let's Encrypt Staging (`letsencrypt-staging`, the default) and Let's Encrypt Production (`letsencrypt-production`) are built in and read-only; an Organization Administrator registers the Organization's ACME Account with each under ACME accounts in the web app (`/api/organizations/{orgId}/acme-accounts`). They may also add a custom ACME CA by name and https directory URL, with optional External Account Binding and an Environment Tag (`/api/organizations/{orgId}/acme-cas`), which registers its account in the same step. Its directory URL and External Account Binding are fixed once added, and it cannot be deleted while a Managed Certificate or Certificate refers to it. How to add, tag, change and delete one is in [docs/acme-cas.md](docs/acme-cas.md).

## Certificate Profiles

An Organization Administrator defines Certificate Profiles (`/api/organizations/{orgId}/certificate-profiles`, or Certificate Profiles under Administration): each fixes the issuer, the key algorithms allowed and, for a Private CA, the validity, gives the starting Renewal Policy and may name a co-Owner Team and name rules. Any member proposes through one by choosing it in the New Managed Certificate dialog (`profileId`), leaving only the names and a CSR to give; a non-administrator's request is always a Proposal, and the requester becomes an Owner. The issuance settings are copied onto each Managed Certificate, while the name rules and whether the profile is enabled are checked live (ADR 0012): while a profile is disabled nothing is issued under it, Renewal included, until it is enabled again or a Managed Certificate is detached from it. An Organization may require its non-administrators to propose only through a profile. How to set one up, propose through one, disable it and detach from it is in [docs/certificate-profiles.md](docs/certificate-profiles.md).

## Private CAs: CRLs and their public routes

A Certificate issued from a Private CA names, in its CRL Distribution Point and AIA caIssuers, where relying parties fetch its Issuing CA's CRL and certificate; a platform-made Issuing CA names its root's the same way. They are served, DER-encoded, at `/pki/issuing-cas/{issuingCaId}/ca.crl` and `ca.crt` for each Issuing CA, and `/pki/roots/{privateCaId}/ca.crl` and `ca.crt` for a platform-made root, on `PKI_BASE_URL` (default `BASE_URL`), which is written into every certificate a Private CA signs, so choose it before issuing and do not change it. Each Issuing CA and each platform-made root publishes its first CRL when it is made. Revoking a Certificate reissues its Issuing CA's CRL in the same transaction, and a pass the server runs once a minute (`crls.tick()`) reissues each CRL at least 3 days before its `nextUpdate` (7 days after `thisUpdate`) and drops Certificates that have expired.

Deployment notes:

- These routes must be public: reachable by every relying party (servers, load balancers, RADIUS servers, browsers) with no authentication, no VPN and no IP allowlist. With the SCEP routes below, they are the platform's only unauthenticated routes outside `/api/auth`.
- They must be reachable over plain HTTP, and must not redirect to HTTPS: a relying party checking revocation must not need TLS, which would need a revocation check of its own. Set `PKI_BASE_URL` to an `http://` URL, such as `http://pki.example.com`. A TLS terminator or load balancer in front of the platform must pass `/pki/*` through over HTTP (no HTTPS redirect, no HSTS on that host). When the platform serves TLS itself (`TLS_CERT_FILE`), set `PKI_HTTP_PORT` (such as 80) and it also listens there over plain HTTP, answering only `/pki/*`. They are served over HTTPS too, on the main listener.

## Device enrollment (SCEP)

An Organization Administrator creates an Enrollment Profile on an active Issuing CA (`POST /api/organizations/{orgId}/enrollment-profiles`): the validity (365 days unless given, or 90 with a Shared Challenge; never past the Issuing CA's end), key usage (digitalSignature and keyEncipherment), extended key usages (clientAuth) and RSA key sizes of the Device Certificates it issues, and the Enrollment Validator kind that decides each request (`GET .../enrollment-validator-kinds` lists those the platform runs: `intune` and `shared_challenge`). The platform makes the profile an RA: a software RSA key held as a Secret, and a certificate the Issuing CA signs for it (ADR 0007). The profile's SCEP URL is `<BASE_URL>/scep/<publicId>`, an opaque id; `.../enrollment-profiles/{id}/ca-certificate?ca=root|issuing` downloads the certificate a device management platform's trusted certificate profile needs, and `caFingerprint` is the SHA-256 fingerprint of the CA certificate `GetCACert` serves, for SCEP profiles that check it.

A device enrolls there with `GetCACaps`, `GetCACert` (the Issuing CA, the RA certificate and the chain to the root) and `PKIOperation` `PKCSReq`, by POST or GET (also at `.../pkiclient.exe`, which Windows appends), served by [ts-scep](vendor/ts-scep/VENDORED.md). It gets a Device Certificate with the CSR's subject and subject alternative names and the profile's key usage, extended key usages and validity, and nothing else the CSR asks for; or FAILURE (`badRequest`) for a key the profile does not allow, a DNS name outside the Issuing CA's permitted names, an Issuing CA that no longer issues, or a request its validator refuses. Each Device Certificate is stored with its profile, apart from the Managed Certificates, with a `device_certificate.issued` Audit Event.

For the clients in the field it accepts RSA-OAEP key transport besides PKCS#1 v1.5 (Windows), AES, 3DES and single DES content encryption (micromdm's `scepclient` sends DES whatever it is offered; DES is never advertised), and requests signed with SHA-1; a CertRep uses the key transport its request did. `GetCACaps` advertises POSTPKIOperation, SHA-256, SHA-512, AES and SCEPStandard, and Renewal where the profile's Enrollment Validator allows it (`allowsRenewal` in the kinds list; Intune does not, `shared_challenge` does). Only there is a `RenewalReq` taken, signed by an unrevoked, unexpired Device Certificate of the same profile; elsewhere a device enrolls again with `PKCSReq`. A request whose transaction ID the profile has had before is answered as it was the first time, never issued twice, and so is `GetCertInitial`; a refusal that may not hold next time (the validator could not be asked, say) is not kept, so the device can send it again. The SCEP routes are rate limited per source address (120 requests a minute) and per profile (3000 a minute), answering 429 with `Retry-After` before anything else is looked at; behind a TLS terminator that sets `X-Forwarded-For`, set `TRUST_FORWARDED_FOR=true` so that devices are counted by the address it saw rather than its own. A test runs micromdm's `scepclient` (`scepclient` in `docker-compose.yml`, built from source) against the platform; it needs `-key-encipherment-selector`, so that it encrypts to the RA certificate alone.

The `intune` Enrollment Validator is configured with an Entra app's tenant ID and app ID (`validator.settings`) and its client secret (`validator.secret`, a Secret, never shown). The app needs the application permissions Intune `scep_challenge_provider` and Microsoft Graph `Application.Read.All`, with admin consent. Intune validates each request (its challenge is the CSR's `challengePassword`) and is told each outcome in the background; it vouches for names, so the profile takes no name rules. A device's Intune device ID is read from an `IntuneDeviceId://{{DeviceId}}` URI SAN, which the Intune SCEP profile should include. `POST .../enrollment-profiles/{id}/validator/test` gets both tokens and finds Intune's services without validating anything, so `scep_challenge_provider` is proven only by the first enrollment. When Intune retires, wipes or unenrolls a device, it queues its certificate for revocation; the platform downloads each tenant's queue at most hourly (Intune's cool-down), revokes what it finds with `cessationOfOperation`, puts it on the Issuing CA's CRL in the same change, and uploads a result for each request. The contract is in `docs/research/intune-scep-api.md`.

The `shared_challenge` Enrollment Validator is for Iru (formerly Kandji) and network gear, which can give no per-device challenge (ADR 0008). Creating such a profile makes its Shared Challenge, returned once as `sharedChallenge.challenge` in the create response; the platform keeps only its SHA-256 hash, so it is never shown again, nor in any Audit Event. A `PKCSReq` must carry it as its CSR's `challengePassword`, compared in constant time before its key or names are checked or the validator is asked; without it, or with a wrong one, it is refused (FAILURE `badRequest`, with `enrollment.refused`, whose reason never quotes what was sent). A `RenewalReq` needs no challenge: its signature by the device's current Device Certificate is the proof. The kind does not vouch for names, so what a holder of the challenge gets is bounded by the Issuing CA's permitted names and by name rules, if the profile has any, and by the profile's short default validity. To rotate it, `POST .../enrollment-profiles/{id}/shared-challenge/rotation` with `previousExpiresAt` returns a new one, once; the old one stays valid as the previous until then, so devices the device management platform has not yet reached keep enrolling, or until `POST .../shared-challenge/previous/retirement` ends it at once. A rotation is refused (409) while a previous one is still valid. Each Device Certificate records the Shared Challenge it was issued under (`sharedChallenge.id`; none for a renewal), so it shows when the previous one stops being used.

An Organization Administrator may also revoke a Device Certificate (`POST .../enrollment-profiles/{id}/device-certificates/{certificateId}/revocation`, with one of the reasons a Private CA takes); it is on the CRL once that succeeds.

Deployment notes: the platform must reach `login.microsoftonline.com`, `graph.microsoft.com` and the Intune service URLs Graph returns (`*.manage.microsoft.com`) over HTTPS. The SCEP routes must be public, reachable by devices from anywhere with no authentication, and served over HTTPS (Android requires it), so put `BASE_URL` on a TLS listener that devices can reach.

## Audit

Every change to an Organization's state is an Audit Event, written in the same transaction as the change. The log is kept for ever: no route changes or deletes one, and the database refuses to. Organization Administrators search it (`GET /api/organizations/{orgId}/audit-events`, or Audit log under Audit) by part of the actor's email or the action (`q`, in any case), actor (id or email), action (`team.created`, or `team.*` for a resource), target types (any of, comma-separated; `GET .../audit-events/target-types` lists those in the log) and id, and time range (`from` inclusive, `to` exclusive), oldest or newest first, a page at a time by `cursor`.

They also forward it to a SIEM (`/api/organizations/{orgId}/audit-forwarders`, or Audit forwarding under Administration): a webhook (https, to a host that is not internal, with an optional `Authorization` header such as an HTTP event collector's token; both are a Secret and only the host is shown) posted each event as JSON, or a syslog receiver over TLS (RFC 5425, port 6514 by default) written each event as an RFC 5424 message whose MSG is the JSON. Events follow the schema `certificate-platform.audit/1`, documented in [docs/audit-events.md](docs/audit-events.md). Every event recorded after a forwarder is added, its own creation included, is queued for it in the same transaction and sent by a pass the server runs every 30 seconds (`auditForwarding.tick()`), in the order of their ids (two changes committing at the same moment may arrive the other way round). A forwarder that cannot be reached is tried again after 1, 5 and 30 minutes, then every hour, and never given up: delivery is at least once, so a receiver may see an event twice (deduplicate by `id`). Adding and removing a forwarder are audited.

## Database schema

Drizzle ORM is the data layer; Better Auth uses it through its Drizzle adapter.

- Better Auth's tables come from its CLI: after changing plugins in `server/src/tenancy/auth.ts`, run `bun run auth:generate` (writes `server/src/platform/db/auth-schema.ts`; do not edit it by hand).
- The platform's own tables are in `server/src/platform/db/schema.ts`.
- `bun run db:generate` turns the schema into a SQL migration in `server/drizzle/` (add `--custom` for hand-written SQL such as triggers). Migrations are applied on server start, or with `bun run migrate`.

## Check

```bash
bun run typecheck
bun run test          # Seam A: the Hono app in-process against the real Postgres (TEST_DATABASE_URL overrides the default), Pebble and BIND
(cd agent && go vet ./... && go test ./...)   # Seam B: the Agent against a stub platform built from the contract
```

Pebble, Let's Encrypt's ACME test server, stands in for the CA (`docker compose up -d pebble`; `PEBBLE_DIRECTORY` overrides `https://localhost:14000/dir`). The tests trust its root, `server/test/support/pebble/minica.pem`. Pebble checks DNS-01 challenges against BIND (`-dnsserver bind:53` in `docker-compose.yml`), so issuing in the tests runs the real path: the platform publishes the challenge record through an RFC 2136 DNS Provider, and the CA reads it back from the same server.

A second Pebble, `pebble-eab` (`docker compose up -d pebble-eab`; `PEBBLE_EAB_DIRECTORY` overrides `https://localhost:14001/dir`), requires External Account Binding, as some commercial CAs do. It registers only accounts bound with the key id and HMAC key in `docker/pebble-eab/pebble-config.json`, which the tests know as `PEBBLE_EAB_KEY`.

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

ACME account keys, a custom ACME CA's External Account Binding HMAC key and DNS Provider credentials (an RFC 2136 provider's TSIG key) are write-only secrets: encrypted under a data key per Organization, which a KMS wraps (`server/src/platform/crypto/kms.ts`, `server/src/platform/crypto/secrets.ts`). No route returns a secret; they can be replaced or tested. Development and tests use the local KMS, keyed by `LOCAL_KMS_KEY` (32 bytes, base64); AWS KMS and Azure Key Vault are to be added behind the same `Kms` interface.

Better Auth's organization endpoints (`/api/auth/organization/*`) are served as they are, from an allowlist in `server/src/tenancy/organization-changes.ts`: invitations, members and roles, and Teams. Reads go straight to Better Auth; each change runs on a transaction of ours (`server/src/platform/unit-of-work.ts`), with Better Auth's organization hooks writing the Audit Event and enforcing the platform's rules in the same transaction (`server/src/tenancy/organization-changes.ts`). Endpoints that skip those hooks (`leave`) or that the platform does not offer (updating or deleting an Organization) answer 404. The platform's own routes (inventory, audit, the Teams overview) check permissions with `server/src/tenancy/authorization.ts`; both read the roles in `server/src/tenancy/permissions.ts`.

## UI components

shadcn/ui components are added only through its CLI, from the `web/` workspace:

```bash
cd web && bunx --bun shadcn@latest add <component name>
```

The root `package.json` pins `express` to 5.2.1 (`overrides`) because the published `express@5.3.0` tarball was missing when this was set up, which broke the CLI's install. Remove the override once 5.3.0 installs again.

It also pins `@peculiar/asn1-schema` so that ts-scep and `@peculiar/x509` share one ASN.1 schema registry; keep the lockfile to a single copy of each `@peculiar/asn1-*` package. `@peculiar/x509` 2.x needs `reflect-metadata` imported before it: the server's entry points and `web/src/main.tsx` import it first, and `bunfig.toml` preloads it for tests.
