# Certificate platform

Domain language: [CONTEXT.md](CONTEXT.md). Spec and tickets: `.scratch/certificate-platform/`.

## Develop

```bash
docker compose up -d --wait        # Postgres on localhost:5433 (databases: certs, certs_test)
bun install
export DATABASE_URL=postgres://postgres:postgres@localhost:5433/certs
export AUTH_SECRET=$(openssl rand -hex 32)
export OPERATOR_EMAIL=operator@example.com OPERATOR_PASSWORD='a-long-password'   # creates the Platform Operator
bun run dev:server                 # API on :3000, applies migrations on start
bun run dev:web                    # UI on :5173, proxies /api to :3000
```

Invitation emails are printed to the server console in development.

## Database schema

Drizzle ORM is the data layer; Better Auth uses it through its Drizzle adapter.

- Better Auth's tables come from its CLI: after changing plugins in `server/src/auth.ts`, run `bun run auth:generate` (writes `server/src/db/auth-schema.ts`; do not edit it by hand).
- The platform's own tables are in `server/src/db/schema.ts`.
- `bun run db:generate` turns the schema into a SQL migration in `server/drizzle/` (add `--custom` for hand-written SQL such as triggers). Migrations are applied on server start, or with `bun run migrate`.

## Check

```bash
bun run typecheck
bun run test          # Seam A: the Hono app in-process against the real Postgres (TEST_DATABASE_URL overrides the default)
```

API contract: `GET /api/openapi.json`. Identity routes under `/api/auth/*` belong to Better Auth.
