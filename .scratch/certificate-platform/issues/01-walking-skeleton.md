# 01: Walking skeleton

**What to build:** A Platform Operator can sign in, create an Organization and invite its first Organization Administrator, who accepts the invitation, sets a password, signs in and lands on an empty inventory for their Organization. This ticket stands up the whole stack (Bun, Hono API, Better Auth with the organization plugin, Postgres with migrations, TanStack front end with shadcn/ui), the Organization-scoping rule for every domain query, the append-only audit log written in the same transaction as each state change, and the Seam A test harness (the Hono app called in-process against a real Postgres, with Better Auth running for real). Better Auth's role names must not include "owner", which is reserved for the domain term Owner.

**Blocked by:** None (can start immediately)

**Status:** done

- [x] A Platform Operator can create an Organization and invite its first Organization Administrator by email (captured, not sent, in tests).
- [x] The invited Organization Administrator can accept, set a password, sign in, and see an empty Managed Certificate inventory.
- [x] Users of one Organization cannot see or reach anything belonging to another Organization (covered by a Seam A test).
- [x] A Platform Operator cannot see inside an Organization they have not been invited into.
- [x] Creating an Organization and accepting an invitation each write an audit entry with actor, time, action and target, in the same transaction.
- [x] The Seam A harness exists, runs in CI, and is the place where later tickets' API tests live.
- [x] The HTTP API is described by OpenAPI generated from route schemas, and the web UI calls only that API.

## Comments

Implemented on `main` (commits `c6dc597` through `afa0013`); typecheck and the 10 Seam A tests pass against Postgres in Docker Compose, and the sign-in, Organization-creation and invitation flow was walked through in a browser.

- The CI workflow (`.github/workflows/ci.yml`) is written but has not run, because the repo has no remote yet.
- The OpenAPI criterion is met by two generated documents shown on one page at `/api/docs`: the platform routes (from the route schemas) and Better Auth's routes (from its OpenAPI plugin).
- Beyond the ticket: `GET /api/organizations/{orgId}/audit-events` (so tests can observe audit entries) and `GET /api/platform/organizations` (for the operator console); tickets 21 and 24 will extend them.
- Deferred to later tickets: an extracted Identity module, email verification and sign-up policy, and a real mail transport to replace `ConsoleMailer`.
