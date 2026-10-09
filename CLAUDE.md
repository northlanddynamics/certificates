## Agent skills

### Issue tracker

Issues and specs live as local markdown files under `.scratch/<feature>/`. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`, recorded as a `Status:` line in each issue file. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.

## Front end

### shadcn/ui components

Add shadcn/ui components only through the CLI, run from `web/`: `bunx --bun shadcn@latest add <component name>`. Never hand-write or copy-paste a component into `web/src/components/ui/`.

## Authentication

Use Better Auth for auth. Use Better Auth client for front end. Use the Better Auth skill to validate assumptions on auth.

## Better Auth

Identity, Organizations, Teams, roles and invitations are Better Auth's job. Reach for its options and API before writing our own; custom code is for what it cannot do (see `server/src/unit-of-work.ts`).

- Read the docs for the installed version (1.7): index at `https://better-auth.com/docs/llms.txt` (v1.6 at `/docs/1.6/llms.txt`); fetch a page's `.md` URL. Its docs MCP server is `https://mcp.better-auth.com/mcp`.
- The docs are incomplete. Check `node_modules/better-auth/dist/plugins/organization/` for what an endpoint really does: the last-Organization-Administrator guard and the Team clean-up on removal are in the source, not the docs, the plugin opens no database transaction, and it accepts its built-in role names ("owner", "admin") wherever a role is assigned.
- Its organization endpoints are served as they are under `/api/auth/organization/*`, from an allowlist in `server/src/app.ts`; changes run through `UnitOfWork.handle` (our transaction, audit written by its hooks). Add a rule or an audit entry as a hook there, not as a wrapper route. Expose a new endpoint only after checking it runs the hooks (`leave` does not).
- Permissions live only in the roles in `server/src/auth.ts`; the platform's own routes ask with `authorize` (`server/src/authorization.ts`).
