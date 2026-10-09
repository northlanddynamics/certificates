# 02: Members, roles and Teams

**What to build:** An Organization Administrator can invite users as Member, Approver or Organization Administrator, change their roles, create Teams and manage Team membership, and remove users from the Organization.

**Blocked by:** 01 (Walking skeleton)

**Status:** done

- [x] Invitations assign one of Member, Approver or Organization Administrator.
- [x] Roles can be changed by an Organization Administrator, and only by one.
- [x] Teams can be created, renamed and deleted, and users added or removed.
- [x] Removing a user from the Organization revokes their access and removes them from every Managed Certificate's Owners and Subscribers (once those exist; the removal hook is in place).
- [x] A single authorization check ("can this actor do this action on this resource in this Organization?") is the only way other modules ask about permissions.
- [x] Role changes, Team changes and removals are audited.

## Comments

Implemented on `main`; typecheck and the 38 Seam A tests pass.

- Better Auth does the work: its organization API (invitations and their acceptance, role changes, removal with Team clean-up, Team CRUD, the last-Organization-Administrator guard, invitation expiry) is called by our routes in `server/src/organization-routes.ts`. It runs on a database transaction of ours with Better Auth's organization hooks writing the audit entries (`server/src/unit-of-work.ts`), so each change and its audit entry commit or roll back together. The plugin opens no transaction itself, so this is what keeps ticket 01's guarantee.
- Authorization: roles and their permissions are defined once, in `server/src/auth.ts`, and read by both Better Auth and our `authorize(actor, orgId, permissions?)` (`server/src/authorization.ts`), the single check other modules call. It takes no resource argument yet; the per-resource rule for Members (own Managed Certificates only) arrives with ticket 07.
- Removal hook: `memberRemovalHooks` (`server/src/member-removal.ts`) runs inside the removal transaction (a throwing hook rolls the removal back). Nothing registers one yet; tickets 05 and 07 add the Owner and Subscriber cleanup.
- Still custom, because Better Auth cannot: the Organization-scoping 404, the platform's Organization creation (the Platform Operator is not a member, so Better Auth's create calls do not fit), unique indexes for one membership per user per Organization and one Team name per Organization ignoring case (Better Auth checks neither atomically), locking the Organization's administrators so concurrent changes cannot leave none, the Teams-with-members overview (Better Auth lists a Team's members only to that Team's members, without emails), and cancelling a user's pending invitations on removal.
- Beyond the ticket: invitations can be listed and cancelled; all roles can read the member and Team lists (needed to pick Owners later; reopen if Members should not see each other's emails); Better Auth's own `/api/auth/organization/*` endpoints answer 404 because they bypass the transaction and the audit; a People page for administrators.
- Behaviour that follows Better Auth: a spent, cancelled or expired invitation is "not found" (404); adding someone to a Team they are already in is a no-op.
- Follow-up: ticket 28 (verify email before accepting an invitation). Known gap: invitation expiry uses the real time (Better Auth's), not the injectable test clock.
