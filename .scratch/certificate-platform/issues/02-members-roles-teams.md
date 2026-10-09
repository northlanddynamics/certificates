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

Implemented on `main`; typecheck and the 41 Seam A tests pass. The People page was built and typechecked but not exercised in a browser.

- Better Auth's organization endpoints are served as they are (`/api/auth/organization/*`, from an allowlist in `server/src/app.ts`) and the web UI calls them directly: invite, accept, reject and cancel invitations, list and remove members, change roles, and Team CRUD and membership. The platform adds no wrapper routes for them.
- Each change runs on a database transaction of ours (`server/src/unit-of-work.ts`); Better Auth's organization hooks write the audit entries on that transaction, so a change and its audit entry commit or roll back together (Better Auth itself opens no transaction). A refused or failed change rolls back and sends no mail.
- Rules added as hooks: only our three roles may be assigned (Better Auth otherwise accepts its built-in "owner" and "admin"), only pending invitations can be cancelled, Team names are unique per Organization ignoring case, a repeat Team add is not audited again, and removing a user (or accepting an invitation) cancels other pending invitations to the same address. `memberRemovalHooks` (`server/src/member-removal.ts`) runs in the removal transaction; nothing registers one yet (tickets 05 and 07 add the Owner and Subscriber cleanup).
- Concurrency: changes lock the actor's memberships (so a concurrently demoted or removed administrator cannot finish an in-flight change), and role changes and removals lock the administrators, so two concurrent changes cannot leave an Organization with none. A unique index allows one membership per user per Organization, and another one Team name per Organization.
- Authorization: roles and permissions are defined once, in `server/src/auth.ts`, and read by Better Auth and by `authorize(actor, orgId, permissions?)` (`server/src/authorization.ts`), which the platform's own routes (inventory, audit, Teams overview) call. It takes no resource argument yet; the per-resource rule for Members arrives with ticket 07.
- Refused because Better Auth would change state without running its hooks (so without an audit entry): invitations that carry Teams (accepting would add the user to them) and `resend` on a pending invitation. Add the hook or the audit before supporting either.
- Not served: Better Auth's `leave` (it removes a member without running its hooks, so no audit and no removal hook), updating and deleting an Organization, roles administration. `/api/auth/organization/*` answers 404 for them.
- Still custom, because Better Auth cannot: the Organization-scoping 404 on the platform's routes, the platform's Organization creation (the Platform Operator is not a member), the Teams-with-members overview (Better Auth lists a Team's members only to that Team's members, without emails), and the unique indexes.
- Beyond the ticket: invitations can be listed, cancelled and rejected; all roles can read the member and Team lists (needed to pick Owners later; reopen if Members should not see each other's emails); a People page for administrators.
- Behaviour that follows Better Auth: refusals are mostly 400 or 403 rather than 404 or 409 (a non-member gets 403 on organization endpoints), a spent or expired invitation is "not found", and adding someone to a Team they are already in is a no-op.
- Follow-up: ticket 28 (verify email before accepting an invitation). Known gap: invitation expiry uses the real time (Better Auth's), not the injectable test clock.
