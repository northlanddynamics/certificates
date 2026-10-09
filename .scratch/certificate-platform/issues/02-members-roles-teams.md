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

Implemented on `main`; typecheck and the 34 Seam A tests pass.

- Authorization: `server/src/authorization.ts` (`authorize(actor, orgId, action)`) is the one permission check; routes in `server/src/organization-routes.ts` (invitations, members, Teams) and the existing inventory and audit routes use it. It takes no resource argument yet; the per-resource rule for Members (own Managed Certificates only) arrives with ticket 07.
- Removal hook: `memberRemovalHooks` in `server/src/member-removal.ts` runs inside the removal transaction (a throwing hook rolls the removal back). Nothing registers one yet; tickets 05 and 07 add the Owner and Subscriber cleanup. Team memberships and active sessions are cleaned up directly.
- Beyond the ticket: the last Organization Administrator cannot be demoted or removed (409); Team names are unique per Organization, ignoring case (migration 0002); invitations can be listed and cancelled; inviting an existing member or a pending email is 409; all roles can read the member and Team lists (needed to pick Owners later; reopen if Members should not see each other's emails); Better Auth's `/api/auth/organization/*` endpoints answer 404 because they bypass audit and the removal hook; a People page for administrators in the web UI.
- Known gaps from review: `authorize` runs before the transaction, so an administrator demoted at the same moment can finish one in-flight mutation; an invitation accepted at the same moment as a new invitation to the same email can leave a member plus a pending invitation; pending invitations are not cancelled when a user is removed.
