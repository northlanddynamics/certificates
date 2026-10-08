# 02: Members, roles and Teams

**What to build:** An Organization Administrator can invite users as Member, Approver or Organization Administrator, change their roles, create Teams and manage Team membership, and remove users from the Organization.

**Blocked by:** 01 (Walking skeleton)

**Status:** ready-for-agent

- [ ] Invitations assign one of Member, Approver or Organization Administrator.
- [ ] Roles can be changed by an Organization Administrator, and only by one.
- [ ] Teams can be created, renamed and deleted, and users added or removed.
- [ ] Removing a user from the Organization revokes their access and removes them from every Managed Certificate's Owners and Subscribers (once those exist; the removal hook is in place).
- [ ] A single authorization check ("can this actor do this action on this resource in this Organization?") is the only way other modules ask about permissions.
- [ ] Role changes, Team changes and removals are audited.
