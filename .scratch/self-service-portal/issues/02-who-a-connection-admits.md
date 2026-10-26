# 02: Who a connection admits

**What to build:** An Organization Administrator chooses whether an SSO Connection admits anyone in its domain, who become Members on their first sign-in with no invitation, or only members and the invited. A typical Organization's Self-Service connection lets everyone in, and its Console connection lets in only people who were invited. Anyone else trying the Console connection is turned away and told to use the Self-Service Portal.

**Blocked by:** 01 (Connections say which front end they sign in to)

**Status:** ready-for-agent

- [ ] SSO Connections gain `admits` (`domain` | `members`), stored beside `signsInTo`, settable on create and update, and returned when connections are read.
- [ ] On create, `admits` defaults to `domain` for a `portal` connection and to `members` for a `console` one. Migrated connections are `admits: domain`, so they behave as before.
- [ ] A `members` connection refuses a sign-in whose email belongs to no member of its Organization and to no pending, unexpired invitation there. The check runs in Better Auth's user-info validation, beside the existing domain check, so a refusal creates no user and no session.
- [ ] The refusal has its own error code, which the sign-in page shows as "You don't have access to the Console. Request certificates in the Self-Service Portal."
- [ ] An invited person can sign in through a `members` connection before they are a member, and then accept the invitation.
- [ ] First-sign-in provisioning (making the user a Member unless they are invited or were removed) runs only for `admits: domain` connections. A `members` connection never makes anyone a Member, including after an invitation lapses.
- [ ] A `domain` connection still respects pending invitations and removals, as today.
- [ ] Requiring SSO is satisfied by a sign-in through either kind of connection. Platform Operators are unaffected.
- [ ] The create and change Audit Events include `admits`. The connections list shows whom each connection admits, and the forms ask for it.
- [ ] Harness tests cover: the defaults and migration; admission of members and the invited; refusal of everyone else, with no user made; a lapsed invitation being refused; `domain` connections unchanged; the Login Policy; and the Audit Events.
