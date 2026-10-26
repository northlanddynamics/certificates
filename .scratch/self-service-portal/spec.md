# Spec: Self-Service Portal

Status: ready-for-agent

## Problem Statement

The web app is built for the people who run certificates: Organization Administrators and Approvers. Most people in an Organization only need to do a few things: get a certificate for their app or server, renew it, and download it. The full web app makes them work through screens and settings meant for PKI specialists.

There is also no way to make the full web app something you must be invited to, while letting everyone else in. An Organization's IT team publishes apps in its identity provider (such as Ping) and assigns each one to a group of people. They want two tiles: "Certificate Platform", assigned to the PKI team, and "Certificate Self-Service", assigned to everyone. Today an email domain can have only one SSO Connection, and that connection makes anyone at the domain a Member when they first sign in. So the platform cannot tell a self-service sign-in from an administrative one, and it cannot keep people who were never invited out of the full web app.

## Solution

A **Self-Service Portal**: a second, simpler front end for the same platform, served from the same origin under its own path. It offers what a Member needs:
- requesting a Managed Certificate through a Certificate Profile;
- making the key in the browser;
- following a Proposal until it is decided;
- renewing, downloading and revoking what they own.

Everything in it goes through the same API, the same roles and the same Audit Events as the full web app, which this spec calls the **Console**. The portal is a different set of screens, not a second identity system, and not a different set of permissions.

Each SSO Connection now says which front end it **signs in to** (Console or Self-Service Portal) and **whom it admits**:
- **Anyone in its domain:** they become a Member on their first sign-in, with no invitation (today's behaviour).
- **Only members and the invited:** anyone else is turned away and pointed to the portal.

An email domain may have one connection for each front end, so the identity provider can publish two SAML apps with different assignments. A typical Organization has:
- a Self-Service connection that admits anyone in the domain;
- a Console connection that admits only members and the invited.

A session remembers which front end it signed in to, and signing in lands there. What anyone may do is still decided only by their role.

## User Stories

1. As an Organization Administrator, I want to say which front end an SSO Connection signs in to, Console or Self-Service Portal, so that each identity provider app opens the right one.
2. As an Organization Administrator, I want to add a second SSO Connection for an email domain that already has one, if it signs in to the other front end, so that our identity provider can publish two apps with different assignments.
3. As an Organization Administrator, I want a second connection for the same front end and domain refused, so that a sign-in never has two candidates.
4. As an Organization Administrator, I want a domain still to belong to only one Organization, whichever front end its connections sign in to, so that no Organization can claim another's users.
5. As an Organization Administrator, I want a new connection for a domain my Organization has already proven to need no new TXT record, so that adding the Self-Service connection is quick.
6. As an Organization Administrator, I want a connection for a domain my Organization has not proven to still need its TXT record, so that adding a front end does not weaken the domain proof.
7. As an Organization Administrator, I want to choose whether a connection admits anyone in its domain or only members and the invited, so that I control who may join through it.
8. As an Organization Administrator, I want a new Self-Service connection to admit anyone in its domain by default, so that self-service needs no invitations.
9. As an Organization Administrator, I want a new Console connection to admit only members and the invited by default, so that the Console is invitation-only unless I choose otherwise.
10. As an Organization Administrator, I want our existing connection to keep working as it does today after the upgrade, so that nobody is locked out by the change.
11. As an Organization Administrator, I want to change a connection's front end and admission later, so that I can rearrange our sign-in as our identity provider changes.
12. As an Organization Administrator, I want each connection's front end and admission recorded in the Audit Events for creating and changing it, so that changes to who may sign in can be traced.
13. As an Organization Administrator, I want to be told the SP entity ID, ACS URL and start URL to give our identity provider for each connection, so that I can set up the identity provider app without guessing.
14. As an Organization Administrator, I want the connections list to show which front end each connection signs in to and whom it admits, so that I can see our setup at a glance.
15. As an employee assigned the Self-Service app in our identity provider, I want to sign in for the first time and land in the portal as a Member, without an invitation, so that I can get a certificate right away.
16. As an employee, I want to sign in to the portal by entering my work email, so that I do not need to know which connection to use.
17. As an employee, I want the identity provider tile to take me straight to the portal's sign-in, so that I do not need a bookmark.
18. As someone who was removed from the Organization, I want signing in through the Self-Service connection not to make me a member again, so that removal holds (today's rule).
19. As someone with a pending invitation, I want signing in through the Self-Service connection to leave my invitation for me to accept, so that I get the role I was invited to (today's rule).
20. As an invited Approver, I want to sign in through the Console connection before I am a member, so that I can accept my invitation.
21. As someone at the domain who is neither a member nor invited, I want the Console connection to turn me away with a message pointing me to the portal, so that I know where to go.
22. As an Organization Administrator, I want a refused Console sign-in to create no user account and no membership, so that turning people away leaves nothing behind.
23. As someone whose invitation to the Console has lapsed, I want a later Console sign-in to be refused rather than make me a Member, so that a members-only connection never admits anyone uninvited.
24. As a Member who joined through the portal, I want to be given a higher role on the Members page rather than invited, so that I keep my account and history.
25. As an Organization Administrator, I want the Members page to show how each member joined (invitation or a connection's first sign-in), so that I can tell self-service members from invited ones.
26. As an Organization that requires SSO, I want a sign-in through either of our connections to count, so that requiring SSO works with two front ends.
27. As a Platform Operator, I want to keep signing in with my own credentials whatever the connections say, so that someone can still get in when an identity provider fails (today's rule).
28. As a user who signed in through the Self-Service connection, I want the platform's root page to open the portal, so that I am not dropped into the Console.
29. As a user who signed in through the Console connection, I want to land in the Console, so that the people who run certificates see their tools.
30. As a user who signed in with a password or a passkey, I want to land in the Console as today, so that nothing changes for us.
31. As a user who followed a link to a specific page before signing in, I want to be taken back to that page, whichever front end it is in, so that links in notices and emails still work.
32. As a user whose role allows more than the portal offers, I want a link from the portal to the Console, so that I can reach the rest when I need it.
33. As a portal user, I want to see the Managed Certificates I own, directly or through a Team, and my Proposals, with what needs my attention first, so that I renew before anything expires.
34. As a portal user, I want to request a Managed Certificate by choosing from the Organization's enabled Certificate Profiles, described in plain words, so that I do not have to choose a CA or key settings.
35. As a portal user, I want to be told when there is no Certificate Profile I can request through, and where to get help, so that I am not stuck.
36. As a portal user, I want my names checked against the profile's name rules as I enter them, so that I fix mistakes before I submit.
37. As a portal user, I want the key made in my browser with the profile's key algorithm, and offered to me to download, or to paste my own CSR, so that the platform never holds my private key.
38. As a portal user, I want to review what I am asking for before I submit it, so that I submit the right request.
39. As a portal user, I want to see that my Proposal is waiting for Approval, and why it was rejected if it was, so that I know what happens next.
40. As a portal user, I want to download a Certificate by choosing what I am installing it on, so that I get the right format without knowing PEM from PKCS#7.
41. As an Owner, I want to renew from the portal, so that I do not need the Console for routine work.
42. As an Owner, I want to turn automatic Renewal on or off from the portal, so that I control how it renews.
43. As an Owner, I want to subscribe myself to a Managed Certificate's notices from the portal, so that I am told before it expires.
44. As an Owner, I want to propose a Name Change from the portal, so that I can add or change names, with Approval.
45. As an Owner, I want to revoke a Certificate from the portal when its key is exposed, so that I can act quickly.
46. As an Owner, I want to see what has happened to a Managed Certificate (requested, approved, issued, renewed), so that I can follow its history.
47. As an Approver who signed in through the portal, I want to see how many Proposals are waiting for me and a link to decide them in the Console, so that I do not miss them.
48. As a portal user, I want only the actions my permissions allow, as `/api/me` reports them, so that I am never offered what the API will refuse.
49. As a portal user, I want to reach the CSR Generator and the Viewer from the portal, so that I have the tools I need.
50. As a portal user, I want the portal to work on my phone, so that I can renew or download wherever I am.
51. As an Organization Administrator, I want everything done in the portal recorded in the same Audit Events as in the Console, so that the audit log is complete.

## Implementation Decisions

- **One platform, two front ends.**
  - The Self-Service Portal is part of the same web app, served from the same origin under its own path prefix, with its own layout (no Organization sidebar).
  - It shares the Better Auth client, the session cookie, the API and `/api/me`. Serving it from the same origin is what lets SAML's ACS response set a session cookie both front ends read, with no cross-subdomain cookies and no tokens.
  - It adds no permissions and no roles. It shows actions from the permissions `/api/me` reports, never from role names, as the Console does.
- **SSO Connection gains two fields:**
  - `signsInTo`: `console` | `portal`.
  - `admits`: `domain` (anyone in its domain; a non-member becomes a Member on first sign-in) | `members` (only existing members of its Organization and people with a pending invitation there).
  - Both are stored as additional fields on Better Auth's SSO provider table, next to `name`.
  - Both are accepted on create and update, returned when connections are read, and included in the create and change Audit Events.
- **Defaults and migration.**
  - On create, `signsInTo` is required. `admits` defaults to `domain` for `portal` and to `members` for `console`.
  - Existing connections are migrated to `signsInTo: console, admits: domain`, so behaviour is unchanged.
- **Domain uniqueness becomes per front end.**
  - A domain may have at most one connection per `signsInTo`.
  - All connections for a domain must belong to the same Organization. A domain held by another Organization is still refused, whatever the front end.
- **Domain proof is inherited within an Organization.**
  - A connection whose Organization already has a verified connection for the same domain is created verified.
  - Otherwise the per-connection TXT value is required as today.
  - The proof is about the Organization holding the domain, which is already proven, and stays once given.
- **Admission is enforced before any user is made.**
  - Better Auth's user-info validation (the platform's existing check that an address is in the connection's domain) also refuses a `members` connection's sign-in when the email belongs to no member of the connection's Organization and to no pending, unexpired invitation there.
  - The refusal carries its own error code, which the sign-in pages turn into "You don't have access to the Console. Request certificates in the Self-Service Portal."
  - Because this check runs before the user and session are made, a refusal leaves no account behind.
- **Provisioning respects admission.**
  - The existing first-sign-in provisioning (become a Member, unless invited or removed) runs only for `admits: domain` connections.
  - For `members` connections it does nothing, so a lapsed invitation never turns into a membership.
- **The session records its front end.**
  - Better Auth sessions gain an additional field, `signedInTo`.
  - It is set when the session is created: the connection's `signsInTo` for an SSO sign-in, `console` for password and passkey sign-ins.
  - It is never set from client input.
  - Impersonation sessions are `console`.
- **`/api/me` reports it** as `session: { signedInTo }`, so the web decides where to land without knowing about connections.
- **Resolving the connection at sign-in.**
  - With two connections per domain, Better Auth's lookup by email domain is ambiguous, so sign-in by email must name the connection.
  - A new unauthenticated platform route takes an email and a front end and returns the connection's `providerId`. It returns the domain's connection for that front end, else its other connection, else not found.
  - The Console and portal sign-in pages call it, then Better Auth's SSO sign-in with that `providerId`.
  - The route reveals no more than Better Auth's own email sign-in already does: whether a domain has SSO.
- **Start URL.** Each connection is shown a start URL for its identity provider tile: the sign-in page of its front end, naming the connection. Signing in from it is SP-initiated; IdP-initiated SAML stays off.
- **Login Policy is unchanged.** Requiring SSO already accepts a sign-in through any connection of an Organization that requires it.
- **Landing is one pure web function.**
  - Inputs: the session's `signedInTo` and the path that was asked for.
  - It returns where to go:
    - a safe asked-for path, whichever front end it is in (built on the existing sign-in redirect rules);
    - otherwise the root of the session's front end.
  - The Console's root page sends a `portal` session to the portal root. Nothing else redirects between the front ends.
- **Portal screens.** They are built from the existing endpoints, with no new server behaviour beyond the above:
  - Home: what needs attention, my Managed Certificates and Proposals.
  - Request through a Certificate Profile. Steps: what it's for, names with live name-rule checks, key (CSR Generator or pasted CSR), review.
  - Managed Certificate detail: download by target, renew, Renewal Policy toggle, self-subscription, Name Change, Revocation, history.
  - Links to the CSR Generator and the Viewer.
  - Approvers see a count of waiting Proposals and a link to the Console's Approvals.
  - Requests in the portal go only through Certificate Profiles.
  - Components come from shadcn/ui via the CLI.
- **Members page** shows how each member joined: from the existing `member.provisioned` and invitation Audit Events, or from a stored field if reading the audit log there is too slow.
- **Domain language.** Add **Self-Service Portal** and **Console** to `CONTEXT.md`. Update **SSO Connection**: one per email domain per front end, with what it admits. Record the decision "a second front end, not a second identity" as a new ADR.

## Testing Decisions

- A good test checks external behaviour only: API responses, who ends up a member and with which role, what `/api/me` reports, and Audit Events. It does not check how the code is arranged.
- **Seam 1, the main one:** the HTTP API through the existing server harness, with the SAML and OIDC identity provider doubles, as the existing SSO tests do. It covers:
  - creating and changing connections with `signsInTo` and `admits`, the defaults, and their Audit Events;
  - one connection per domain per front end, and a domain still held by one Organization;
  - domain proof inherited from a verified sibling in the same Organization, and not from another Organization's;
  - migrated connections behaving as before;
  - resolving a connection from an email and a front end, including the fallback;
  - a `domain` connection making a newcomer a Member, and still respecting pending invitations and removals;
  - a `members` connection admitting members and the invited, refusing everyone else with its error code and making no user, and refusing after an invitation lapses;
  - `signedInTo` reported by `/api/me` for SSO, password, passkey and impersonated sessions;
  - requiring SSO satisfied by either connection;
  - Platform Operators unaffected.
- **Seam 2:** the pure landing function, tested as the existing sign-in redirect web test does: the asked-for path wins when safe; otherwise the root of the session's front end; and a `portal` session at the Console root goes to the portal.
- No browser tests of the portal screens; they use existing endpoints whose behaviour is already tested.
- Prior art:
  - `server/test/sso.test.ts` with its IdP doubles;
  - `server/test/members-roles-teams.test.ts`;
  - `server/test/organization-changes.test.ts`;
  - `server/test/sign-in-redirect-web.test.ts`.

## Out of Scope

- Roles from identity provider groups or attributes; roles are given by invitation or on the Members page.
- SCIM provisioning and deprovisioning.
- IdP-initiated SAML.
- The platform acting as an identity provider (SAML or OIDC) for a portal hosted elsewhere.
- Serving the portal from another host or subdomain.
- Deciding Proposals inside the portal; Approvers decide in the Console.
- Requests that bypass Certificate Profiles from the portal.
- Deployments, Agents, Private CAs, Enrollment Profiles and other administration in the portal.
- Changing where password and passkey sign-ins land.
- Branding or theming the portal per Organization.

## Further Notes

- Wireframes: https://claude.ai/artifact/8Bxg15BtFWctqJZPAHAptm (architecture, Console sign-in settings, who each connection admits, portal sign-in, home, request steps and certificate detail).
- The split between front ends is about what people see, not what they may do. A `portal` session that opens a Console page sees what its role allows there and nothing more. The security boundary is the role, enforced by the API.
- Better Auth facts this relies on, checked in the installed SSO plugin (1.7.7):
  - its SSO sign-in accepts a `providerId` instead of an email;
  - each SAML connection has its own ACS URL and SP metadata;
  - IdP-initiated SAML is off unless enabled;
  - the provisioning callback runs after the session is made, so admission must be enforced earlier, in user-info validation.
