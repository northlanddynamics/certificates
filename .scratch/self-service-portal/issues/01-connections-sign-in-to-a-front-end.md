# 01: Connections say which front end they sign in to

**What to build:** An Organization Administrator says, for each SSO Connection, whether it signs in to the Console or the Self-Service Portal. An email domain can then have one connection for each front end, so the identity provider can publish two SAML apps. Signing in by email finds the connection for the front end being signed in to. Existing connections keep working, as Console connections.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] SSO Connections gain `signsInTo` (`console` | `portal`), stored as an additional field on Better Auth's SSO provider table beside `name`. It is required on create, can be changed on update, and is returned when connections are read.
- [ ] Existing connections are migrated to `signsInTo: console`.
- [ ] A domain may have at most one connection per `signsInTo`; a second for the same front end is refused (409).
- [ ] All connections for a domain belong to one Organization: a domain held by another Organization is refused, whatever the front end.
- [ ] A connection whose Organization already has a verified connection for the same domain is created verified. Otherwise its TXT record is required as today, and another Organization's verified connection proves nothing.
- [ ] A new unauthenticated route takes an email and a front end and returns the `providerId` of the domain's connection for that front end, else its other connection, else 404.
- [ ] The sign-in page resolves the connection through that route, then signs in with Better Auth's SSO sign-in by `providerId` rather than by email.
- [ ] Each connection is shown the SP entity ID, ACS URL and start URL (its front end's sign-in page, naming the connection) to give the identity provider.
- [ ] The connections list shows which front end each connection signs in to; the add and edit forms ask for it (components through the shadcn CLI).
- [ ] The create and change Audit Events include `signsInTo`.
- [ ] Harness tests with the SAML and OIDC IdP doubles cover: the field and its migration; per-front-end uniqueness; the one-Organization rule; inherited domain proof; the resolve route and its fallback; signing in through each of two connections on one domain; and the Audit Events.
