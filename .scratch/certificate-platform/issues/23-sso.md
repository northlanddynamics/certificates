# 23: SSO

**What to build:** An Organization Administrator can configure a SAML (for example Ping) or OIDC connection that belongs to their Organization. Users signing in through it for the first time are provisioned just in time as Members. An Organization Administrator can require SSO, blocking password sign-in for the Organization's users.

**Blocked by:** 02 (Members, roles and Teams)

**Status:** done

- [x] An Organization Administrator can create, edit and test a SAML or OIDC connection; each connection belongs to exactly one Organization.
- [x] First sign-in through SSO creates the user as a Member of that Organization.
- [x] Requiring SSO blocks password sign-in for that Organization's users.
- [x] SSO configuration and policy changes are audited.

## Comments

- Implemented with Better Auth's SSO plugin (`@better-auth/sso`), which runs the sign-in itself: `POST /api/auth/sign-in/sso` (by email, which picks the connection of its domain), the OIDC callback, and the SAML ACS and SP metadata. Its own provider endpoints (`/sso/register`, `/sso/update-provider` and the rest) are disabled: they ask for its built-in "owner" and "admin" roles, which the platform does not use, and write no Audit Events.
- Connections are the platform's routes, `GET`/`POST /api/organizations/{orgId}/sso-connections`, `PATCH`/`DELETE …/{connectionId}` and `POST …/{connectionId}/test`, under the `ssoConnection` permission (Organization Administrators only), in `server/src/sso-connections.ts`. They write the plugin's `sso_provider` rows on the unit of work, with `sso_connection.created`, `changed`, `deleted` and `tested`. An OIDC connection is the issuer, client ID and client secret; its endpoints are taken from the discovery document when it is added (outside the transaction), and a test fetches the document again. A SAML connection is the IdP's entity ID, SSO URL and signing certificate; assertions must be signed, carry timestamps, answer a request the platform made (no IdP-initiated sign-in), and the test checks that the certificate is valid now. The platform's entity ID for a SAML connection is its SP metadata URL. The client secret is never returned nor audited.
- Each connection has one email domain, unique across all Organizations. It signs in only addresses in that domain or its subdomains, and links to an existing account only when that user is a member of its Organization (`validateUserInfo`, `server/src/sso-sign-in.ts`). Which identity provider a connection trusts (OIDC issuer or client ID, SAML entity ID) cannot change once anyone has signed in through it; a new secret or certificate can.
- Just-in-time provisioning: a user's first sign-in through a connection makes them a Member of its Organization, on the unit of work, audited as `member.provisioned`. Only the first sign-in does this, so a member who is removed is not added back by signing in again. A user with a pending invitation to that Organization is left to accept it, so that they get the role they were invited to.
- Requiring SSO is part of the Login Policy (`PUT /api/organizations/{orgId}/login-policy` with `{ requireSso }`, audited as `login_policy.changed`). While it is on, the Organization's members get a session only from an SSO sign-in through a connection of an Organization of theirs that requires it. Password and passkey sign-in are refused with 403 `SSO_REQUIRED` (a `databaseHooks.session.create.before` hook). Platform Operators are exempt, so that someone can still get in if an identity provider fails. To avoid a lockout, requiring SSO is refused unless the Organization has a connection and the administrator turning it on has signed in through one of its connections. Its last connection cannot be deleted while SSO is required.
- Web: an "SSO connections" page under Administration (add, edit, test, delete, and what to give the identity provider), a "Require SSO" checkbox on the Login policy page, and "Sign in with SSO" on the sign-in page, which uses the email entered there. A sign-in that the IdP or the platform refuses comes back to the sign-in page, which shows the error.
- Tests: `server/test/sso.test.ts` signs in through an OIDC IdP double (`oidc-idp-double.ts`, ID tokens signed with `jose`) and a SAML IdP double (`saml-idp-double.ts`, `samlify`). Both are devDependencies.
- Not done here:
  - Requiring SSO does not end sessions that were already signed in by password; they last until they expire.
  - A connection's domain is the one its Organization Administrator gives. The platform records it as verified and does not prove ownership by DNS (the plugin's domain verification), so an administrator could claim a domain they do not own. The first connection to claim a domain blocks every other Organization from using it.
  - An OIDC IdP on a private network must have its origin in `TRUSTED_ORIGINS`, as Better Auth requires.
  - The client secret is stored in plain text in `sso_provider.oidc_config`, where the plugin reads it, not with `secrets.ts`.
  - The plugin's `sso_provider.user_id` cascades on delete: if a Platform Operator deletes the user who created a connection, the connection goes too, without an Audit Event.
  - SAML Single Logout, IdP metadata XML upload, signed AuthnRequests, encrypted assertions and attribute mapping are not offered. The email comes from an `email` attribute or the NameID, and the name from `givenName`/`surname` or `displayName`.
