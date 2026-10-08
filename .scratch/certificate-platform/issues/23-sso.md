# 23: SSO

**What to build:** An Organization Administrator can configure a SAML (for example Ping) or OIDC connection that belongs to their Organization. Users signing in through it for the first time are provisioned just in time as Members. An Organization Administrator can require SSO, blocking password sign-in for the Organization's users.

**Blocked by:** 02 (Members, roles and Teams)

**Status:** ready-for-agent

- [ ] An Organization Administrator can create, edit and test a SAML or OIDC connection; each connection belongs to exactly one Organization.
- [ ] First sign-in through SSO creates the user as a Member of that Organization.
- [ ] Requiring SSO blocks password sign-in for that Organization's users.
- [ ] SSO configuration and policy changes are audited.
