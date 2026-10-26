# 03: Sessions land in their front end

**What to build:** Someone who signs in through a Self-Service connection lands in the Self-Service Portal; someone who signs in through a Console connection, or with a password or passkey, lands in the Console. The portal exists as its own part of the web app, with its own layout and sign-in page, and a placeholder home for later tickets to fill.

**Blocked by:** 01 (Connections say which front end they sign in to)

**Status:** ready-for-agent

- [ ] Better Auth sessions gain `signedInTo` (`console` | `portal`), set when the session is created and never from client input. It is the connection's `signsInTo` for an SSO sign-in, and `console` for password, passkey and impersonation sessions.
- [ ] `/api/me` reports it as `session: { signedInTo }`.
- [ ] The portal is served from the same origin under its own path prefix, with its own layout (no Organization sidebar, a header with help and the account menu), and works at phone width.
- [ ] The portal has its own sign-in page: work email, then SSO through the portal connection resolved by 01's route. It links to the Console.
- [ ] One pure web function decides where to land, from `signedInTo` and the path asked for: a safe asked-for path (by the existing sign-in redirect rules) in either front end, otherwise the root of the session's front end.
- [ ] The Console's root page sends a `portal` session to the portal root. Nothing else redirects between the front ends.
- [ ] Harness tests check `signedInTo` in `/api/me` for SSO through each kind of connection, and for password, passkey and impersonation sessions.
- [ ] A web test of the landing function, in the style of the existing sign-in redirect test.
