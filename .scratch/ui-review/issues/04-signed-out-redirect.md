# 04: Signed-out visitors get a dead-end page

**What to build:** A signed-out visitor to any app route sees only "Sign in to continue." (`components/app-shell.tsx:18`). Send them to `/sign-in` and bring them back to the page they asked for.

**Blocked by:** none

**Status:** ready-for-agent

- [ ] A 401 from `me` redirects to `/sign-in?redirect=<path>` (replace, so Back does not loop).
- [ ] After password, second factor or passkey sign-in, the user lands on `redirect` when it is a same-origin path, else `/`.
- [ ] The SSO `callbackURL` carries the same path.
- [ ] An external or malformed `redirect` is ignored (no open redirect).
