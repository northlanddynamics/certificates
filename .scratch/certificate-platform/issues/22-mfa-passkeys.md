# 22: MFA and passkeys

**What to build:** Users can enroll TOTP MFA and passkeys and sign in with them. An Organization Administrator can require MFA for password users in their Organization.

**Blocked by:** 02 (Members, roles and Teams)

**Status:** done

- [x] Users can enroll and use TOTP as a second factor.
- [x] Users can register and sign in with passkeys.
- [x] An Organization Administrator can require MFA; password users without MFA are made to enroll before continuing.
- [x] Enrollment and policy changes are audited.

## Comments

- Implemented with Better Auth's `twoFactor` (TOTP, with backup codes) and `passkey` (`@better-auth/passkey`) plugins. The email OTP method is not configured. Passkeys sign in on their own, without a password or a second factor. The relying party is the host of `BASE_URL`, and the expected origin is the request's, already checked against the trusted origins.
- Their endpoints are served as they are under `/api/auth/two-factor/*` and `/api/auth/passkey/*`, from the allowlist in `server/src/account-security.ts`. Each change to a signed-in user's sign-in methods runs on the unit of work and records its Audit Events in the same transaction: `two_factor.enabled` (on the first right code, not when the secret is handed out), `two_factor.disabled`, `two_factor.backup_codes_regenerated`, `passkey.registered`, `passkey.renamed` and `passkey.deleted`. Both plugins lack hooks, so the change is found by comparing the user's sign-in methods before and after. A sign-in method belongs to a user while an Audit Event belongs to an Organization, so it is recorded in every Organization the user belongs to at that moment. A user with no Organization leaves no event. The sign-in ceremonies (`verify-totp` and `verify-backup-code` without a session, passkey authentication) pass straight through, so Better Auth's failed-attempt lockout is never rolled back.
- `GET`/`PUT /api/organizations/{orgId}/login-policy` (`{ requireMfa }`, the `loginPolicy` permission, which only Organization Administrators hold) sets the policy, and a change is audited as `login_policy.changed`. While it is on, a member who has a password and no TOTP gets 403 from every platform route and every Better Auth organization endpoint until they set one up, and so do their own API keys (an Organization's keys are not affected). `/api/me` stays open and reports `user.mfa: { enabled, setupRequired }`, as do Better Auth's own endpoints and the login policy, so the Organization Administrator who turned it on can still undo it. The hold applies to the user as a whole, not per Organization: a member of any Organization that requires MFA is held up everywhere. A passkey does not count as MFA, because the password still signs in alone. A user without a password is not held up. This is recorded as **Login Policy** in `CONTEXT.md`.
- Web: sign-in asks for the TOTP code or a backup code when needed, and offers "Sign in with a passkey". "Account security" (user menu) sets up the authenticator app with a QR code, makes new backup codes, turns it off, and adds, renames and removes passkeys. "Login policy" is under Administration. A user held up by the policy is sent to Account security. The web uses Better Auth's client for these.
- Not done here: changes made through Better Auth's admin plugin are not audited here. A Platform Operator's `admin/update-user` can set `twoFactorEnabled`, and `admin/remove-user` deletes a user's TOTP and passkeys. Using a backup code to answer the second factor while already signed in is not audited, because it changes no sign-in method. A user with a leaked password who has not set up TOTP can still set it up and be let in; requiring MFA protects accounts once they have it. The Login policy page uses a checkbox, because the shadcn registry could not be reached to add a Switch.
- Rate limits: the endpoints that change sign-in methods run on a per-transaction Better Auth instance. They still share Better Auth's rate limits (the two-factor plugin's 3 requests per 10 seconds), because its in-memory store is module-level, shared by every instance. The limit is on wherever Better Auth enables it, which is production by default.
