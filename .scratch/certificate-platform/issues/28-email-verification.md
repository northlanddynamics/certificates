# 28: Verify email before accepting an invitation

**What to build:** Sign-up verifies the user's email address, and an invitation can be accepted only by a user whose address is verified. Today `/api/invitations/{id}/accept` trusts that the signed-in user's email matches the invitation, and sign-up does not verify email, so anyone holding an invitation link can register the invited address and join the Organization. Better Auth documents this risk and has the option for it (`requireEmailVerificationOnInvitation`), which is left off in `server/src/auth.ts` until verification exists.

**Blocked by:** 01 (Walking skeleton)

**Status:** needs-triage

- [ ] Sign-up sends a verification email (Better Auth's email verification) and the user can verify from the link.
- [ ] `requireEmailVerificationOnInvitation` is turned on, and accepting an invitation with an unverified address is refused.
- [ ] The first Organization Administrator's flow (ticket 01) still works: accept, set a password, verify, sign in.
- [ ] Verification emails are captured, not sent, in tests, and the Seam A harness can complete verification.
- [ ] The mail transport is real outside tests (today `ConsoleMailer` only prints); decide here or in ticket 20 which delivers it first.

## Comments

Raised while reviewing Better Auth's documentation against ticket 02 (see the Comments in `02-members-roles-teams.md`). The docs flag `requireEmailVerificationOnInvitation` as the stricter posture.
