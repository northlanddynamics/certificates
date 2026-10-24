# 21: Accept invitation page doesn't say what you're joining

**What to build:** `pages/accept-invitation.tsx` asks for name, the email the invitation went to, and a new password. It never names the Organization, makes you retype the email, and always signs up, so someone with an account cannot accept.

**Blocked by:** none

**Status:** needs-triage

- [ ] Check what Better Auth exposes about an invitation to someone not signed in (`getInvitation` needs a session); decide whether a public lookup is acceptable.
- [ ] If so: the title names the Organization and role, and the email is pre-filled and read-only.
- [ ] "Already have an account? Sign in" goes to `/sign-in?redirect=/accept-invitation/<id>` (ticket 04), and a signed-in visitor sees a one-click Accept.
- [ ] Password field shows the 12-character rule as a hint, not in the label.
