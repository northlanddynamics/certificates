# 05: Shared Challenge rotation

**What to build:** An Organization Administrator rotates a profile's Shared Challenge, is shown the new one once, and the previous one keeps working until they retire it or its expiry passes, so Macs Iru has not yet reached keep enrolling. Each Device Certificate records the challenge it was issued under, so the administrator can tell when the previous one is no longer used. See `spec.md`, "Shared Challenge mechanism".

**Blocked by:** 04

**Status:** ready-for-agent

- [ ] Rotating takes the previous challenge's expiry (required), returns a new challenge once, and keeps the old one as previous; it is refused (409) while a previous challenge is still valid.
- [ ] Both the current and the still-valid previous challenge enroll; after retirement, or once the expiry passes on the harness clock, the previous one is refused.
- [ ] Retiring ends the previous challenge at once.
- [ ] Each Device Certificate records the Shared Challenge id it was issued under (none for a renewal), shown in its details and carried by `device_certificate.issued`.
- [ ] `enrollment_profile.shared_challenge_rotated` and `enrollment_profile.shared_challenge_retired` (the administrator as actor, or no actor on expiry) are written, never with a challenge in them, and documented in `docs/audit-events.md`.
- [ ] Rotating and retiring need `enrollmentProfile:update`; Members and Approvers are refused.
- [ ] The profile's actions offer Rotate Shared Challenge (asking for the expiry, then showing the new challenge once) and Retire previous challenge.
