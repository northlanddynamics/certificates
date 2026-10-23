# 04: Disable and re-enable a Certificate Profile: Proposals and Name Changes

**What to build:** An Organization Administrator disables a Certificate Profile, and nothing more is proposed or approved under it until they enable it again. Pending Proposals and Name Changes stay pending: they can be rejected but not approved.

**Blocked by:** 02

**Status:** done

- [x] Disabling and enabling need `certificateProfile.disable`, and each writes an Audit Event.
- [x] While a profile is disabled, a request through it is refused with 422 for everyone, Organization Administrators included.
- [x] Approving a Proposal from a disabled profile is refused with 422, naming the profile; rejecting it is allowed.
- [x] Proposing a Name Change on a Managed Certificate linked to a disabled profile is refused for everyone, and approving a pending one is refused.
- [x] The check is made where an Issuance begins, so approval and Name Changes meet the same refusal (Renewal follows in 05).
- [x] Enabling the profile makes its pending Proposals and Name Changes approvable again.
- [x] Members and Approvers no longer see a disabled profile in the list or the profile step. Its name and disabled state still show in the Approval queue and on its Managed Certificates.
- [x] Reading a profile reports the number of pending Proposals and Name Changes. The disable confirmation in the web app shows it.
- [x] Server tests through the harness, and a web test for the confirmation.
