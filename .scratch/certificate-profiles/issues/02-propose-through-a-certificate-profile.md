# 02: Propose through a Certificate Profile

**What to build:** A member chooses a Certificate Profile in the New Managed Certificate dialog, enters names and a CSR, and the request becomes a Proposal with the profile's settings and the member as an Owner. An Organization Administrator's request through a profile is created outright. Approvers see which profile a Proposal came from.

**Blocked by:** 01

**Status:** done

- [x] The create-Managed-Certificate route takes an optional profile id. With one, the issuer, validity and Renewal Policy are copied from the profile. A request that also gives `issuer`, `acmeCaId`, `validityDays` or a Renewal Policy is refused with 400.
- [x] A key algorithm the profile does not allow is refused with 422. The existing names-and-CSR check and the issuer's own checks then run as today.
- [x] A profile whose issuer is no longer usable (Issuing CA not active, or ACME CA with no ACME Account) refuses the request with 422.
- [x] A non-administrator's request is a Proposal; an Organization Administrator's is created and its Issuance begins.
- [x] The Managed Certificate records which profile it came from. Editing the profile afterwards does not change it.
- [x] The requester and the profile's default Team become Owners, as well as any Owners named, each audited as added.
- [x] The Audit Event for the Proposal or creation records the profile.
- [x] The Managed Certificate's API representation names its profile. The Approval queue and the details page show it.
- [x] The dialog starts with "Choose a profile": the enabled profiles with their descriptions, and "Custom". On a profile, the Authority step is skipped and the Key step is pre-filled with the profile's key algorithm, or limited to its list.
- [x] Server tests through the harness, and web tests for the profile step and the pre-filled Key step.

## Comments

- The profile step is shown only when the caller has an enabled profile to choose; otherwise the dialog starts on the Authority step as before. "Custom" is always offered until ticket 07 adds the Organization setting.
- A request through a disabled profile is already refused with 422 for everyone, and the API's `profile` carries `enabled`, which the Approval queue and details page show as "(disabled)"; ticket 04 builds on both.
- The create route takes an optional `renewalPolicy`, so that giving one with `profileId` can be refused (400); a request without a profile may give one too.
- The API names the profile as it is now (its current name); the Audit Event keeps the name at the time of the request.
