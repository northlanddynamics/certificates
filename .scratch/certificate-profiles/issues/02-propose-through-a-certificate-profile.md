# 02: Propose through a Certificate Profile

**What to build:** A member chooses a Certificate Profile in the New Managed Certificate dialog, enters names and a CSR, and the request becomes a Proposal with the profile's settings and the member as an Owner. An Organization Administrator's request through a profile is created outright. Approvers see which profile a Proposal came from.

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] The create-Managed-Certificate route takes an optional profile id. With one, the issuer, validity and Renewal Policy are copied from the profile. A request that also gives `issuer`, `acmeCaId`, `validityDays` or a Renewal Policy is refused with 400.
- [ ] A key algorithm the profile does not allow is refused with 422. The existing names-and-CSR check and the issuer's own checks then run as today.
- [ ] A profile whose issuer is no longer usable (Issuing CA not active, or ACME CA with no ACME Account) refuses the request with 422.
- [ ] A non-administrator's request is a Proposal; an Organization Administrator's is created and its Issuance begins.
- [ ] The Managed Certificate records which profile it came from. Editing the profile afterwards does not change it.
- [ ] The requester and the profile's default Team become Owners, as well as any Owners named, each audited as added.
- [ ] The Audit Event for the Proposal or creation records the profile.
- [ ] The Managed Certificate's API representation names its profile. The Approval queue and the details page show it.
- [ ] The dialog starts with "Choose a profile": the enabled profiles with their descriptions, and "Custom". On a profile, the Authority step is skipped and the Key step is pre-filled with the profile's key algorithm, or limited to its list.
- [ ] Server tests through the harness, and web tests for the profile step and the pre-filled Key step.
