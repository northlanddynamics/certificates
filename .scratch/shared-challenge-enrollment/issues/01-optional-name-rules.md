# 01: Optional Name Rules

**What to build:** An Organization Administrator creates an Enrollment Profile whose Enrollment Validator does not vouch for names without any Name Rules, and devices enrolling under it get the subject and SANs they asked for, within the Issuing CA's Permitted Name Rules. Name Rules can still be given, and added, changed or removed later. See `spec.md`, "Optional Name Rules".

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] A profile whose validator does not vouch for names can be created with or without Name Rules; one whose validator vouches still refuses them (422).
- [ ] Without Name Rules, enrollment issues the CSR's subject and SANs, and names outside the Issuing CA's Permitted Name Rules are still refused.
- [ ] With Name Rules, they are enforced as before.
- [ ] Updating a profile adds, changes or removes its Name Rules, effective for the next request and shown in `enrollment_profile.updated`'s `changes`.
- [ ] The profile form has a Name Rules editor, empty by default, for validator kinds that do not vouch for names only.
- [ ] The validator kinds listing, the create endpoint's description and `docs/audit-events.md` say "may carry", not "must carry".
- [ ] Scenarios use the existing non-vouching test validator kind through the Seam A harness.
