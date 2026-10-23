# 01: Create, edit and list Certificate Profiles

**What to build:** An Organization Administrator creates and edits Certificate Profiles on a page beside Enrollment Profiles. A profile has a name, a description, one issuer, the key algorithms it allows, a validity for a Private CA, a starting Renewal Policy and an optional default Team. Members and Approvers can list the enabled ones.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] A new `certificateProfile` permission resource with `read`, `create`, `update` (and `disable`, used in 04). Organization Administrators hold all of it; Approvers and Members hold `read`. `/api/me` reports it.
- [ ] A profile's name is unique within the Organization.
- [ ] The issuer is an ACME CA the Organization has an ACME Account with, or an active Issuing CA of one of its Private CAs; anything else is refused with 422 and the reason.
- [ ] The allowed key algorithms are a non-empty subset of what the issuer takes (an ML-DSA Private CA takes only ML-DSA ones, and other issuers take none).
- [ ] Validity is given only for a Private CA issuer and is at most its Issuing CA's maximum; it is refused (400) for an ACME CA.
- [ ] The starting Renewal Policy follows the existing Renewal Policy rules. The default Team is a Team of the Organization.
- [ ] Editing changes any of these, including pointing the profile at another issuer, re-validated the same way.
- [ ] Listing returns enabled profiles to everyone with `read`, and all profiles to Organization Administrators.
- [ ] Creating and editing a profile each write an Audit Event through the `UnitOfWork`.
- [ ] The admin page lists, creates and edits profiles (components added through the shadcn CLI).
- [ ] Server tests through the harness cover validation, permissions and Audit Events.
