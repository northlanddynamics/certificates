# 07: Enrollment Profiles refused on ML-DSA Issuing CAs

**What to build:** An Enrollment Profile cannot be created on, or repointed to, an ML-DSA Issuing CA. Device keys stay RSA, and the profile's SCEP RA certificate would carry an ML-DSA signature that SCEP clients (Intune, Iru, network gear) cannot verify.

**Blocked by:** 03

**Status:** done

- [x] Creating an Enrollment Profile on an ML-DSA Issuing CA is refused with a 422 that says why.
- [x] Repointing an Enrollment Profile to an ML-DSA Issuing CA is refused the same way, and the profile is left as it was.
- [x] The web app does not offer ML-DSA Issuing CAs when creating or repointing a profile.
- [x] Seam A tests cover both, following the existing Enrollment Profile lifecycle tests.

## Comments

- The rule is `enrollmentProfileRefusal` in `server/src/private-ca/private-ca.ts`, applied beside `issuingRefusal` when a profile is created and when it is repointed (the repoint is refused before the new RA is signed, so the profile is untouched). It is also reported on each Private CA in the list as `enrollmentProfileRefusal` (the reason, or null), so the web holds no copy of the rule: both the create form and the Change Issuing CA dialog drop the Private CAs that carry one.
- Tests are in `server/test/enrollment-profile-lifecycle.test.ts`.
