# 07: Enrollment Profiles refused on ML-DSA Issuing CAs

**What to build:** An Enrollment Profile cannot be created on, or repointed to, an ML-DSA Issuing CA. Device keys stay RSA, and the profile's SCEP RA certificate would carry an ML-DSA signature that SCEP clients (Intune, Iru, network gear) cannot verify.

**Blocked by:** 03

**Status:** ready-for-agent

- [ ] Creating an Enrollment Profile on an ML-DSA Issuing CA is refused with a 422 that says why.
- [ ] Repointing an Enrollment Profile to an ML-DSA Issuing CA is refused the same way, and the profile is left as it was.
- [ ] The web app does not offer ML-DSA Issuing CAs when creating or repointing a profile.
- [ ] Seam A tests cover both, following the existing Enrollment Profile lifecycle tests.
