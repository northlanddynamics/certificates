# 03: Prefactor: an Enrollment Profile's issuer is a union

**What to build:** Enrollment Profiles, their RA certificates and Device Certificates are tied to an Issuing CA. Make them name their issuer through one type that, for now, has a single case (an Issuing CA), so that a later ticket can add an ADCS CA and a Certificate Template without touching every caller. Behaviour, the API's shape for existing profiles, and the SCEP responses are unchanged. See `.scratch/adcs/spec.md` (Implementation Decisions: SCEP, RA certificate).

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] An Enrollment Profile, its RA certificate and its Device Certificates refer to their issuer through one issuer type.
- [ ] Issuing a Device Certificate and an RA certificate, revoking a Device Certificate and serving GetCACert all go through that type.
- [ ] Existing profiles keep working after the migration, with no change to their API responses.
- [ ] All existing device enrollment, Intune, Shared Challenge and SCEP interop tests pass unchanged.
