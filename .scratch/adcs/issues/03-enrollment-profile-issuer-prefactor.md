# 03: Prefactor: an Enrollment Profile's issuer is a union

**What to build:** Enrollment Profiles, their RA certificates and Device Certificates are tied to an Issuing CA. Make them name their issuer through one type that, for now, has a single case (an Issuing CA), so that a later ticket can add an ADCS CA and a Certificate Template without touching every caller. Behaviour, the API's shape for existing profiles, and the SCEP responses are unchanged. See `.scratch/adcs/spec.md` (Implementation Decisions: SCEP, RA certificate).

**Blocked by:** None (can start immediately).

**Status:** done

- [x] An Enrollment Profile, its RA certificate and its Device Certificates refer to their issuer through one issuer type.
- [x] Issuing a Device Certificate and an RA certificate, revoking a Device Certificate and serving GetCACert all go through that type.
- [x] Existing profiles keep working after the migration, with no change to their API responses.
- [x] All existing device enrollment, Intune, Shared Challenge and SCEP interop tests pass unchanged.

## Comments

- Implemented as `EnrollmentIssuer` (`server/src/enrollment/enrollment-issuer.ts`), stored as `issuer_kind` (only `private_ca` for now) with `issuing_ca_id` as its reference on `enrollment_profile` and `device_certificate` (migration 0059, nullable `issuing_ca_id` with a per-kind check). `EnrollmentIssuers` issues the RA certificate and Device Certificates, gives the device refusal and GetCACert's chain; Device Certificate revocation groups by issuer. What a profile shows of its issuer (`enrollmentIssuerFields`, `enrollmentIssuerCaCertificate`, audit detail) is in the same module, so a new kind changes it there and in the API schema. `server/test/enrollment-issuer-migration.test.ts` covers existing profiles.
- Ticket 10 must still touch two read paths that join the Issuing CA for the issuer's subject: the Device Certificate list/detail (`device-certificates.ts`, inner join) and the revocation feed's serial-and-issuer match (`enrollment-validators.ts`). An inner join would drop ADCS Device Certificates there.
