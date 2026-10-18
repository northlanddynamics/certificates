# 02: Tracer: a device enrolls over SCEP

**What to build:** An Organization Administrator creates an Enrollment Profile on a Private CA's Issuing CA, and a device enrolls at its SCEP URL and gets a Device Certificate that follows the profile. Validation is a test-only validator that always allows, so this ticket is the SCEP and issuance path alone. See `spec.md`.

**Blocked by:** private-ca 03

**Status:** done

- [x] An Organization Administrator creates an Enrollment Profile (Issuing CA, validity, key usage, EKU defaulting to client authentication, allowed key types) with an opaque public id; the platform generates its RA key (software RSA, wrapped by the Organization's data key) and an RA certificate from the Issuing CA. `enrollmentProfile` permissions are Organization Administrators only and reported by `/api/me`.
- [x] Public SCEP routes per profile answer `GetCACaps`, `GetCACert` (RA certificate and CA chain) and `PKIOperation` `PKCSReq` (GET and POST) with PKCS#1 v1.5 key transport and AES content encryption, using ts-scep (see the spec).
- [x] A request is issued with the profile's validity (clipped to the Issuing CA), key usage and EKU, subject and SANs from the CSR; CSR-requested extras are ignored; a disallowed key type is answered FAILURE.
- [x] The Device Certificate is stored with its profile, serial, subject, SANs and transaction ID, with a `device_certificate.issued` Audit Event in the same Unit of Work; it does not appear among Managed Certificates.
- [x] A SCEP device test helper builds the messages and parses CertRep; tests run through the Seam A harness.
- [x] Web: a minimal Enrollment Profiles page (create, SCEP URL, CA certificate download), hidden in production while no Enrollment Validator kind is registered.
- [x] `CONTEXT.md`: Enrollment Profile redefined, Device Certificate added; `docs/audit-events.md` documents the new actions.

## Comments

Done. ts-scep is not on npm and this session's proxy blocked GitHub tarballs, so it is vendored, built from `b56eb8a`, under `vendor/ts-scep` (`file:` dependency; see its `VENDORED.md`), and `@peculiar/asn1-schema` is overridden to one version, since two copies break its schema registry. The Enrollment Validator is a minimal `validate`-only interface (`server/src/enrollment/enrollment-validator.ts`), its kinds given to the app (`AppDeps.enrollmentValidators`); the harness registers `test_allow`, production none. A refused request is FAILURE `badRequest` with no Audit Event yet (ticket 03 adds `enrollment.refused`). Device DNS SANs must be inside the Issuing CA's permitted names, since a platform-made Issuing CA's name constraints would make relying parties reject them anyway. The device ID column exists but is not filled until ticket 04. The web page is shown in development builds only (a build-time flag in `web/src/lib/navigation.ts`), not by asking which kinds are registered; ticket 04 removes the flag.

