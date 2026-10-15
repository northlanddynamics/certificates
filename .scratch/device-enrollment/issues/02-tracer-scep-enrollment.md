# 02: Tracer: a device enrolls over SCEP

**What to build:** An Organization Administrator creates an Enrollment Profile on a Private CA's Issuing CA, and a device enrolls at its SCEP URL and gets a Device Certificate that follows the profile. Validation is a test-only validator that always allows, so this ticket is the SCEP and issuance path alone. See `spec.md`.

**Blocked by:** private-ca 03

**Status:** ready-for-agent

- [ ] An Organization Administrator creates an Enrollment Profile (Issuing CA, validity, key usage, EKU defaulting to client authentication, allowed key types) with an opaque public id; the platform generates its RA key (software RSA, wrapped by the Organization's data key) and an RA certificate from the Issuing CA. `enrollmentProfile` permissions are Organization Administrators only and reported by `/api/me`.
- [ ] Public SCEP routes per profile answer `GetCACaps`, `GetCACert` (RA certificate and CA chain) and `PKIOperation` `PKCSReq` (GET and POST) with PKCS#1 v1.5 key transport and AES content encryption, served by `ts-scep`'s `ScepServer` (RA identity only, no CA key) with the issuance flow in its `ScepHandler`. `ts-scep` is added as a dependency pinned to a commit or release, and runs under Bun (fixed upstream if it does not).
- [ ] A request is issued with the profile's validity (clipped to the Issuing CA), key usage and EKU, subject and SANs from the CSR; CSR-requested extras are ignored; a disallowed key type is answered FAILURE.
- [ ] The Device Certificate is stored with its profile, serial, subject, SANs and transaction ID, with a `device_certificate.issued` Audit Event in the same Unit of Work; it does not appear among Managed Certificates.
- [ ] A SCEP device test helper, built on `ts-scep`'s `ScepClient` and builders, sends the messages and parses CertRep; tests run through the Seam A harness.
- [ ] Web: a minimal Enrollment Profiles page (create, SCEP URL, CA certificate download), hidden in production while no Enrollment Validator kind is registered.
- [ ] `CONTEXT.md`: Enrollment Profile redefined, Device Certificate added; `docs/audit-events.md` documents the new actions.
