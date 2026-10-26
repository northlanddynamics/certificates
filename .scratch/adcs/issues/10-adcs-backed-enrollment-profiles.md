# 10: ADCS-backed Enrollment Profiles over SCEP

**What to build:** An Organization Administrator creates an Enrollment Profile that names an ADCS CA, one of its device templates, and a template for its RA certificate.
- The platform generates the RA key. An Agent has ADCS issue the RA certificate, and the profile serves SCEP only once it has one. The RA certificate is renewed the same way when a third of its life is left.
- A device's PKCSReq or RenewalReq first passes the Enrollment Validator, the profile's Name Rules, the ADCS CA's Permitted Name Rules and the template's key checks. It is then submitted through an Agent and answered PENDING.
- GetCertInitial answers PENDING until ADCS issues, then SUCCESS with the certificate. It answers FAILURE if ADCS denies or 7 days pass.
- Device Certificates from ADCS are listed, searched and pruned like the others.

See `.scratch/adcs/spec.md` (SCEP, RA certificate).

**Blocked by:** 03 (an Enrollment Profile's issuer is a union), 07 (Requests pending at ADCS).

**Status:** ready-for-agent

- [ ] Enrollment Profiles can name an ADCS CA, an available unhidden device template, and an RA template.
- [ ] The RA certificate is issued through ADCS before the profile serves SCEP, renewed at a third of its life left, and GetCACert returns it with the ADCS chain.
- [ ] SCEP answers PENDING for ADCS-backed profiles and records the transaction with its ADCS request ID. GetCertInitial gives PENDING, SUCCESS or FAILURE (`badRequest`).
- [ ] Profiles on an Issuing CA still answer at once and never PENDING.
- [ ] Every refusal happens before submission and is reported to the Enrollment Validator as today.
- [ ] Device Certificates record the ADCS CA, template and request ID, and the Enrollment Validator is told about each issuance.
- [ ] The SCEP device test support polls with GetCertInitial. Seam A tests cover Intune and Shared Challenge profiles on an ADCS CA, including pending, denial and timeout.
- [ ] Removing an ADCS CA is refused while an Enrollment Profile names it.
