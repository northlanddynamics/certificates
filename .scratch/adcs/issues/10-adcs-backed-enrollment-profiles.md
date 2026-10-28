# 10: ADCS-backed Enrollment Profiles over SCEP

**What to build:** An Organization Administrator creates an Enrollment Profile that names an ADCS CA, one of its device templates, and a template for its RA certificate.
- The platform generates the RA key. An Agent has ADCS issue the RA certificate, and the profile serves SCEP only once it has one. The RA certificate is renewed the same way when a third of its life is left.
- A device's PKCSReq or RenewalReq first passes the Enrollment Validator, the profile's Name Rules, the ADCS CA's Permitted Name Rules and the template's key checks. It is then submitted through an Agent and answered PENDING.
- GetCertInitial answers PENDING until ADCS issues, then SUCCESS with the certificate. It answers FAILURE if ADCS denies or 7 days pass.
- Device Certificates from ADCS are listed, searched and pruned like the others.

See `.scratch/adcs/spec.md` (SCEP, RA certificate).

**Blocked by:** 03 (an Enrollment Profile's issuer is a union), 07 (Requests pending at ADCS).

**Status:** done

- [x] Enrollment Profiles can name an ADCS CA, an available unhidden device template, and an RA template.
- [x] The RA certificate is issued through ADCS before the profile serves SCEP, renewed at a third of its life left, and GetCACert returns it with the ADCS chain.
- [x] SCEP answers PENDING for ADCS-backed profiles and records the transaction with its ADCS request ID. GetCertInitial gives PENDING, SUCCESS or FAILURE (`badRequest`).
- [x] Profiles on an Issuing CA still answer at once and never PENDING.
- [x] Every refusal happens before submission and is reported to the Enrollment Validator as today.
- [x] Device Certificates record the ADCS CA, template and request ID, and the Enrollment Validator is told about each issuance.
- [x] The SCEP device test support polls with GetCertInitial. Seam A tests cover Intune and Shared Challenge profiles on an ADCS CA, including pending, denial and timeout.
- [x] Removing an ADCS CA is refused while an Enrollment Profile names it.

## Comments

Implemented. A profile on an ADCS CA keeps its RA key as any profile does; its RA certificate is asked of ADCS on the change that creates it (`adcs-ra.ts`), renewed by an hourly pass at a third of its life left (the old one serving until then), and asked again a day after a failure or when an Organization Administrator rotates it. Requests for devices and RA certificates go through the same ADCS request engine as Issuances (`adcs_request.purpose`), whose outcome is handed to device enrollment or the RA module on the transaction that learned it. A SCEP transaction waiting for ADCS records its request (`scep_transaction.adcs_request_id`) and what it was decided with, and is answered PENDING until the request ends.

Left for 11: a RenewalReq's `superseded` revocation is asked of ADCS when the replacement is stored, but if no Agent is online to ask it is only logged, not retried.
