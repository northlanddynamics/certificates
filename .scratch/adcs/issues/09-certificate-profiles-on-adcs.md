# 09: Certificate Profiles on an ADCS CA

**What to build:** An Organization Administrator creates or edits a Certificate Profile whose issuer is an ADCS CA and one of its TLS templates. It has no validity setting, because the template decides validity. Members propose through it under its name rules and the ADCS CA's Permitted Name Rules. A profile whose template is unavailable shows a warning but stays enabled, and its Issuances fail with that cause until the template comes back. Detaching, disabling and requiring proposals through a profile behave as today. See `.scratch/adcs/spec.md`.

**Blocked by:** 06 (TLS Managed Certificates from an ADCS CA).

**Status:** ready-for-agent

- [ ] The Certificate Profile dialog offers ADCS CAs with their available, unhidden TLS templates, and no validity step for them.
- [ ] Proposals through it copy the ADCS CA and template onto the Managed Certificate and keep to both sets of name rules.
- [ ] A warning shows on the profile, and in its list, while its template is unavailable.
- [ ] Removing an ADCS CA is refused while a Certificate Profile names it.
- [ ] Seam A tests, in the style of the existing Certificate Profile tests.
