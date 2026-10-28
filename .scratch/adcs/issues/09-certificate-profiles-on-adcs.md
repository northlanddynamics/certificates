# 09: Certificate Profiles on an ADCS CA

**What to build:** An Organization Administrator creates or edits a Certificate Profile whose issuer is an ADCS CA and one of its TLS templates. It has no validity setting, because the template decides validity. Members propose through it under its name rules and the ADCS CA's Permitted Name Rules. A profile whose template is unavailable shows a warning but stays enabled, and its Issuances fail with that cause until the template comes back. Detaching, disabling and requiring proposals through a profile behave as today. See `.scratch/adcs/spec.md`.

**Blocked by:** 06 (TLS Managed Certificates from an ADCS CA).

**Status:** done

- [x] The Certificate Profile dialog offers ADCS CAs with their available, unhidden TLS templates, and no validity step for them.
- [x] Proposals through it copy the ADCS CA and template onto the Managed Certificate and keep to both sets of name rules.
- [x] A warning shows on the profile, and in its list, while its template is unavailable.
- [x] Removing an ADCS CA is refused while a Certificate Profile names it.
- [x] Seam A tests, in the style of the existing Certificate Profile tests.

## Comments

- Server: a Certificate Profile's issuer may be `{ kind: "adcs", adcsCaId, templateId }`, stored in new `adcs_ca_id` and `adcs_template_id` columns (migration 0064) with foreign keys to the ADCS CA and its template, so removing an ADCS CA a profile names is refused with 409 by the existing guard. Creating or editing one checks the template as a Managed Certificate's ADCS issuer is checked (`adcsIssuerRefusal`, once per allowed key algorithm), and a validity is refused with 400.
- Unavailable template: profiles report `templateUnavailable` (the reason from `unavailableReason`, or null), in the list and when read. The profile stays enabled. A request through it is refused with 422 ("cannot issue now: ... is unavailable: ..."), as a profile on an Issuing CA that does not issue is. Issuances of Managed Certificates made from it fail as `template_unavailable` (ticket 06's check). Nothing changes once discovery reports the template again. A hidden template shows no warning, since hiding is an administrator's choice, but requests through it are refused as not offered for TLS.
- Edits that do not touch the issuer, key algorithms or validity are not re-checked, so a profile with an unavailable template can still be renamed or described.
- Web: the profile dialog offers ADCS CAs with their TLS templates and no validity step for them. The list shows "The template's" for validity and a "Template unavailable" badge with the reason. The edit dialog warns about an unavailable template and keeps the profile's key algorithms while it stays on that template.

