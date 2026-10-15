# 05: Validity limits

**What to build:** Each Private CA sets a maximum and a default TLS validity (default 397 days), a Managed Certificate on a Private CA may choose a validity at or below the maximum, and nothing is issued that outlives its Issuing CA. See `spec.md`, "Validity".

**Blocked by:** 03

**Status:** done

- [x] Organization Administrators set a Private CA's maximum and default validity in days; a default above the maximum is refused.
- [x] A Managed Certificate on a Private CA may set its own validity; above the CA's maximum is refused, and without one it gets the default.
- [x] Issued validity is the chosen validity, clipped to the Issuing CA's `notAfter`.
- [x] The Renewal Policy's rules apply unchanged to these lifetimes.
- [x] Web: the CA's limits on the Private CA page; a validity field on the Managed Certificate form when its issuer is a Private CA.

## Comments

Implemented. Notes for the tickets that follow:

- A Private CA's limits are `validity: { maximumDays, defaultDays }` (columns `max_validity_days`, `default_validity_days`, 397 for both unless given, a database check that 1 <= default <= maximum). The maximum allowed is 3650 days (`MAX_VALIDITY_DAYS` in `private-ca.ts`). A default above the maximum is refused with 422, on create and on `PATCH`.
- `PATCH /api/organizations/{orgId}/private-cas/{id}` takes `validity` beside `permittedNames`; both in one request are one `private_ca.updated`, whose `detail.validity` has `{ from, to }` for each of `maximumDays` and `defaultDays` that changed.
- A Managed Certificate chooses with `issuer: { kind: "private_ca", privateCaId, validityDays }` (column `managed_certificate.validity_days`, null for the default and always null for ACME). It is part of the `Issuer` type in `issuer.ts`, so Issuance, Renewal and Name Changes carry it with no change of their own. Above the maximum is refused with 422 at create and propose; `managed_certificate.created`/`proposed` have `validityDays` when one was chosen.
- At Issuance the days are the chosen validity (or the CA's default at that time), no more than the CA's maximum at that time (it may have been lowered since), and the Certificate never ends after its Issuing CA's `notAfter`.
- There is no way yet to change a Managed Certificate's validity after it is created; repointing (ticket 09) should decide what happens to a chosen validity above the new CA's maximum (today it would be clipped at Issuance).
