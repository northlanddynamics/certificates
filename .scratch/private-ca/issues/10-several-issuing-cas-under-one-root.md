# 10: Several Issuing CAs under one root

**What to build:** A Private CA becomes a root with any number of Issuing CAs under it. An Organization Administrator adds an Issuing CA to an existing platform-made root, each Issuing CA has its own key, Permitted Name Rules, Validity Limits and status, and a Managed Certificate is issued from one Issuing CA. Rolling over an Issuing CA then means adding a new one under the same root, not making a new root that every relying party must be given again.

This reverses `spec.md`'s Out of Scope entry "multiple Issuing CAs under one Private CA at once"; that line, and the spec's Schema, Rollover and Web sections, change with this ticket.

**Blocked by:** None (03, 04 and 05 are done)

**Status:** needs-triage

## Why now

Today a `private_ca` row holds the root and its one Issuing CA together, so:

- the only way to get another Issuing CA is another Private CA, with its own root that relying parties must trust separately;
- rollover as written in 09 (new Private CA, repoint, retire the old) changes the root every time, so every machine that trusts the old root has to be given the new one;
- an Organization cannot have, say, a TLS Issuing CA and a device Issuing CA under one root.

06 (CRL) and 09 (retire and repoint) both build on which object is retired, revoked and listed on which CRL, so this should land before them.

## Decisions

- **Private CA = root + its Issuing CAs.** The Private CA keeps its name, kind and the root (certificate and KMS key for the platform-root kind). Its Issuing CAs are a new table, each pointing at its Private CA.
- **Per Issuing CA:** subject, KMS key, certificate, status (`awaiting_signature`, `active`, `retired`, `revoked`), Permitted Name Rules (and so its name constraints), Validity Limits. These move off `private_ca`. Name constraints are baked into each Issuing CA's certificate, so the rules belong with it.
- **Per Private CA:** status of the root itself (`active`, `revoked`). A revoked root's Issuing CAs issue nothing.
- **A Managed Certificate is issued from an Issuing CA.** The issuer becomes `{ kind: "private_ca", issuingCaId }`. Existing Managed Certificates migrate to their Private CA's one Issuing CA. Certificate rows record the Issuing CA that signed them (06's CRL needs this).
- **Adding an Issuing CA** (`privateCa.update`, or a new `privateCa.addIssuingCa` if triage prefers) to a platform-root Private CA: the platform makes a new key in the KMS and has the root sign it (pathLen 0, the given name constraints), valid no longer than the root. The subject must differ from the Private CA's other Issuing CAs' subjects.
- **Creating a Private CA** still makes the root and its first Issuing CA in one step, as now.
- **Organization-root kind (07):** each Issuing CA under it gets its own CSR and upload step; the Private CA holds the uploaded root and chain once, shared by its Issuing CAs.
- **Glossary:** **Issuing CA** stays the term (`CONTEXT.md` says to avoid "intermediate"); the Private CA's definition gains "a root and one or more Issuing CAs under it".

## Acceptance

- [ ] `POST /api/organizations/{orgId}/private-cas/{id}/issuing-cas` adds an Issuing CA to a platform-root Private CA: separate key, signed by the root, pathLen 0, critical dNSName name constraints from its rules, validity clipped to the root's `notAfter`; a duplicate subject is refused with 422 (`private_ca.issuing_ca_added` Audit Event).
- [ ] The Private CA response lists its Issuing CAs (id, subject, status, `notAfter`, `permittedNames`, `validity`); `PATCH` of names and validity moves to the Issuing CA (`private_ca.updated` detail names the Issuing CA).
- [ ] Managed Certificate create, propose and Name Change take `issuer: { kind: "private_ca", issuingCaId }`; names and validity are checked against that Issuing CA; an Issuing CA of another Organization is refused with 422.
- [ ] Issuance signs with the Managed Certificate's Issuing CA and the chain is that Issuing CA then the root; the stored Certificate records the Issuing CA.
- [ ] The migration moves each existing Private CA's issuing certificate, key, rules and limits to one Issuing CA row, and repoints its Managed Certificates and Certificates; existing tests pass against the migrated shape.
- [ ] Chain download is per Issuing CA; the root alone can be downloaded from the Private CA.
- [ ] Web: the Private CAs table lists each root with its Issuing CAs as sub-rows (already laid out that way); "Add Issuing CA…" in the root's menu; Permitted names… and Validity… move to each Issuing CA row's menu; the sub-row column header reads "Issuing CA", not "Intermediate". The Managed Certificate forms pick an Issuing CA, grouped by Private CA.
- [ ] `spec.md` (Out of Scope, Schema, Rollover, Web) and `CONTEXT.md` (**Private CA**) updated; 06's CRL bullet reads "a platform-made root publishes its own CRL, covering its Issuing CAs"; 09's rollover becomes "add an Issuing CA under the same root, repoint, retire the old one", and 06 and 09 are blocked by this ticket.

## Open questions for triage

- Should a Managed Certificate point at the Private CA and always use its current active Issuing CA instead? That makes rollover automatic but rules out several active Issuing CAs with different names (TLS vs devices), which is the reason for this ticket, so the decision above points at the Issuing CA.
- Separate `privateCa.addIssuingCa` permission, or covered by `privateCa.update`? Both are held only by Organization Administrators today.

## Comments
