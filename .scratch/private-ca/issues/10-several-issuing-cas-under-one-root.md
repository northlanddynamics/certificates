# 10: Several Issuing CAs under one root

**What to build:** A Private CA becomes a root with any number of Issuing CAs under it. An Organization Administrator adds an Issuing CA to an existing platform-made root, each Issuing CA has its own key, Permitted Name Rules, Validity Limits and status, and a Managed Certificate is issued from one Issuing CA. Rolling over an Issuing CA then means adding a new one under the same root, not making a new root that every relying party must be given again.

This reverses `spec.md`'s former Out of Scope entry "multiple Issuing CAs under one Private CA at once". `spec.md` and `CONTEXT.md` were updated to this design during triage.

**Blocked by:** None (03, 04 and 05 are done)

**Status:** done

## Why now

Today a `private_ca` row holds the root and its one Issuing CA together, so:

- the only way to get another Issuing CA is another Private CA, with its own root that relying parties must trust separately;
- rollover as written in 09 (new Private CA, repoint, retire the old) changes the root every time, so every machine that trusts the old root has to be given the new one;
- an Organization cannot have, say, a TLS Issuing CA and a device Issuing CA under one root.

06 (CRL) and 09 (retire and repoint) both build on which object is retired, revoked and listed on which CRL, and 07 (Organization root) on which object holds the CSR, so this lands before all three; they are blocked by it.

## Decisions

- **Private CA = root + its Issuing CAs.** The Private CA keeps its name, kind and the root (certificate and KMS key for the platform-root kind). Its Issuing CAs are a new table, each pointing at its Private CA.
- **Per Issuing CA:** subject, KMS key, certificate, status (`awaiting_signature`, `active`, `retired`, `revoked`), Permitted Name Rules (and so its name constraints), Validity Limits. These move off `private_ca`. Name constraints are baked into each Issuing CA's certificate, so the rules belong with it.
- **Per Private CA:** status of the root itself (`active`, `revoked`). A revoked root's Issuing CAs issue nothing.
- **A Managed Certificate is issued from an Issuing CA.** The issuer becomes `{ kind: "private_ca", issuingCaId }`. Existing Managed Certificates migrate to their Private CA's one Issuing CA. Certificate rows record the Issuing CA that signed them (06's CRL needs this).
- **A Managed Certificate names its Issuing CA, not its Private CA.** Pointing at the Private CA and using its current active Issuing CA would make rollover automatic, but would rule out several active Issuing CAs with different names (TLS vs devices), which is the reason for this ticket. Rollover stays a manual repoint (09).
- **Adding an Issuing CA** (`privateCa.update`; no separate permission, since only Organization Administrators hold either) to a platform-root Private CA: the platform makes a new key in the KMS and has the root sign it (pathLen 0, the given name constraints), valid no longer than the root. The subject must differ from the Private CA's other Issuing CAs' subjects.
- **Creating a Private CA** still makes the root and its first Issuing CA in one step, as now.
- **Organization-root kind (07):** each Issuing CA under it gets its own CSR and upload step; the Private CA holds the uploaded root and chain once, shared by its Issuing CAs. 07 is not built yet and is blocked by this ticket, so this ticket only shapes the schema for it.
- **Glossary:** **Issuing CA** stays the term (`CONTEXT.md` says to avoid "intermediate"); the Private CA's definition gains "a root and one or more Issuing CAs under it".

## Acceptance

- [x] `POST /api/organizations/{orgId}/private-cas/{id}/issuing-cas` adds an Issuing CA to a platform-root Private CA: separate key, signed by the root, pathLen 0, critical dNSName name constraints from its rules, validity clipped to the root's `notAfter`; a duplicate subject is refused with 422 (`private_ca.issuing_ca_added` Audit Event).
- [x] The Private CA response lists its Issuing CAs (id, subject, status, `notAfter`, `permittedNames`, `validity`); `PATCH` of names and validity moves to the Issuing CA (`private_ca.updated` detail names the Issuing CA).
- [x] Managed Certificate create, propose and Name Change take `issuer: { kind: "private_ca", issuingCaId }`; names and validity are checked against that Issuing CA; an Issuing CA of another Organization is refused with 422.
- [x] Issuance signs with the Managed Certificate's Issuing CA and the chain is that Issuing CA then the root; the stored Certificate records the Issuing CA.
- [x] The migration moves each existing Private CA's issuing certificate, key, rules and limits to one Issuing CA row, and repoints its Managed Certificates and Certificates; existing tests pass against the migrated shape.
- [x] Chain download is per Issuing CA; the root alone can be downloaded from the Private CA.
- [x] Web: the Private CAs table lists each root with its Issuing CAs as sub-rows (already laid out that way); "Add Issuing CA…" in the root's menu; Permitted names… and Validity… move to each Issuing CA row's menu; the sub-row column header reads "Issuing CA", not "Intermediate". The Managed Certificate forms pick an Issuing CA, grouped by Private CA.
- [x] `spec.md` and `CONTEXT.md` updated; 06, 07 and 09 reworded and blocked by this ticket (done in triage).

## Comments

> *This was generated by AI during triage.*

## Agent Brief

**Category:** enhancement
**Summary:** Split the Private CA into a root and its Issuing CAs, so an Organization Administrator can add Issuing CAs under an existing platform-made root and each Managed Certificate is issued from one named Issuing CA.

**Current behavior:**
A Private CA is a single record holding both its root and its one Issuing CA: the Issuing CA's subject, certificate, KMS key reference, status, Permitted Name Rules and Validity Limits all sit on the Private CA. A Managed Certificate's issuer is `{ kind: "private_ca", privateCaId }`, and the issuer-refusal checks (status, names, validity) read that record. Certificates record the Private CA. The API has list, create, read, `PATCH` (names and validity) and a chain download per Private CA. The web Private CAs table already renders each root with sub-rows, but always exactly one, under a column header labelled "Intermediates" for screen readers.

**Desired behavior:**
See `.scratch/private-ca/spec.md` (Solution; Schema; Adding an Issuing CA; Rollover and retirement; Permissions; Audit Events; API; Web), which describes the target.
- A Private CA holds its name, kind, root (certificate, and KMS key for the platform-root kind), the root's status (`active`, `revoked`) and its CRL bookkeeping. Each Issuing CA is its own record under it: subject (unique within the Private CA), KMS key, certificate, status (`awaiting_signature`, `active`, `retired`, `revoked`), Permitted Name Rules, Validity Limits and CRL bookkeeping.
- Creating a Private CA still makes the root and its first Issuing CA in one step, with the same request body.
- An Organization Administrator (`privateCa.update`) adds an Issuing CA to a platform-root Private CA: a new KMS key in the Organization's context, signed by the root with pathLen 0 and critical dNSName permitted subtrees from its rules, `notAfter` no later than the root's. A repeated subject is refused with 422. Adding one to an Organization-root Private CA is refused until 07 builds that path.
- A Managed Certificate's issuer is `{ kind: "private_ca", issuingCaId }`. Create, propose and Name Change check names, validity and status against that Issuing CA, and also refuse it when its root is `revoked`; an Issuing CA of another Organization is refused with 422.
- Issuance signs with the Managed Certificate's Issuing CA. The chain is that Issuing CA, then the root, and the stored Certificate records the Issuing CA.
- The migration turns each existing Private CA's issuing certificate, key, subject, status, rules and limits into one Issuing CA record, and repoints its Managed Certificates and Certificates. No data is lost, and existing Private CA tests pass once adjusted to the new shape.

**Key interfaces:**
- The `Issuer` type's Private CA variant: `privateCaId` becomes `issuingCaId`, in the API schema and in the web client.
- The Private CA response gains `issuingCas: { id, subject, status, notAfter, permittedNames, validity }[]`. The per-Issuing-CA fields leave the top level, and the root's fields (subject, `notAfter`, status) stay.
- `POST /api/organizations/{orgId}/private-cas/{id}/issuing-cas` takes subject, permitted names and validity, and writes the `private_ca.issuing_ca_added` Audit Event.
- Names and validity changes move to the Issuing CA (`PATCH …/private-cas/{id}/issuing-cas/{issuingCaId}`). `private_ca.updated` keeps its action name, and its `detail` names the Issuing CA.
- Chain download is per Issuing CA (`…/issuing-cas/{issuingCaId}/chain`), and the root alone downloads from the Private CA.
- The issuer-refusal helpers (status, names, validity) take an Issuing CA together with its Private CA's root status.
- `docs/audit-events.md` documents `private_ca.issuing_ca_added`.

**Acceptance criteria:**
- [x] Adding an Issuing CA via the API returns it in the Private CA response. Its certificate, parsed with `@peculiar/x509`, verifies against the root, has a key distinct from the root's and from the other Issuing CAs', has pathLen 0 and critical dNSName name constraints matching its rules, and has `notAfter` no later than the root's.
- [x] A second Issuing CA with the same subject under the same Private CA is refused with 422, and adding one to another Organization's Private CA is refused.
- [x] Only holders of `privateCa.update` can add an Issuing CA or change one's names or validity; Approvers and Members are refused.
- [x] Each change writes its Audit Event (`private_ca.issuing_ca_added`; `private_ca.updated` naming the Issuing CA).
- [x] With two Issuing CAs under one root that have different rules, a Managed Certificate created on each is checked against its own Issuing CA's names and validity at create, propose and Name Change. Issuance from each signs with that Issuing CA's key, and the chain is that Issuing CA, then the root.
- [x] A Managed Certificate naming an Issuing CA of another Organization is refused with 422.
- [x] The migration, run on a database holding a Private CA, a Managed Certificate and an issued Certificate in the old shape, leaves one Issuing CA with that data. The Managed Certificate still issues and renews from it.
- [x] The Private CA chain route downloads the root, and the Issuing CA chain route downloads that Issuing CA then the root.
- [x] Web: each root's Issuing CAs are sub-rows under a column headed "Issuing CA". A root's menu has "Add Issuing CA…". Permitted names… and Validity… are on each Issuing CA row. The Managed Certificate create, propose and Name Change forms pick an Issuing CA grouped by Private CA, and the forms' permitted-names hint and validity ceiling follow the chosen Issuing CA.
- [x] Tests drive the HTTP API on the existing in-process harness (real Postgres, Better Auth, local KMS), in the style of the existing Private CA tests.

**Out of scope:**
- The Organization-root kind (CSR, upload, shared chain): that is 07.
- CRLs, CDP and AIA: 06.
- Retiring and revoking an Issuing CA, repointing a Managed Certificate, and Issuing CA expiry in the UI: 09.
- Any route that sets a root to `revoked`, and root rollover.
- A separate permission for adding an Issuing CA.

> *Implemented by AI (`claude/private-ca-10`).*

Notes from the implementation:
- Migration 0035 gives each existing Private CA's Issuing CA the Private CA's own id, so Managed Certificates' and Certificates' `private_ca_id` is only renamed to `issuing_ca_id`, and no immutable Certificate row is updated. Every root is migrated as `active`: the old status was the Issuing CA's, which keeps it.
- Adding an Issuing CA also takes an optional `lifetimeYears` (it runs until the root ends when none is given, and is clipped to the root either way). It is refused with 422 under a revoked or ended root.
- The Private CA's `/chain` route now serves only the root (`*.root.pem`), as the ticket asks; the Issuing CA's `/issuing-cas/{id}/chain` serves the Issuing CA, then the root.
- The Managed Certificate's `issuer` in responses now carries `issuingCa { id, subject }` beside `privateCa { id, name }`; a Certificate's `privateCaId` became `issuingCaId`.
- The CRL bookkeeping columns (CRL number, `nextUpdate`) on `private_ca` and `issuing_ca` are left for 06, which uses them.
- The stored Certificate chain is still the leaf and its Issuing CA; the root is added by the downloads (`roots`), as before.
