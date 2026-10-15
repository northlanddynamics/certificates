# 04: Permitted name rules

**What to build:** Each Private CA has permitted name rules (exact names and zones), so it can only issue for the namespaces it is meant for. Names outside them are refused as soon as someone asks for them, and a platform-made Issuing CA carries them as X.509 name constraints that relying parties enforce. See `spec.md`, "Permitted name rules".

**Blocked by:** 03

**Status:** done

- [x] Organization Administrators set a Private CA's rules when creating it and change them later (`privateCa.update`), using the platform's existing name normalization; `private_ca.updated` is an Audit Event.
- [x] Creating, proposing or proposing a Name Change for a Managed Certificate on a Private CA with a name outside its rules is refused with 422, naming the names.
- [x] Issuance refuses such names as a backstop, with a new Issuance failure code.
- [x] A platform-made Issuing CA carries the rules as critical `permittedSubtrees` dNSName constraints; the UI says that changing rules later does not change constraints already in the Issuing CA.
- [x] Web: the rules are editable on the Private CA page and shown beside the CA picker on the create/propose/Name Change forms.

## Comments

Implemented. Notes for the tickets that follow:

- The rules are `permittedNames: { exact, zones }` on a Private CA (columns `permitted_exact_names`, `permitted_zones`); the matching and normalisation are in `server/src/permitted-names.ts`. An exact wildcard permits that wildcard alone; a zone permits its name and everything beneath it, wildcards included. At least one rule is required on create and update.
- A Private CA made before this ticket has no rules and issues for nothing until an Organization Administrator sets them.
- `PATCH /api/organizations/{orgId}/private-cas/{id}` takes `permittedNames`; ticket 05 adds the validity fields to the same body and to `private_ca.updated`'s `detail` (`{ from, to }` per field changed). A change to identical rules is no event.
- The Issuance backstop is `name_not_permitted`. Approving a proposal or a name change does not re-check the rules; the backstop catches rules narrowed in between.
- The Issuing CA's name constraints are critical `permittedSubtrees` dNSNames (a wildcard exact name contributes its base; an exact name as a dNSName also covers names beneath it, which the platform still refuses), and `excludedSubtrees` for every IPv4 and IPv6 address. The DER is encoded by hand in `ca-certificates.ts`, since `@peculiar/x509` has no class for it; OpenSSL reads it and rejects a leaf outside it.
