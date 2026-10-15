# 04: Permitted name rules

**What to build:** Each Private CA has permitted name rules (exact names and zones), so it can only issue for the namespaces it is meant for. Names outside them are refused as soon as someone asks for them, and a platform-made Issuing CA carries them as X.509 name constraints that relying parties enforce. See `spec.md`, "Permitted name rules".

**Blocked by:** 03

**Status:** ready-for-agent

- [ ] Organization Administrators set a Private CA's rules when creating it and change them later (`privateCa.update`), using the platform's existing name normalization; `private_ca.updated` is an Audit Event.
- [ ] Creating, proposing or proposing a Name Change for a Managed Certificate on a Private CA with a name outside its rules is refused with 422, naming the names.
- [ ] Issuance refuses such names as a backstop, with a new Issuance failure code.
- [ ] A platform-made Issuing CA carries the rules as critical `permittedSubtrees` dNSName constraints; the UI says that changing rules later does not change constraints already in the Issuing CA.
- [ ] Web: the rules are editable on the Private CA page and shown beside the CA picker on the create/propose/Name Change forms.
