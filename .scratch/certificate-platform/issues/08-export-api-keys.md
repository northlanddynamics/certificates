# 08: Export formats and API keys

**What to build:** Owners can download the current or any earlier Certificate as PEM, DER or PKCS#7 (P7B), choosing leaf only, leaf plus intermediates, or leaf plus intermediates plus root. Users can create API keys that carry their own permissions, so a CI pipeline can fetch a Certificate in any of these forms.

**Blocked by:** 02 (Members, roles and Teams), 05 (First Certificate (tracer))

**Status:** ready-for-agent

- [ ] Downloads are available as PEM, DER and P7B, each with the three chain options.
- [ ] Any earlier Certificate of a Managed Certificate can be downloaded.
- [ ] No PFX or JKS export exists.
- [ ] Users can create and revoke API keys (Better Auth API-key plugin) scoped to their Organization and carrying their permissions.
- [ ] An API key can fetch the current Certificate in a chosen format and chain option.
- [ ] API key creation, revocation and each use are audited.
