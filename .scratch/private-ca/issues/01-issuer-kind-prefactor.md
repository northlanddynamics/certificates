# 01: Make the issuer a kind on a Managed Certificate (prefactor)

**What to build:** No behaviour change. A Managed Certificate's issuer becomes a kind (only ACME, carrying today's environment and ACME Account), so that ticket 03 can add a Private CA kind beside it. The `CertificateAuthority` interface is split so that accounts, DCV and ARI are the ACME kind's concern, and Issuance hands a DCV responder only to an issuer that needs one. See `spec.md`, "`CertificateAuthority` interface" and "Schema".

**Blocked by:** None (can start immediately)

**Status:** done

- [x] A Managed Certificate's issuer is stored as a kind plus that kind's reference; existing rows migrate to the ACME kind with their environment and ACME Account unchanged.
- [x] Issuance, Renewal, the Renewal scheduler (ARI) and Revocation reach the CA through the issuer, not by assuming ACME; their callers and API contracts do not change.
- [x] The API's Managed Certificate shape is unchanged (or only gains an issuer field defaulting to ACME); the web app needs no change.
- [x] Every existing test passes unchanged.
