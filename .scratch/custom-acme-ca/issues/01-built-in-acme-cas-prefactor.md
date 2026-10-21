# 01: Let's Encrypt becomes two built-in ACME CAs (prefactor)

**What to build:** No behaviour change for users. A Managed Certificate's issuer, and an ACME Account, refer to an ACME CA by id instead of an environment. Let's Encrypt Staging and Let's Encrypt Production are the two built-in ACME CAs, shown read-only with their tag on the ACME accounts page and in the registration dialog. See `spec.md`, "Implementation Decisions".

**Blocked by:** None (can start immediately)

**Status:** resolved

- [x] An ACME Account belongs to an ACME CA (at most one per Organization and CA); existing accounts, Managed Certificates and Certificates migrate to the built-in CAs with nothing lost.
- [x] The issuer reference is `acmeCaId` through Issuance, Renewal, ARI, Revocation, the API and the agent contract; there is no `environment` alias, and the `environment` columns on Managed Certificate and Certificate are gone.
- [x] The ACME accounts page and the registration dialog show the two built-in CAs read-only, with a tag badge; registering needs only a contact email and agreeing to the terms.
- [x] The issuer picker for a Managed Certificate lists the built-in CAs, Let's Encrypt Staging first and the default.
- [x] `CONTEXT.md` defines **ACME CA**, rewords **ACME Account**, and defines the environment tag; one short ADR records replacing `environment` with `acmeCaId`.
- [x] Existing tests pass, changed only where the issuer shape they assert has changed; a migration test covers existing rows.
