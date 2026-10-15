# 06: Revocation and the CRL

**What to build:** Revoking a Certificate issued from a Private CA takes effect at once, and relying parties learn it from a CRL served at a public, unauthenticated URL named in each certificate. See `spec.md`, "Revocation" and "CRL".

**Blocked by:** 03, 10

**Status:** ready-for-agent

- [ ] Revocation of a Private CA Certificate (by an Owner or anyone holding `managedCertificate.revoke`) offers `unspecified`, `keyCompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation` and `privilegeWithdrawn`, records the Revocation and regenerates the CRL of the Issuing CA that signed it in the same Unit of Work.
- [ ] Each Issuing CA has a full CRL, and a platform-made root publishes its own CRL, covering its Issuing CAs; each is a full CRL signed by its own key, with an increasing CRL number and `nextUpdate` 7 days after `thisUpdate`.
- [ ] The CRL (DER) and CA certificates are served at public routes under an opaque id, over plain HTTP without redirecting to HTTPS as well as over HTTPS, at the platform's configured public base URL.
- [ ] Certificates issued from a Private CA carry a CDP and AIA caIssuers pointing at those routes.
- [ ] A scheduled job reissues each CRL at least 3 days before `nextUpdate`, driven by the harness clock in tests; expired serials are dropped.
- [ ] Tests fetch the CRL from its route and check the signature, the revoked serial and reason, the CRL number and `nextUpdate`.
- [ ] The deployment notes say these routes must be public and reachable over plain HTTP.
