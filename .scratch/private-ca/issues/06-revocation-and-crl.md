# 06: Revocation and the CRL

**What to build:** Revoking a Certificate issued from a Private CA takes effect at once, and relying parties learn it from a CRL served at a public, unauthenticated URL named in each certificate. See `spec.md`, "Revocation" and "CRL".

**Blocked by:** 03, 10

**Status:** done

- [x] Revocation of a Private CA Certificate (by an Owner or anyone holding `managedCertificate.revoke`) offers `unspecified`, `keyCompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation` and `privilegeWithdrawn`, records the Revocation and regenerates the CRL of the Issuing CA that signed it in the same Unit of Work.
- [x] Each Issuing CA has a full CRL, and a platform-made root publishes its own CRL, covering its Issuing CAs; each is a full CRL signed by its own key, with an increasing CRL number and `nextUpdate` 7 days after `thisUpdate`.
- [x] The CRL (DER) and CA certificates are served at public routes under an opaque id, over plain HTTP without redirecting to HTTPS as well as over HTTPS, at the platform's configured public base URL.
- [x] Certificates issued from a Private CA carry a CDP and AIA caIssuers pointing at those routes.
- [x] A scheduled job reissues each CRL at least 3 days before `nextUpdate`, driven by the harness clock in tests; expired serials are dropped.
- [x] Tests fetch the CRL from its route and check the signature, the revoked serial and reason, the CRL number and `nextUpdate`.
- [x] The deployment notes say these routes must be public and reachable over plain HTTP.

## Comments

Implemented. Notes for the tickets that follow:

- `server/src/crl.ts` holds the CRLs (`createCrls`: `publish` on a Unit of Work's transaction, `tick` for the scheduled pass) and the public routes: `/pki/issuing-cas/{issuingCaId}/ca.crl` and `ca.crt` for each Issuing CA, `/pki/roots/{privateCaId}/ca.crl` and `ca.crt` for a platform-made root (DER). The opaque ids are the Issuing CA's and the Private CA's own; a new Private CA's id is chosen before its certificates are made, so its first Issuing CA can name the root's URLs. `makeCrl` and the CDP/AIA extensions are in `ca-certificates.ts`. Tests: `server/test/private-ca-crl.test.ts`.
- Each CA keeps only its latest CRL, on its own row (`crl_number`, `crl_this_update`, `crl_next_update`, `crl_der`, `crl_failing_since` on `issuing_ca` and on `private_ca` for the root). Publishing locks that row, so CRL numbers are taken one at a time. Creating a Private CA publishes the root's and the first Issuing CA's CRLs; adding an Issuing CA publishes its own.
- `PKI_BASE_URL` (`AppDeps.pkiBaseURL`, default `BASE_URL`) is written into every certificate a Private CA signs. `PKI_HTTP_PORT` adds a plain-HTTP listener for `/pki/*` only when the platform serves TLS itself. The README's "Private CAs: CRLs and their public routes" has the deployment notes.
- The revocation route now records the revocation first and then asks the issuer (`Issuers.revoke` takes the transaction and the `Change`), so the Issuing CA's CRL, and only that one, is reissued in the same Unit of Work; a KMS that does not sign is a 502 and nothing is recorded.
- Reasons are in `server/src/revocation-reasons.ts` (`REVOCATION_REASONS_OF`), imported by the web too. An ACME Certificate revoked with `affiliationChanged` or `privilegeWithdrawn` is refused with 422 before the CA is told. `unspecified` is on a CRL with no reason code, as RFC 5280 asks.
- `certificate.revoked` has the issuer in `detail` for a Private CA. `private_ca.crl_published` is recorded only when a CRL is published after its scheduled reissue had failed.
- 09: the root's CRL lists nothing yet; a revoked Issuing CA goes in its `entries` in `crl.ts`. Every Issuing CA with a certificate keeps publishing whatever its status, and so does every root the platform holds; 09 decides when a retired one stops (after its last Certificate expires).
- Issuing CAs and Certificates made before this ticket have no CDP or AIA; their CRLs are published by the first scheduled pass. A failure to publish one of those first CRLs is not noted (there is no CRL yet to note it on), so its eventual success is no `private_ca.crl_published`. A failure in a revocation rolls the revocation back and is not noted either.
